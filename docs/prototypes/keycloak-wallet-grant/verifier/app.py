from __future__ import annotations

import hashlib
import os
import re
import base64
import logging
from functools import partial
from anyio import to_thread
import trio
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from decent_identity.identity_resolver import IdentityHistoryUnavailable, resolve_identity_record, _derive_owner_name_hex_from_identifier

app = FastAPI(title="Prototype Registry verifier", docs_url=None, redoc_url=None)

IDENTIFIER_RE = re.compile(r"(?:mailto:[^\s]+|tel:\\+?[0-9]+)\Z")
FINGERPRINT_RE = re.compile(r"ed25519:[0-9a-f]{64}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Grant(BaseModel):
  model_config = ConfigDict(extra="forbid")

  owner_identifier: str = Field(min_length=1, max_length=512)
  wallet_public_key_hex: str = Field(pattern=r"^[0-9a-f]{64}$")
  object_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
  storage_aud: str = Field(min_length=1, max_length=512)
  actions: list[str] = Field(min_length=1, max_length=8)
  purpose: str = Field(min_length=1, max_length=128)
  grant_jti: str = Field(min_length=1, max_length=256)
  consent_exp: int = Field(gt=0)
  assertion_signing_input_b64: str = Field(min_length=1, max_length=8192)
  assertion_signature_b64: str = Field(min_length=1, max_length=256)


@dataclass(frozen=True, slots=True)
class Settings:
  registry_host: str
  registry_port: int
  registry_bootstrap: list[str]
  quorum: int
  expected_storage_audiences: frozenset[str]


def settings() -> Settings:
  # This is the resolver's local listen IP, not the remote Registry host.
  host = os.environ.get("REGISTRY_HOST", "0.0.0.0")
  port = int(os.environ.get("REGISTRY_CLIENT_PORT", "9100"))
  seed_file=os.environ.get("REGISTRY_BOOTSTRAP_FILE")
  seed_text=open(seed_file,encoding="utf-8").read().strip() if seed_file else os.environ.get("REGISTRY_BOOTSTRAP", "")
  seeds = [x for x in seed_text.split(",") if x]
  if not seeds:
    raise RuntimeError("REGISTRY_BOOTSTRAP must contain the Registry node's identify multiaddr")
  audiences = frozenset(x for x in os.environ.get("STORAGE_AUDIENCES", "").split(",") if x)
  if not audiences:
    raise RuntimeError("STORAGE_AUDIENCES must be an operator-configured allowlist")
  return Settings(host, port, seeds, int(os.environ.get("REGISTRY_QUORUM", "1")), audiences)


def key_fingerprint(public_key_hex: str) -> str:
  return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


@app.get("/healthz")
def healthz() -> dict[str, str]:
  try:
    settings()
  except Exception as exc:
    raise HTTPException(status_code=503, detail="verifier configuration missing") from exc
  return {"status": "ok"}


@app.post("/v1/verify-grant")
async def verify_grant(grant: Grant) -> dict[str, Any]:
  try:
    cfg = settings()
  except Exception as exc:
    raise HTTPException(status_code=503, detail="verifier unavailable") from exc

  if not IDENTIFIER_RE.fullmatch(grant.owner_identifier):
    raise HTTPException(status_code=400, detail="owner identifier profile rejected")
  if len(set(grant.actions)) != len(grant.actions) or any(not a or len(a) > 32 for a in grant.actions):
    raise HTTPException(status_code=400, detail="actions rejected")
  if grant.storage_aud not in cfg.expected_storage_audiences:
    raise HTTPException(status_code=403, detail="Storage audience is not registered")

  owner_name_hex = _derive_owner_name_hex_from_identifier(grant.owner_identifier)
  try:
    # libp2p requires Trio; Uvicorn runs asyncio. A bounded worker runs its
    # own Trio loop, and cancellation does not abandon an active lookup.
    async def lookup():
      with trio.fail_after(8):
        return await resolve_identity_record(
          owner_name_hex=owner_name_hex,
          host=cfg.registry_host,
          port=cfg.registry_port,
          bootstrap=cfg.registry_bootstrap,
          quorum=cfg.quorum,
        )
    current = await to_thread.run_sync(partial(trio.run, lookup))
  except Exception as exc:
    if isinstance(exc, IdentityHistoryUnavailable):
      category = "history_unavailable"
    elif isinstance(exc, (TimeoutError, trio.TooSlowError)):
      category = "timeout"
    elif isinstance(exc, OSError):
      category = "transport"
    else:
      category = "runtime"
    logging.getLogger("prototype.verifier").warning("Identity verification category=%s", category)
    raise HTTPException(status_code=503, detail="current Identity state unavailable") from exc
  if current is None:
    logging.getLogger("prototype.verifier").warning("Identity verification category=absent_record")
    raise HTTPException(status_code=403, detail="Identity verification rejected")
  if current.owner_name_hex.lower() != owner_name_hex:
    logging.getLogger("prototype.verifier").warning("Identity verification category=binding_mismatch")
    raise HTTPException(status_code=403, detail="Identity verification rejected")
  current_key = current.owner_public_key_hex.lower()
  if current_key != grant.wallet_public_key_hex:
    logging.getLogger("prototype.verifier").warning("Identity verification category=key_mismatch")
    raise HTTPException(status_code=403, detail="Identity verification rejected")
  try:
    signing_input = base64.urlsafe_b64decode(grant.assertion_signing_input_b64 + "=" * (-len(grant.assertion_signing_input_b64) % 4))
    signature = base64.urlsafe_b64decode(grant.assertion_signature_b64 + "=" * (-len(grant.assertion_signature_b64) % 4))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(current_key)).verify(signature, signing_input)
  except (ValueError, InvalidSignature) as exc:
    logging.getLogger("prototype.verifier").warning("Identity verification category=signature_failure")
    raise HTTPException(status_code=403, detail="Identity verification rejected") from exc

  return {
    "owner_identifier": grant.owner_identifier,
    "owner_key_fingerprint": key_fingerprint(current.owner_public_key_hex),
    "identity_registry_seq": current.seq,
    "object_digest": grant.object_digest,
    "storage_aud": grant.storage_aud,
    "actions": grant.actions,
    "purpose": grant.purpose,
    "grant_jti": grant.grant_jti,
    "consent_exp": grant.consent_exp,
  }
