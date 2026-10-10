from __future__ import annotations

import importlib.util
import pathlib
import sys
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verifier_app", ROOT / "verifier" / "app.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def configured(monkeypatch):
  monkeypatch.setenv("REGISTRY_HOST", "registry")
  monkeypatch.setenv("REGISTRY_CLIENT_PORT", "9100")
  monkeypatch.setenv("REGISTRY_BOOTSTRAP", "/ip4/registry/tcp/9000/p2p/testpeer")
  monkeypatch.setenv("REGISTRY_QUORUM", "1")
  monkeypatch.setenv("STORAGE_AUDIENCES", "storage-a")


def grant():
  key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex("ab"*32))
  pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
  signing_input=b"header.payload"
  sig=key.sign(signing_input)
  import base64
  return {
    "owner_identifier": "mailto:alice@example.org",
    "wallet_public_key_hex": pub,
    "assertion_signing_input_b64": base64.urlsafe_b64encode(signing_input).decode().rstrip("="),
    "assertion_signature_b64": base64.urlsafe_b64encode(sig).decode().rstrip("="),
    "object_digest": "sha256:" + "a" * 64,
    "storage_aud": "storage-a",
    "actions": ["read"],
    "purpose": "test",
    "grant_jti": "jti-test",
    "consent_exp": 1999999999,
  }


def test_exact_identifier_current_key_and_seq_are_returned(monkeypatch):
  configured(monkeypatch)
  pub=grant()["wallet_public_key_hex"]
  module.resolve_identity_record = AsyncMock(return_value=type("Resolved",(),{"owner_name_hex":"6d61696c746f3a616c696365406578616d706c652e6f7267","owner_public_key_hex":pub,"seq":7})())
  with TestClient(module.app) as client:
    response = client.post("/v1/verify-grant", json=grant())
  assert response.status_code == 200
  body=response.json()
  assert body["owner_identifier"] == "mailto:alice@example.org"
  assert body["owner_key_fingerprint"].startswith("ed25519:")
  assert body["identity_registry_seq"] == 7
  module.resolve_identity_record.assert_awaited_once()


def test_registry_outage_fails_closed(monkeypatch):
  configured(monkeypatch)
  module.resolve_identity_record = AsyncMock(side_effect=TimeoutError("offline"))
  with TestClient(module.app) as client:
    response = client.post("/v1/verify-grant", json=grant())
  assert response.status_code == 503


def test_registry_key_mismatch_fails_closed(monkeypatch):
  configured(monkeypatch)
  module.resolve_identity_record = AsyncMock(return_value=type("Resolved",(),{"owner_name_hex":"6d61696c746f3a616c696365406578616d706c652e6f7267","owner_public_key_hex":"cd" * 32,"seq":8})())
  with TestClient(module.app) as client:
    response = client.post("/v1/verify-grant", json=grant())
  assert response.status_code == 403


def test_wallet_signature_failure_fails_closed(monkeypatch):
  configured(monkeypatch)
  pub=grant()["wallet_public_key_hex"]
  module.resolve_identity_record=AsyncMock(return_value=type("Resolved",(),{"owner_name_hex":"6d61696c746f3a616c696365406578616d706c652e6f7267","owner_public_key_hex":pub,"seq":9})())
  payload=grant();payload["assertion_signature_b64"]="AA"
  with TestClient(module.app) as client:
    response=client.post("/v1/verify-grant",json=payload)
  assert response.status_code==403
