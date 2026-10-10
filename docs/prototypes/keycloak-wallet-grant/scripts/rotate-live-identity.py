#!/usr/bin/env python3
"""Disposable legacy-to-v1 owner-key rotation, with exact remote read-back."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import time
import trio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat, PrivateFormat, NoEncryption
from decent_identity.identity_resolver import put_identity, resolve_identity_record
from decent_registry.dht.libp2p_dht import Libp2pKadDHT, DHTMode
from decent_registry.encoding import encode_multisignature_signed_update
from decent_registry.record_validator import RecordValidator
from decent_registry.signed_envelope import decode_signed_envelope, encode_multisignature_envelope
from decent_registry.verification import validate_multisignature_history

NAME = b'mailto:alice@example.org'
RECORD_KEY = hashlib.sha256(NAME).digest()


def public(key):
  return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


async def direct(bootstrap):
  async with Libp2pKadDHT(listen='/ip4/0.0.0.0/tcp/0', dht_mode=DHTMode.CLIENT) as dht:
    await dht.bootstrap(bootstrap)
    return await dht.read_remote_identity_envelope(RECORD_KEY.hex())


async def main(args):
  root = Path(args.directory)
  report: dict[str, object] = {'status':'failed','scope':'one configured Registry peer; not global currentness'}
  try:
    old = load_pem_private_key((root/'owner.key').read_bytes(), None)
    assert isinstance(old, Ed25519PrivateKey)
    predecessor = await direct(args.bootstrap)
    assert predecessor is not None
    prior = RecordValidator().validate_identity_get(record_key=RECORD_KEY,envelope_cbor=predecessor)
    assert prior.owner_name_hex == NAME.hex() and prior.owner_public_key == public(old) and prior.seq == 1
    previous_update, _ = decode_signed_envelope(predecessor)
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    for i,key in enumerate(keys):
      path = root / f'rotation-key-{i}.pem'
      with path.open('xb') as file:
        path.chmod(0o600)
        file.write(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    signed_update = encode_multisignature_signed_update(
      record_fields={1:NAME,2:public(keys[0])}, payload={},seq=2,
      authorization={1:1,2:1,3:5,4:1,5:2,6:[{1:f'signer-{i}',2:public(k)} for i,k in enumerate(keys)],7:hashlib.sha256(previous_update).digest()},
    )
    candidate = encode_multisignature_envelope(signed_update_bytes=signed_update,proofs=[{1:None,2:old.sign(hashlib.sha256(signed_update).digest())}])
    state = validate_multisignature_history(record_key=RECORD_KEY,envelopes=(predecessor,candidate))
    # Unauthorized successor cannot sign its own installation.
    bad = encode_multisignature_envelope(signed_update_bytes=signed_update,proofs=[{1:None,2:keys[0].sign(hashlib.sha256(signed_update).digest())}])
    try:
      validate_multisignature_history(record_key=RECORD_KEY,envelopes=(predecessor,bad))
    except ValueError:
      report['unauthorized_rotation_locally_rejected'] = True
    else:
      raise AssertionError('successor cannot authorize its own installation')
    assert await direct(args.bootstrap) == predecessor
    (root/'rotation-predecessor.cbor').write_bytes(predecessor)
    (root/'rotation.cbor').write_bytes(candidate)
    # Write once. Any error after dispatch is ambiguous and resolved by reads.
    (root/'rotation-dispatch.started').write_text('possibly dispatched; read-back only\n')
    try:
      await put_identity(identifier=NAME.decode(),host='0.0.0.0',port=0,bootstrap=[args.bootstrap],finalized_envelope_cbor=candidate)
    except Exception as exc:
      report['write_call_exception_type'] = type(exc).__name__
    deadline=time.monotonic()+20
    observed=None
    while time.monotonic()<deadline:
      observed=await direct(args.bootstrap)
      if observed==candidate:
        break
      await trio.sleep(.3)
    assert observed==candidate, 'exact rotation not remotely confirmed'
    resolved=await resolve_identity_record(owner_name_hex=NAME.hex(),host='0.0.0.0',port=0,bootstrap=[args.bootstrap],quorum=1)
    assert resolved is not None and resolved.owner_name_hex==NAME.hex() and resolved.owner_public_key_hex==public(keys[0]).hex() and resolved.seq==2
    assert resolved.authorization is not None and resolved.authorization.operation==5 and resolved.authorization.state_hash==state.state_hash.hex()
    report.update(status='passed',exact_remote_candidate=True,fresh_history_resolution=True,seq=2,state_hash=state.state_hash.hex(),new_public_key_hex=public(keys[0]).hex())
  except Exception as exc:
    report['exception_type']=type(exc).__name__
  (root/'rotation-report.json').write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report))
  if report['status']!='passed':
    raise SystemExit(1)


if __name__=='__main__':
  p=argparse.ArgumentParser()
  p.add_argument('--bootstrap',required=True)
  p.add_argument('--directory',required=True)
  args=p.parse_args()
  async def bounded():
    with trio.fail_after(45):
      await main(args)
  trio.run(bounded)
