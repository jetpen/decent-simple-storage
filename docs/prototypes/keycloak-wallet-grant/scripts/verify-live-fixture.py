#!/usr/bin/env python3
"""Gate a running disposable Registry/verifier topology before Keycloak tests."""
from __future__ import annotations
import argparse
import os
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.request
import urllib.error
import uuid


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--network', required=True)
  parser.add_argument('--bootstrap', required=True)
  parser.add_argument('--key', type=Path, required=True)
  parser.add_argument('--verifier-url', required=True)
  parser.add_argument('--report', type=Path, required=True)
  parser.add_argument('--tls-dir', type=Path, required=True)
  args = parser.parse_args()
  from check_verifier_tls import context
  tls = context(args.tls_dir, 'preflight')
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
  key = load_pem_private_key(args.key.read_bytes(), None)
  assert isinstance(key, Ed25519PrivateKey)
  public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
  identifier = 'mailto:alice@example.org'
  owner_hex = identifier.encode().hex()
  report = {'status':'failed','gates':{}}
  stage = 'independent_read'
  try:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
      response = subprocess.run(['podman','run','--rm','--network',args.network,os.environ.get('KC_REGISTRY_IMAGE','localhost/decent-registry-prototype:local'),'get','identity','--host','0.0.0.0','--port','9100','--bootstrap',args.bootstrap,'--owner-name',owner_hex],capture_output=True,text=True,timeout=15)
      if response.returncode == 0:
        record = json.loads(response.stdout)
        assert record['owner_name'] == owner_hex and record['owner_public_key'] == public and record['seq'] == 1
        break
      time.sleep(.3)
    else:
      raise AssertionError('independent read-back did not match')
    report['gates'][stage] = 'passed'
    stage = 'resolver_container'
    code = '''import trio,sys
from decent_identity.identity_resolver import resolve_identity_record
async def main():
 with trio.fail_after(8):
  r=await resolve_identity_record(owner_name_hex=sys.argv[1],host='0.0.0.0',port=0,bootstrap=[sys.argv[2]],quorum=1)
  assert r is not None and r.owner_name_hex==sys.argv[1] and r.owner_public_key_hex==sys.argv[3] and r.seq==1
trio.run(main)
'''
    result = subprocess.run(['podman','run','--rm','--network',args.network,'--entrypoint','python',os.environ.get('KC_VERIFIER_IMAGE','localhost/decent-identity-verifier-prototype:local'),'-c',code,owner_hex,args.bootstrap,public],capture_output=True,text=True,timeout=20)
    assert result.returncode == 0, 'resolver failed'
    report['gates'][stage] = 'passed'
    stage = 'http_verifier'
    fields = {'owner_identifier':identifier,'wallet_public_key_hex':public,'storage_aud':'https://storage.example.test/instance/alpha','object_digest':'sha256:'+'a'*64,'actions':['read'],'purpose':'fixture-preflight','grant_jti':uuid.uuid4().hex,'consent_exp':int(time.time())+120}
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
    signing_input = (b64(b'{"alg":"EdDSA"}')+'.'+b64(json.dumps(fields).encode())).encode()
    fields.update(assertion_signing_input_b64=b64(signing_input), assertion_signature_b64=b64(key.sign(signing_input)))
    request = urllib.request.Request(args.verifier_url+'/v1/verify-grant',data=json.dumps(fields).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=15,context=tls) as response:
      body = json.load(response)
      assert response.status == 200
    assert body['owner_key_fingerprint']=='ed25519:'+hashlib.sha256(bytes.fromhex(public)).hexdigest()
    assert body['identity_registry_seq']==1
    for field in ('owner_identifier','storage_aud','object_digest','actions','purpose','grant_jti','consent_exp'):
      assert body[field] == fields[field]
    report['gates'][stage] = 'passed'
    report['status'] = 'passed'
  except Exception as exc:
    report['failure'] = {'gate':stage,'exception_type':type(exc).__name__}
  args.report.parent.mkdir(parents=True, exist_ok=True)
  args.report.write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report))
  return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
  raise SystemExit(main())
