"""Regression for the real resolver runtime boundary, without a network mock."""
import importlib.util
from pathlib import Path
import sys

from fastapi.testclient import TestClient
import trio

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_verifier', ROOT / 'verifier/app.py')
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def test_resolver_executes_on_its_trio_runtime_from_asyncio_http(monkeypatch):
  monkeypatch.setenv('REGISTRY_HOST', '0.0.0.0')
  monkeypatch.setenv('REGISTRY_CLIENT_PORT', '0')
  monkeypatch.setenv('REGISTRY_BOOTSTRAP', '/ip4/127.0.0.1/tcp/9000/p2p/test')
  monkeypatch.setenv('STORAGE_AUDIENCES', 'storage-a')
  observed = []

  async def runtime_probe(**kwargs):
    # This is a real Trio primitive; it fails on asyncio, just like libp2p.
    observed.append(trio.lowlevel.current_task().name)
    assert kwargs['host'] == '0.0.0.0'
    return None

  monkeypatch.setattr(module, 'resolve_identity_record', runtime_probe)
  import base64
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives import serialization
  key = Ed25519PrivateKey.generate()
  data = b'header.payload'
  b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
  payload = {'owner_identifier':'mailto:alice@example.org','wallet_public_key_hex':key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex(),'object_digest':'sha256:'+'a'*64,'storage_aud':'storage-a','actions':['read'],'purpose':'test','grant_jti':'test','consent_exp':1999999999,'assertion_signing_input_b64':b64(data),'assertion_signature_b64':b64(key.sign(data))}
  with TestClient(module.app) as client:
    response = client.post('/v1/verify-grant', json=payload)
  assert observed, 'resolver did not run on Trio'
  assert response.status_code == 403, 'absent Identity must be distinguished from runtime failure'
