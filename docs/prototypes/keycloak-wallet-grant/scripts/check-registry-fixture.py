#!/usr/bin/env python3
"""Throwaway live Registry/verifier preflight; no Keycloak required."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SCRATCH_ROOT = Path(os.environ.get("TMPDIR", Path.home() / ".hermes/cache/scratch"))
IDENTITY = "mailto:alice@example.org"
AUDIENCE = "https://storage.example.test/instance/alpha"


def run(*args, timeout=45, input=None):
  return subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)


def checked(*args, **kwargs):
  result = run(*args, **kwargs)
  if result.returncode:
    # Deliberately don't echo subprocess payloads or arbitrary exception text.
    raise RuntimeError(f"{args[0]} command failed (exit {result.returncode})")
  return result.stdout


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--report", type=Path, required=True)
  parser.add_argument("--listen-host", default="0.0.0.0")
  parser.add_argument("--skip-http", action="store_true")
  args = parser.parse_args()
  stack = "decent-fixture-" + uuid.uuid4().hex[:12]
  report = {"status": "failed", "gates": {}, "listen_host": args.listen_host, "sources": {}, "images": {}}
  for name in ("decent-registry", "decent-identity", "decent-simple-storage"):
    # Explicit sibling paths in this experiment.
    path = Path('/home/ben/projects') / name
    report["sources"][name] = {"revision": checked("git", "-C", str(path), "rev-parse", "HEAD").strip(), "dirty": bool(checked("git", "-C", str(path), "status", "--porcelain"))}
  for image in ("localhost/decent-registry-prototype:local", "localhost/decent-identity-verifier-prototype:local"):
    report["images"][image] = checked("podman", "image", "inspect", image, "--format", "{{.Id}}").strip()
  stage = "setup"
  containers = []
  network_created = False
  cleanup_errors = []
  with tempfile.TemporaryDirectory(prefix="registry-fixture-", dir=SCRATCH_ROOT) as directory:
    scratch = Path(directory)
    try:
      checked("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(scratch / "owner.key"))
      (scratch / "owner.key").chmod(0o600)
      from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
      from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
      key = load_pem_private_key((scratch / "owner.key").read_bytes(), None)
      assert isinstance(key, Ed25519PrivateKey)
      public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
      checked("podman", "network", "create", stack)
      network_created = True
      server = stack + "-registry"
      containers.append(server)
      checked("podman", "run", "-d", "--name", server, "--network", stack, "--network-alias", "registry", "localhost/decent-registry-prototype:local", "node", "--host", "0.0.0.0", "--port", "9000", "-v")
      deadline = time.monotonic() + 45
      bootstrap = None
      peer = None
      while time.monotonic() < deadline:
        logs = checked("podman", "logs", server)
        match = re.search(r"\[BOOTSTRAP\] (\S+)", logs)
        if match:
          peer = match.group(1).split("/p2p/")[-1]
          address = checked("podman", "inspect", server, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}").strip()
          bootstrap = f"/ip4/{address}/tcp/9000/p2p/{peer}"
          break
        time.sleep(.3)
      assert bootstrap, "Registry startup not ready"
      report['registry_peer_id'] = peer
      owner_hex = IDENTITY.encode().hex()
      cli = ["podman", "run", "--rm", "--network", stack, "-v", f"{scratch}:/scratch:ro", "localhost/decent-registry-prototype:local"]
      network = ["--host", "0.0.0.0", "--port", "9100", "--bootstrap", bootstrap]
      stage = "publication"
      publication = run(*cli, "put", "identity", *network, "--owner-name", owner_hex, "--owner-privkey", "/scratch/owner.key", "--seq", "1")
      if publication.returncode:
        report['publication_error'] = {'exit_code': publication.returncode}
      assert publication.returncode == 0, 'Registry writer failed'
      report["gates"][stage] = "writer returned; not publication proof"
      stage = "independent_read"
      deadline = time.monotonic() + 45
      record = None
      attempts = 0
      while time.monotonic() < deadline:
        attempts += 1
        result = run(*cli, "get", "identity", *network, "--owner-name", owner_hex, timeout=15)
        if result.returncode == 0:
          record = json.loads(result.stdout)
          break
        time.sleep(.3)
      assert record is not None, "fresh reader did not resolve published Identity"
      assert record["owner_name"] == owner_hex
      assert record["owner_public_key"] == public
      assert record["seq"] == 1
      report["gates"][stage] = {"status": "passed", "attempts": attempts, "sequence": 1, "exact_identity_and_key": True}
      stage = "resolver_container"
      resolver_code = '''import trio,json,sys
from decent_identity.identity_resolver import resolve_identity_record
async def main():
 try:
  r=await resolve_identity_record(owner_name_hex=sys.argv[1],host=sys.argv[2],port=0,bootstrap=[sys.argv[3]],quorum=1)
  assert r is not None
  assert r.owner_name_hex==sys.argv[1] and r.owner_public_key_hex==sys.argv[4] and r.seq==1
  print(json.dumps({"status":"passed","sequence":r.seq}))
 except Exception as exc:
  print(json.dumps({"status":"failed","exception_type":type(exc).__name__}))
  raise SystemExit(1)
trio.run(main)
'''
      result = run("podman", "run", "--rm", "--network", stack, "--entrypoint", "python", "localhost/decent-identity-verifier-prototype:local", "-c", resolver_code, owner_hex, args.listen_host, bootstrap, public)
      report["gates"][stage] = {"status": "passed" if result.returncode == 0 else "failed", "diagnostic": result.stdout.strip()}
      assert result.returncode == 0, "resolver container failed"
      if not args.skip_http:
        from create_verifier_tls import create
        from check_verifier_tls import context
        create(scratch / "tls")
        tls = context(scratch / "tls", "preflight")
        stage = "http_verifier"
        verifier = stack + "-verifier"
        containers.append(verifier)
        checked("podman", "run", "-d", "--name", verifier, "--network", stack, "-p", "127.0.0.1::8000", "-v", f"{scratch / 'tls'}:/tls:ro", "-e", f"REGISTRY_HOST={args.listen_host}", "-e", "REGISTRY_CLIENT_PORT=0", "-e", f"REGISTRY_BOOTSTRAP={bootstrap}", "-e", "REGISTRY_QUORUM=1", "-e", f"STORAGE_AUDIENCES={AUDIENCE}", "localhost/decent-identity-verifier-prototype:local")
        published = checked("podman", "port", verifier, "8000/tcp").strip()
        url = "https://" + published
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
          try:
            urllib.request.urlopen(url + "/healthz", timeout=2, context=tls).close()
            break
          except (OSError, urllib.error.URLError):
            time.sleep(.3)
        fields = {"owner_identifier": IDENTITY, "wallet_public_key_hex": public, "object_digest": "sha256:" + "a" * 64, "storage_aud": AUDIENCE, "actions": ["read"], "purpose": "fixture-preflight", "grant_jti": uuid.uuid4().hex, "consent_exp": int(time.time()) + 120}
        b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
        signing_input = (b64(b'{"alg":"EdDSA"}') + "." + b64(json.dumps(fields).encode())).encode()
        fields.update(assertion_signing_input_b64=b64(signing_input), assertion_signature_b64=b64(key.sign(signing_input)))
        req = urllib.request.Request(url + "/v1/verify-grant", data=json.dumps(fields).encode(), headers={"Content-Type": "application/json"})
        try:
          with urllib.request.urlopen(req, timeout=30, context=tls) as response:
            body = json.load(response)
            status = response.status
        except urllib.error.HTTPError as exc:
          status = exc.code
          body = json.load(exc)
        report["gates"][stage] = {"status_code": status}
        assert status == 200, f"live verifier returned {status}"
        assert body['owner_identifier'] == IDENTITY
        assert body['owner_key_fingerprint'] == 'ed25519:' + hashlib.sha256(bytes.fromhex(public)).hexdigest()
        assert body['identity_registry_seq'] == 1
        for field in ('object_digest','storage_aud','actions','purpose','grant_jti','consent_exp'):
          assert body[field] == fields[field]
        report["gates"][stage]['exact_claims'] = True
      report['status'] = 'passed'
    except Exception as exc:
      report['failure'] = {'gate': stage, 'exception_type': type(exc).__name__, 'message': str(exc) if isinstance(exc, AssertionError) else 'command/runtime failure'}
    finally:
      for container in reversed(containers):
        result = run("podman", "rm", "-f", container)
        if result.returncode:
          cleanup_errors.append(container)
      if network_created and run("podman", "network", "rm", stack).returncode:
        cleanup_errors.append(stack)
      remaining = json.loads(checked('podman','ps','-a','--format','json'))
      assert not any(x.get('Names') and any(n in containers for n in x['Names']) for x in remaining), 'test containers remain'
  report['cleanup'] = {'errors': cleanup_errors, 'scratch_removed': not scratch.exists(), 'containers_removed': True}
  if cleanup_errors:
    report['status']='failed'
  args.report.parent.mkdir(parents=True, exist_ok=True)
  args.report.write_text(json.dumps(report, indent=2) + '\n')
  print(json.dumps(report, indent=2))
  return 0 if report['status']=='passed' else 1


if __name__ == '__main__':
  raise SystemExit(main())
