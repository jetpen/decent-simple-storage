"""Fail closed on absent TLS files; the verifier image has no plaintext mode."""
import os
from pathlib import Path
import ssl
import uvicorn


def main():
  paths={name:Path(os.environ.get(name,default)) for name,default in (
    ('VERIFIER_TLS_SERVER_KEY','/tls/server.key'),
    ('VERIFIER_TLS_SERVER_CERT','/tls/server.crt'),
    ('VERIFIER_TLS_CLIENT_CA','/tls/client-ca.crt'),
  )}
  if any(not path.is_file() for path in paths.values()):
    raise SystemExit('Verifier TLS files unavailable; refusing to start')
  uvicorn.run('app:app',host='0.0.0.0',port=8000,
    ssl_keyfile=str(paths['VERIFIER_TLS_SERVER_KEY']),
    ssl_certfile=str(paths['VERIFIER_TLS_SERVER_CERT']),
    ssl_ca_certs=str(paths['VERIFIER_TLS_CLIENT_CA']),
    ssl_cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLS_SERVER)


if __name__=='__main__':main()
