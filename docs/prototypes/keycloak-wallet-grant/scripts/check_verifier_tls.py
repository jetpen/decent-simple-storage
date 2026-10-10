#!/usr/bin/env python3
"""Exercise real mutual-TLS denial/positive controls without grant payloads."""
import argparse
import json
from pathlib import Path
import ssl
import socket
from urllib.parse import urlsplit
import urllib.request


def context(directory,client=None,trust='server-ca'):
  ctx=ssl.create_default_context(cafile=str(directory/(trust+'.crt')))
  ctx.minimum_version=ssl.TLSVersion.TLSv1_2
  if client:ctx.load_cert_chain(str(directory/(client+'.crt')),str(directory/(client+'.key')))
  return ctx


def main():
  p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--tls-dir',type=Path,required=True);p.add_argument('--report',type=Path,required=True);args=p.parse_args()
  results={}
  for label,client,trust in [('missing_client',None,'server-ca'),('unauthorized_client','unauthorized','server-ca'),('untrusted_server','preflight','rogue-ca'),('authorized_client','preflight','server-ca')]:
    try:
      with urllib.request.urlopen(args.url+'/healthz',context=context(args.tls_dir,client,trust),timeout=5) as response:
        passed=response.status==200
      results[label]='accepted' if passed else 'http_failure'
    except (OSError,ssl.SSLError):results[label]='tls_rejected'
  endpoint=urlsplit(args.url)
  # Send a plain HTTP request to the TLS-only port; no HTTP application
  # response may be returned even with otherwise valid grant formatting.
  try:
    with socket.create_connection((endpoint.hostname,endpoint.port or 443),timeout=3) as connection:
      connection.sendall(b'GET /healthz HTTP/1.1\r\nHost: verifier\r\nConnection: close\r\n\r\n')
      received=connection.recv(256)
    results['plaintext']='accepted' if received.startswith(b'HTTP/') else 'rejected'
  except OSError:results['plaintext']='rejected'
  wrong_name=context(args.tls_dir,'preflight')
  try:
    with socket.create_connection((endpoint.hostname,endpoint.port or 443),timeout=3) as connection:
      with wrong_name.wrap_socket(connection,server_hostname='wrong-verifier.example.test'):
        results['hostname_mismatch']='accepted'
  except (OSError,ssl.SSLError):results['hostname_mismatch']='tls_rejected'
  passed=all(results[label]=='tls_rejected' for label in ('missing_client','unauthorized_client','untrusted_server','hostname_mismatch')) and results['authorized_client']=='accepted' and results['plaintext']=='rejected'
  report={'passed':passed,'transport':'mutual TLS with separate server/client trust anchors','cases':results}
  args.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
  return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
