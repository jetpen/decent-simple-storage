#!/usr/bin/env python3
"""Disposable prototype PKI; no certificate/key contents are printed."""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def create(directory):
  root=Path(directory);root.mkdir(mode=0o700,parents=True,exist_ok=True)
  now=datetime.now(timezone.utc)
  def key():return rsa.generate_private_key(public_exponent=65537,key_size=2048)
  def name(label):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label)])
  def write(path,data,private=False):
    path.write_bytes(data);path.chmod(0o600 if private else 0o644)
  def ca(label):
    k=key();n=name(label)
    c=x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(k.public_key()),critical=False).sign(k,hashes.SHA256())
    write(root/(label+'.crt'),c.public_bytes(serialization.Encoding.PEM));return k,c
  server_ca=ca('server-ca');client_ca=ca('client-ca');rogue_ca=ca('rogue-ca')
  def leaf(label,issuer,server=False):
    k=key();ik,ic=issuer
    b=x509.CertificateBuilder().subject_name(name(label)).issuer_name(ic.subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),critical=True)
    if server:b=b.add_extension(x509.SubjectAlternativeName([x509.DNSName('verifier'),x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
    c=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ik.public_key()),critical=False).sign(ik,hashes.SHA256())
    write(root/(label+'.crt'),c.public_bytes(serialization.Encoding.PEM));write(root/(label+'.key'),k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),True)
  leaf('server',server_ca,True)
  for label in ('keycloak1','keycloak2','preflight'):leaf(label,client_ca)
  leaf('unauthorized',rogue_ca)
  # CA private keys are deliberately not persisted or mounted anywhere.


if __name__=='__main__':
  p=argparse.ArgumentParser();p.add_argument('directory');create(p.parse_args().directory)
