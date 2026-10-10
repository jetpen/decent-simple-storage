package dev.decent.keycloak.grant;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Prototype workload TLS credentials are mounted files, never editable grant attributes. */
final class VerifierTLS {
  static SSLContext context() {
    try {
      return context(required("VERIFIER_TLS_CA"), required("VERIFIER_TLS_CLIENT_CERT"), required("VERIFIER_TLS_CLIENT_KEY"));
    } catch (Exception e) { throw new IllegalArgumentException("verifier TLS credentials unavailable", e); }
  }
  private static Path required(String name) {
    String value=System.getenv(name);
    if(value==null || value.isBlank()) throw new IllegalArgumentException("missing verifier TLS credential path");
    return Path.of(value);
  }
  static SSLContext context(Path ca, Path certificate, Path key) throws Exception {
    var certificates=CertificateFactory.getInstance("X.509");
    var trust=KeyStore.getInstance(KeyStore.getDefaultType());trust.load(null,null);
    try(var input=Files.newInputStream(ca)) {
      int i=0;for(var cert:certificates.generateCertificates(input)) trust.setCertificateEntry("ca-"+(i++),cert);
      if(i==0) throw new IllegalArgumentException("no verifier trust anchor");
    }
    java.security.cert.Certificate[] chain;
    try(var input=Files.newInputStream(certificate)) {
      chain=certificates.generateCertificates(input).toArray(java.security.cert.Certificate[]::new);
    }
    if(chain.length==0) throw new IllegalArgumentException("no workload certificate");
    String pem=Files.readString(key).replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replaceAll("\\s", "");
    var privateKey=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
    // This password protects only the transient in-memory keystore; PEM files
    // are protected by private mounts and filesystem permissions in this slice.
    char[] password=new char[0];
    var keys=KeyStore.getInstance(KeyStore.getDefaultType());keys.load(null,null);
    keys.setKeyEntry("workload",privateKey,password,chain);
    var km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(keys,password);
    var tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(trust);
    var ssl=SSLContext.getInstance("TLS");ssl.init(km.getKeyManagers(),tm.getTrustManagers(),new SecureRandom());
    return ssl;
  }
}
