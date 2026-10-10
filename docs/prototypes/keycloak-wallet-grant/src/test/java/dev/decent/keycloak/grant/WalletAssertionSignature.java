package dev.decent.keycloak.grant;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

final class WalletAssertionSignature {
  private WalletAssertionSignature() {}
  static boolean verify(String signingInput, byte[] signature, String publicKeyHex) {
    try {
      byte[] raw=HexFormat.of().parseHex(publicKeyHex);
      if(raw.length!=32)return false;
      byte[] spki=new byte[raw.length+12];
      byte[] prefix=HexFormat.of().parseHex("302a300506032b6570032100");
      System.arraycopy(prefix,0,spki,0,prefix.length);System.arraycopy(raw,0,spki,prefix.length,raw.length);
      var key=KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      Signature verifier=Signature.getInstance("Ed25519");verifier.initVerify(key);verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));return verifier.verify(signature);
    } catch(Exception e){return false;}
  }
}
