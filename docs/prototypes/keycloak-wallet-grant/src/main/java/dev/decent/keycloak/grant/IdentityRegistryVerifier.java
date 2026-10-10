package dev.decent.keycloak.grant;

import java.util.Map;
import java.util.List;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.keycloak.util.JsonSerialization;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.protocol.oidc.JWTAuthorizationGrantValidationContext;

/** Test/development validator for a deterministic fixture. Replace with real wallet/Registry validation. */
public interface IdentityRegistryVerifier {
  VerifiedGrantClaims verify(JWTAuthorizationGrantValidationContext assertion) throws IdentityBrokerException;
  static IdentityRegistryVerifier testFixture() {
    return assertion -> {
      if (!"mailto:alice@example.org".equals(assertion.getSubject())) throw new IdentityBrokerException("unknown exact Identity identifier");
      Object c = assertion.getJWT().getOtherClaims().get("decent_grant");
      if (!(c instanceof Map<?,?> m)) throw new IdentityBrokerException("missing signed grant claims");
      String storage = required(m,"storage_aud"), owner = required(m,"owner_identifier"), fp = required(m,"owner_key_fingerprint");
      String digest = required(m,"object_digest"), purpose = required(m,"purpose"), jti = required(m,"grant_jti");
      Object seq = m.get("identity_registry_seq"), exp=m.get("consent_exp"); Object acts=m.get("actions");
      if (!(seq instanceof Number n) || !(exp instanceof Number e) || !(acts instanceof List<?> list) || list.isEmpty() || list.stream().anyMatch(a->!(a instanceof String))) throw new IdentityBrokerException("invalid typed grant claims");
      if (!owner.equals(assertion.getSubject())) throw new IdentityBrokerException("exact owner identifier mismatch");
      return new VerifiedGrantClaims(storage,owner,fp,n.longValue(),digest,list.stream().map(String.class::cast).toList(),purpose,jti,e.longValue());
    };
  }

  static IdentityRegistryVerifier remote(String baseUrl, java.util.Set<String> acceptedAudiences) {
    HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(2)).build();
    java.util.Set<String> allowedAudiences = java.util.Set.copyOf(acceptedAudiences);
    if (allowedAudiences.isEmpty()) throw new IllegalArgumentException("registered Storage audiences required");
    return assertion -> {
      String owner = assertion.getSubject();
      if (owner == null || owner.isBlank() || !owner.matches("mailto:[^\\s]+|tel:\\+?[0-9]+")) throw new IdentityBrokerException("exact owner identifier is invalid");
      Object raw = assertion.getJWT().getOtherClaims().get("decent_grant");
      if (!(raw instanceof Map<?,?> m)) throw new IdentityBrokerException("missing signed wallet grant");
      String grantOwner = required(m,"owner_identifier");
      String storage = required(m,"storage_aud");
      if (!owner.equals(grantOwner)) throw new IdentityBrokerException("external subject is not the exact grant owner identifier");
      if (!allowedAudiences.contains(storage)) throw new IdentityBrokerException("Storage audience is not registered");
      String publicKey = required(m,"wallet_public_key");
      if (!publicKey.matches("[0-9a-f]{64}")) throw new IdentityBrokerException("wallet public key format rejected");
      String digest = required(m,"object_digest"), purpose = required(m,"purpose"), jti = required(m,"grant_jti");
      Object consentExp=m.get("consent_exp"), rawActions=m.get("actions");
      if (!(consentExp instanceof Number exp) || !(rawActions instanceof List<?> list) || list.isEmpty() || list.size()>8 || list.stream().anyMatch(a->!(a instanceof String s)||s.isBlank()||s.length()>32) || list.stream().distinct().count()!=list.size()) throw new IdentityBrokerException("wallet grant claims have invalid types");
      if (!digest.matches("sha256:[0-9a-f]{64}") || purpose.length()>128 || jti.length()>256) throw new IdentityBrokerException("grant digest/jti rejected");
      if (!jti.equals(assertion.getJWT().getId())) throw new IdentityBrokerException("grant jti must equal signed assertion jti");
      if (assertion.getJWT().getExp()==null || exp.longValue()<=0 || exp.longValue()>assertion.getJWT().getExp()) throw new IdentityBrokerException("consent expiry exceeds signed assertion expiry");
      try {
        var payload = new java.util.HashMap<String,Object>();
        payload.put("owner_identifier", owner); payload.put("wallet_public_key_hex", publicKey);
        payload.put("object_digest", digest); payload.put("storage_aud", storage);
        payload.put("actions", list); payload.put("purpose", purpose); payload.put("grant_jti", jti);
        payload.put("consent_exp", exp.longValue());
        payload.put("assertion_signing_input_b64", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(assertion.getJws().getEncodedSignatureInput().getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        payload.put("assertion_signature_b64", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(assertion.getJws().getSignature()));
        String body = JsonSerialization.writeValueAsString(payload);
        HttpRequest req=HttpRequest.newBuilder(URI.create(baseUrl+"/v1/verify-grant")).timeout(Duration.ofSeconds(8)).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> response=http.send(req,HttpResponse.BodyHandlers.ofString());
        if (response.statusCode()>=500) throw new IdentityBrokerException("current Identity verifier unavailable");
        if (response.statusCode()!=200) throw new IdentityBrokerException("wallet grant failed current Identity verification");
        Map<?,?> verified=JsonSerialization.readValue(response.body(),Map.class);
        String verifiedOwner=required(verified,"owner_identifier"), fingerprint=required(verified,"owner_key_fingerprint");
        if (!verifiedOwner.equals(owner) || !fingerprint.matches("ed25519:[0-9a-f]{64}")) throw new IdentityBrokerException("verifier response binding rejected");
        if (!required(verified,"storage_aud").equals(storage) || !required(verified,"object_digest").equals(digest) || !required(verified,"purpose").equals(purpose) || !required(verified,"grant_jti").equals(jti) || !(verified.get("consent_exp") instanceof Number returnedExp) || returnedExp.longValue()!=exp.longValue() || !verified.get("actions").equals(list)) throw new IdentityBrokerException("verifier changed signed grant fields");
        Object verifiedSeq=verified.get("identity_registry_seq");
        if (!(verifiedSeq instanceof Number seq) || seq.longValue()<0) throw new IdentityBrokerException("verifier sequence invalid");
        return new VerifiedGrantClaims(storage,owner,fingerprint,seq.longValue(),digest,list.stream().map(String.class::cast).toList(),purpose,jti,exp.longValue());
      } catch (IdentityBrokerException e) { throw e; }
      catch (Exception e) { throw new IdentityBrokerException("current Identity verifier unavailable",e); }
    };
  }
  private static String required(Map<?,?> claims,String name) throws IdentityBrokerException { Object v=claims.get(name); if (!(v instanceof String s)||s.isBlank()) throw new IdentityBrokerException("missing/invalid "+name); return s; }
}
