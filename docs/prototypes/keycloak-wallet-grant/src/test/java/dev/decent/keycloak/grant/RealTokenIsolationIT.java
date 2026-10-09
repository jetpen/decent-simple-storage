package dev.decent.keycloak.grant;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.time.Duration;
import java.util.*;
import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.*;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureException;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.AccessToken;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RealTokenIsolationIT {
  private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
  private final ObjectMapper json=new ObjectMapper();
  private String tokenUrl, clientId, clientSecret, issuer;
  private PrivateKey assertionKey;
  @BeforeAll void start() throws Exception {
    String url=System.getenv().getOrDefault("KC_URL","http://127.0.0.1:18080");
    tokenUrl=url+"/realms/decent/protocol/openid-connect/token";issuer=url+"/realms/decent";
    clientId=System.getenv().getOrDefault("KC_CLIENT_ID","decent-client");
    clientSecret=System.getenv().getOrDefault("KC_CLIENT_SECRET","prototype-secret");
    String raw=System.getenv("KC_ASSERTION_PRIVATE_KEY").replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");assertionKey=KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(raw)));
    HttpResponse<String> r=http.send(HttpRequest.newBuilder(URI.create(url+"/realms/decent/.well-known/openid-configuration")).GET().build(),HttpResponse.BodyHandlers.ofString());assertTrue(r.statusCode()==200 || r.statusCode()==404,r.body());
  }
  private String assertion(Map<String,Object> extra) {
    AccessToken a=new AccessToken();a.id(UUID.randomUUID().toString());a.subject("mailto:alice@example.org");a.issuer("https://wallet.test");a.audience(issuer);a.issuedNow();a.exp(System.currentTimeMillis()/1000+55L);a.setOtherClaims("decent_grant",extra);
    SignatureSignerContext signer=new SignatureSignerContext() {
      public String getKid(){return "fixture-ed25519";} public String getAlgorithm(){return "EdDSA";} public String getHashAlgorithm(){return "EdDSA";}
      public byte[] sign(byte[] data) throws SignatureException {try {Signature sig=Signature.getInstance("Ed25519");sig.initSign(assertionKey);sig.update(data);return sig.sign();}catch(Exception e){throw new SignatureException("signing failed",e);}}
    };
    return new JWSBuilder().kid("fixture-ed25519").jsonContent(a).sign(signer);
  }
  private HttpResponse<String> exchange(String assertion) throws Exception {
    String body="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="+java.net.URLEncoder.encode(assertion,StandardCharsets.UTF_8);
    String auth=Base64.getEncoder().encodeToString((clientId+":"+clientSecret).getBytes(StandardCharsets.UTF_8));
    return http.send(HttpRequest.newBuilder(URI.create(tokenUrl)).timeout(Duration.ofSeconds(20)).header("Authorization","Basic "+auth).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
  }
  private Map<String,Object> claims(String jti) {return Map.of("storage_aud","https://storage.example.test/instance/alpha","owner_identifier","mailto:alice@example.org","owner_key_fingerprint","ed25519:fp-verified","identity_registry_seq",9,"object_digest","sha256:"+"a".repeat(64),"actions",List.of("read","update"),"purpose","profile-update","grant_jti",jti,"consent_exp",System.currentTimeMillis()/1000+50);}
  private JsonNode decodePayload(String jwt) throws Exception {return json.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));}
  private void verifyKeycloakSignature(String jwt) throws Exception {
    String[] p=jwt.split("\\.");JsonNode h=json.readTree(Base64.getUrlDecoder().decode(p[0]));assertEquals("RS256",h.get("alg").asText());
    String certs=System.getenv().getOrDefault("KC_URL","http://127.0.0.1:18080")+"/realms/decent/protocol/openid-connect/certs";
    JsonNode keys=json.readTree(http.send(HttpRequest.newBuilder(URI.create(certs)).GET().build(),HttpResponse.BodyHandlers.ofString()).body()).get("keys");
    JsonNode jwk=null;for(JsonNode k:keys)if(k.get("kid").asText().equals(h.get("kid").asText())){jwk=k;break;}assertNotNull(jwk,"signing key id found in realm JWKS");
    BigInteger modulus=new BigInteger(1,Base64.getUrlDecoder().decode(jwk.get("n").asText()));BigInteger exponent=new BigInteger(1,Base64.getUrlDecoder().decode(jwk.get("e").asText()));
    RSAPublicKey key=(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus,exponent));Signature sig=Signature.getInstance("SHA256withRSA");sig.initVerify(key);sig.update((p[0]+"."+p[1]).getBytes(StandardCharsets.US_ASCII));assertTrue(sig.verify(Base64.getUrlDecoder().decode(p[2])),"Keycloak-issued token signature verifies against realm JWKS");
  }
  @Test void signedGrantMintsSignedTokenWithExactClaimsAndNoRefresh() throws Exception {
    HttpResponse<String> r=exchange(assertion(claims(UUID.randomUUID().toString())));assertEquals(200,r.statusCode(),r.body());JsonNode response=json.readTree(r.body());assertFalse(response.hasNonNull("refresh_token"));verifyKeycloakSignature(response.get("access_token").asText());JsonNode access=decodePayload(response.get("access_token").asText());assertEquals("mailto:alice@example.org",access.get("sub").asText());assertEquals("https://storage.example.test/instance/alpha",access.get("storage_aud").asText());assertEquals("ed25519:fp-verified",access.get("owner_key_fingerprint").asText());assertEquals(9,access.get("identity_registry_seq").asInt());assertEquals("profile-update",access.get("storage_purpose").asText());assertEquals("read",access.get("storage_actions").get(0).asText());
  }
  @Test void grantClaimsRemainBoundToTheirSignedStorageAudience() throws Exception {
    Map<String,Object> wrong=new HashMap<>(claims(UUID.randomUUID().toString()));wrong.put("storage_aud","https://storage.example.test/instance/beta");
    HttpResponse<String> r=exchange(assertion(wrong));assertEquals(200,r.statusCode(),r.body());JsonNode response=json.readTree(r.body());JsonNode access=decodePayload(response.get("access_token").asText());assertEquals("https://storage.example.test/instance/beta",access.get("storage_aud").asText());
  }
  @Test void replayedAssertionIsRejected() throws Exception {
    String signed=assertion(claims(UUID.randomUUID().toString()));assertEquals(200,exchange(signed).statusCode());HttpResponse<String> replay=exchange(signed);assertEquals(400,replay.statusCode());assertTrue(replay.body().contains("invalid_grant"));
  }
  @Test void assertionTamperingIsRejected() throws Exception {
    String signed=assertion(claims(UUID.randomUUID().toString()));
    String[] parts=signed.split("\\.");byte[] payload=Base64.getUrlDecoder().decode(parts[1]);payload[payload.length/2]^=1;parts[1]=Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
    HttpResponse<String> r=exchange(String.join(".",parts));assertEquals(400,r.statusCode());assertTrue(r.body().contains("invalid_grant"));
  }
  @Test void concurrentRequestsDoNotCrossContaminateClaims() throws Exception {
    String a=assertion(claims("node-a-"+UUID.randomUUID())),b=assertion(claims("node-b-"+UUID.randomUUID()));
    var fa=java.util.concurrent.CompletableFuture.supplyAsync(()->exchangeUnchecked(a));var fb=java.util.concurrent.CompletableFuture.supplyAsync(()->exchangeUnchecked(b));
    JsonNode pa=json.readTree(fa.join().body()),pb=json.readTree(fb.join().body());assertNotEquals(decodePayload(pa.get("access_token").asText()).get("wallet_grant_jti").asText(),decodePayload(pb.get("access_token").asText()).get("wallet_grant_jti").asText());
  }
  private HttpResponse<String> exchangeUnchecked(String assertion) {try{return exchange(assertion);}catch(Exception e){throw new RuntimeException(e);}}
}
