package dev.decent.keycloak.grant;

import java.util.Map;
import java.util.List;
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
  private static String required(Map<?,?> claims,String name) throws IdentityBrokerException { Object v=claims.get(name); if (!(v instanceof String s)||s.isBlank()) throw new IdentityBrokerException("missing/invalid "+name); return s; }
}
