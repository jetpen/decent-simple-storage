package dev.decent.keycloak.grant;

import java.util.List;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.JWTAuthorizationGrantProvider;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.JWTAuthorizationGrantValidationContext;

/** Narrow RFC 7523 IdP extension. Verifies with configured issuer keys, then applies wallet grant policy. */
public final class DecentGrantIdentityProvider implements JWTAuthorizationGrantProvider<IdentityProviderModel> {
  private final KeycloakSession session;
  private final IdentityProviderModel config;
  private final List<String> acceptedAudiences;
  private final IdentityRegistryVerifier verifier;
  public DecentGrantIdentityProvider(KeycloakSession session, IdentityProviderModel config, List<String> acceptedAudiences, IdentityRegistryVerifier verifier) {
    this.session=session; this.config=config; this.acceptedAudiences=List.copyOf(acceptedAudiences); this.verifier=verifier;
  }
  private JWTAuthorizationGrantConfig grantConfig() {
    if (!(config instanceof JWTAuthorizationGrantConfig gc)) throw new IdentityBrokerException("provider configuration lacks Keycloak JWT grant settings");
    return gc;
  }
  @Override public boolean isType(KeycloakSession ignored, IdentityProviderType type) {
    return type == IdentityProviderType.JWT_AUTHORIZATION_GRANT && grantConfig().isJWTAuthorizationGrantEnabled();
  }
  @Override public BrokeredIdentityContext validateAuthorizationGrantAssertion(JWTAuthorizationGrantValidationContext assertion) throws IdentityBrokerException {
    GrantClaimContext.clear(session);
    VerifiedGrantClaims claims = verifier.verify(assertion);
    if (!claims.ownerIdentifier().equals(assertion.getSubject())) throw new IdentityBrokerException("assertion subject mismatch");
    if (claims.consentExpiresAt() > assertion.getJWT().getExp()) throw new IdentityBrokerException("grant consent outlives signed assertion");
    BrokeredIdentityContext brokered = new BrokeredIdentityContext(claims.ownerIdentifier(), config);
    GrantClaimContext.put(session, claims);
    brokered.setUsername(claims.ownerIdentifier());
    return brokered;
  }
  @Override public int getAllowedClockSkew() { return grantConfig().getJWTAuthorizationGrantAllowedClockSkew(); }
  @Override public boolean isAssertionReuseAllowed() { return false; }
  @Override public List<String> getAllowedAudienceForJWTGrant() { return acceptedAudiences; }
  @Override public int getMaxAllowedExpiration() { return grantConfig().getJWTAuthorizationGrantMaxAllowedAssertionExpiration(); }
  @Override public String getAssertionSignatureAlg() { return "EdDSA"; }
  @Override public boolean isLimitAccessTokenExpiration() { return true; }
  @Override public IdentityProviderModel getConfig() { return config; }
  @Override public boolean isMapperSupported(org.keycloak.broker.provider.IdentityProviderMapper mapper) { return false; }
  @Override public boolean reloadKeys() { return false; }
  @Override public void close() {}
}
