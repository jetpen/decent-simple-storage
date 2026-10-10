package dev.decent.keycloak.grant;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.List;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.representations.AccessToken;

/** Dedicated mapper: reads only immutable claims held in this token-request's KeycloakSession. */
public final class VerifiedGrantProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
  public static final String PROVIDER_ID = "decent-verified-grant";
  @Override public String getId() { return PROVIDER_ID; }
  @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
  @Override public String getDisplayType() { return "Decent verified grant"; }
  @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
  @Override public String getHelpText() { return "Copies only server-verified per-grant claims into this access token."; }
  @Override public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel model, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
    var verified = GrantClaimContext.get(session);
    if (verified.isEmpty()) return token; // normal OIDC flows get no grant claims
    var g = verified.get();
    token.setSubject(g.ownerIdentifier());
    token.exp(Math.min(token.getExp(), g.consentExpiresAt()));
    token.setOtherClaims("storage_aud", g.storageAudience());
    token.setOtherClaims("owner_identifier", g.ownerIdentifier());
    token.setOtherClaims("owner_key_fingerprint", g.ownerKeyFingerprint());
    token.setOtherClaims("identity_registry_seq", g.registrySequence());
    token.setOtherClaims("storage_object_digest", g.objectDigest());
    token.setOtherClaims("storage_actions", g.actions());
    token.setOtherClaims("storage_purpose", g.purpose());
    token.setOtherClaims("wallet_grant_jti", g.grantId());
    token.setOtherClaims("wallet_consent_exp", g.consentExpiresAt());
    return token;
  }
}
