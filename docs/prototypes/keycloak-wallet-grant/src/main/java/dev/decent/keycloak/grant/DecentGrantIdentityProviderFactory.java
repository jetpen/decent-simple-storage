package dev.decent.keycloak.grant;

import java.util.List;
import java.util.Map;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProviderConfig;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.Urls;

/** Pinned 26.8 prototype IdP. Registry implementation is deliberately injected in the harness. */
public final class DecentGrantIdentityProviderFactory extends AbstractIdentityProviderFactory<DecentGrantIdentityProvider> {
  public static final String PROVIDER_ID = "decent-wallet-grant";
  @Override public String getId() { return PROVIDER_ID; }
  @Override public String getName() { return "Decent Wallet Grant (prototype)"; }
  @Override public DecentGrantIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    var config = new JWTAuthorizationGrantIdentityProviderConfig(model);
    config.setJWTAuthorizationGrantEnabled(true);
    config.getConfig().putIfAbsent(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ASSERTION_REUSE_ALLOWED, "false");
    config.getConfig().putIfAbsent(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_MAX_ALLOWED_ASSERTION_EXPIRATION, "60");
    config.getConfig().putIfAbsent(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ASSERTION_SIGNATURE_ALG, "EdDSA");
    config.getConfig().putIfAbsent(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ALLOWED_CLOCK_SKEW, "0");
    config.getConfig().putIfAbsent(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_LIMIT_ACCESS_TOKEN_EXP, "true");
    return new DecentGrantIdentityProvider(session, config, List.of(
      Urls.realmIssuer(session.getContext().getUri().getBaseUri(), session.getContext().getRealm().getName()),
      Urls.tokenEndpoint(session.getContext().getUri().getBaseUri(), session.getContext().getRealm().getName()).toString()));
  }
  @Override public IdentityProviderModel createConfig() { return new JWTAuthorizationGrantIdentityProviderConfig(); }
  @Override public Map<String,String> parseConfig(KeycloakSession session, String config) { throw new UnsupportedOperationException("use Admin configuration model"); }
  @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
