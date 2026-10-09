package dev.decent.keycloak.grant;

import java.util.Optional;
import org.keycloak.models.KeycloakSession;

/** Request/session-scoped bridge. Never persist claims in user, client, realm, or shared factory attributes. */
public final class GrantClaimContext {
  private static final String KEY = GrantClaimContext.class.getName() + ".verified";
  private GrantClaimContext() {}

  public static void put(KeycloakSession session, VerifiedGrantClaims claims) {
    if (session.getAttribute(KEY) != null) throw new IllegalStateException("verified grant context already set");
    session.setAttribute(KEY, claims);
  }

  public static Optional<VerifiedGrantClaims> get(KeycloakSession session) {
    return Optional.ofNullable(session.getAttribute(KEY, VerifiedGrantClaims.class));
  }

  public static Optional<VerifiedGrantClaims> take(KeycloakSession session) {
    return Optional.ofNullable((VerifiedGrantClaims) session.removeAttribute(KEY));
  }

  public static void clear(KeycloakSession session) { session.removeAttribute(KEY); }
}
