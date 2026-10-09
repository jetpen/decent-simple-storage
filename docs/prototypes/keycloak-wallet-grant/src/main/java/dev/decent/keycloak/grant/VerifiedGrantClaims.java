package dev.decent.keycloak.grant;

import java.util.List;

/** Immutable, validated wallet grant values safe to publish into one issued access token. */
public record VerifiedGrantClaims(
    String storageAudience,
    String ownerIdentifier,
    String ownerKeyFingerprint,
    long registrySequence,
    String objectDigest,
    List<String> actions,
    String purpose,
    String grantId,
    long consentExpiresAt
) {
  public VerifiedGrantClaims {
    if (storageAudience == null || storageAudience.isBlank()) throw new IllegalArgumentException("storage audience required");
    if (ownerIdentifier == null || ownerIdentifier.isBlank()) throw new IllegalArgumentException("exact owner identifier required");
    if (ownerKeyFingerprint == null || ownerKeyFingerprint.isBlank()) throw new IllegalArgumentException("owner key binding required");
    if (registrySequence < 0) throw new IllegalArgumentException("registry sequence must be non-negative");
    if (objectDigest == null || objectDigest.isBlank()) throw new IllegalArgumentException("object digest required");
    if (actions == null || actions.isEmpty() || actions.stream().anyMatch(a -> a == null || a.isBlank())) throw new IllegalArgumentException("actions required");
    if (purpose == null || purpose.isBlank()) throw new IllegalArgumentException("purpose required");
    if (grantId == null || grantId.isBlank()) throw new IllegalArgumentException("grant jti required");
    if (consentExpiresAt <= 0) throw new IllegalArgumentException("consent expiry required");
    actions = List.copyOf(actions);
    if (!ownerIdentifier.matches("mailto:[^\\s]+|tel:\\+?[0-9]+")) throw new IllegalArgumentException("owner identifier must preserve exact mailto:/tel: URI text");
    if (!objectDigest.matches("sha256:[0-9a-f]{64}")) throw new IllegalArgumentException("object digest must be sha256 hex");
    if (grantId.length() > 256) throw new IllegalArgumentException("grant jti too long");
    if (actions.stream().distinct().count() != actions.size()) throw new IllegalArgumentException("duplicate action");
  }
}
