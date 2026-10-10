package dev.decent.keycloak.grant;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Set;
import org.junit.jupiter.api.Test;

class VerifierTransportTest {
  @Test void plaintextVerifierIsRejectedBeforeAnyGrantCanBeSent() {
    assertThrows(IllegalArgumentException.class,
      () -> IdentityRegistryVerifier.remote("http://verifier:8000", Set.of("storage-a")),
      "a private network is not authenticated transport");
  }
  @Test void urlCredentialsAndQueryAreRejected() {
    assertThrows(IllegalArgumentException.class,
      () -> IdentityRegistryVerifier.remote("https://user:password@verifier:8000?token=x", Set.of("storage-a")));
  }
}
