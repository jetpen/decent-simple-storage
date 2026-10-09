package dev.decent.keycloak.grant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;

class GrantClaimContextTest {
  private KeycloakSession session(Map<String,Object> attributes) {
    KeycloakSession s=mock(KeycloakSession.class);
    when(s.getAttribute(anyString())).thenAnswer(i->attributes.get(i.getArgument(0)));
    when(s.getAttribute(anyString(),eq(VerifiedGrantClaims.class))).thenAnswer(i->attributes.get(i.getArgument(0)));
    doAnswer(i->{attributes.put(i.getArgument(0),i.getArgument(1));return null;}).when(s).setAttribute(anyString(),any());
    when(s.removeAttribute(anyString())).thenAnswer(i->attributes.remove(i.getArgument(0)));
    return s;
  }
  @Test void validatedClaimsAreIsolatedAndConsumedPerKeycloakSession() {
    KeycloakSession a=session(new HashMap<>()), b=session(new HashMap<>());
    VerifiedGrantClaims claims=new VerifiedGrantClaims("storage-1","mailto:alice@example.org","fp-1",4,"sha256:"+"a".repeat(64),java.util.List.of("read"),"profile-read","jti-1",2000000000L);
    GrantClaimContext.put(a,claims);
    assertEquals(claims,GrantClaimContext.get(a).orElseThrow());
    assertTrue(GrantClaimContext.get(b).isEmpty());
    assertThrows(IllegalStateException.class,()->GrantClaimContext.put(a,claims));
    assertEquals(claims,GrantClaimContext.take(a).orElseThrow());
    assertTrue(GrantClaimContext.get(a).isEmpty());
  }
}
