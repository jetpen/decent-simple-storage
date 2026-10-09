# Keycloak 26.8 wallet-grant bridge prototype

Throwaway prototype for Wayfinder [Prototype Keycloak RFC 7523 wallet-grant extension on pinned release](https://github.com/jetpen/decent-simple-storage/issues/17). It targets Keycloak 26.8.0 and proves a narrow `JWTAuthorizationGrantProvider` / dedicated access-token mapper bridge with request-local `KeycloakSession` state. **Not production-ready.**

## Run

Requires Java 21, Maven, OpenSSL and Podman. Make a throwaway Ed25519 key (`openssl genpkey -algorithm Ed25519 -out /path/test.key`) and run:

```bash
KC_ASSERTION_PRIVATE_KEY=/path/test.key ./scripts/run-real-token-test.sh
```

The test realm uses an explicit fixture validator in the provider. It accepts only one exact test subject and typed signed `decent_grant` claims; it does **not** perform the real `decent-identity`/Registry lookup. Replace `IdentityRegistryVerifier.testFixture()` with a fail-closed current-state resolver before any non-test use. No Storage callback exists in the prototype.

The runner rebuilds the Java 21 extension, assembles a Keycloak 26.8.0 test image and runs the signed JWT grant against a real Keycloak server. The `RealTokenIsolationIT` uses real Ed25519 assertion signatures, verifies the returned signed token’s claims, no refresh token, invalid-signature rejection, `jti` replay rejection, and concurrent request separation through one Keycloak process. The unit test verifies separate KeycloakSession stores, one-write semantics, and consume/clear behavior. This does **not** establish multi-node cluster replay atomicity or run Keycloak as a multi-node cluster.

The Keycloak SPI is internal/private. Keycloak 26.8.0 build logs warn for both provider factory SPIs. Before production, require live Registry outage/key-rotation tests, atomic replay behavior on a genuine cluster, token behavior with real REST enforcement, and a working next-version compatibility run. No custom client/user attributes carry claims; the only client property is Keycloak's stock allowlist for which IdP may issue JWT grants.
