# Keycloak 26.8 wallet-grant bridge prototype

Throwaway prototype for Wayfinder [Prototype Keycloak RFC 7523 wallet-grant extension on pinned release](https://github.com/jetpen/decent-simple-storage/issues/17). It targets Keycloak 26.8.0 and proves a narrow `JWTAuthorizationGrantProvider` / dedicated access-token mapper bridge with request-local `KeycloakSession` state. **Not production-ready.**

## Historical single-node proof

The fixture-only baseline is preserved in the earlier published commit `d1757b0f85aa6b5c77715553543e2596b15148f4`. The current `run-real-token-test.sh` delegates to the in-progress live cluster runner described below. The original command was:

```bash
KC_ASSERTION_PRIVATE_KEY=/path/test.key ./scripts/run-real-token-test.sh
```

The test realm uses an explicit fixture validator in the provider. It accepts only one exact test subject and typed signed `decent_grant` claims; it does **not** perform the real `decent-identity`/Registry lookup. Replace `IdentityRegistryVerifier.testFixture()` with a fail-closed current-state resolver before any non-test use. No Storage callback exists in the prototype.

The runner rebuilds the Java 21 extension, assembles a Keycloak 26.8.0 test image and runs the signed JWT grant against a real Keycloak server. The `RealTokenIsolationIT` uses real Ed25519 assertion signatures, verifies the returned signed token’s claims, no refresh token, invalid-signature rejection, `jti` replay rejection, and concurrent request separation through one Keycloak process. The unit test verifies separate KeycloakSession stores, one-write semantics, and consume/clear behavior. This does **not** establish multi-node cluster replay atomicity or run Keycloak as a multi-node cluster.

The Keycloak SPI is internal/private. Keycloak 26.8.0 build logs warn for both provider factory SPIs. Before production, require live Registry outage/key-rotation tests, atomic replay behavior on a genuine cluster, token behavior with real REST enforcement, and a working next-version compatibility run. No custom client/user attributes carry claims; the only client property is Keycloak's stock allowlist for which IdP may issue JWT grants.


## Live Podman integration (in progress)

The second-stage harness uses Podman containers for the Registry node, a test-only private verifier built from the sibling `decent-identity` and `decent-registry` checkouts, PostgreSQL, and two Keycloak 26.8.0 nodes sharing that database. It provisions a disposable legacy Ed25519 Identity for `mailto:alice@example.org` and removes all stack volumes and scratch private keys when the runner exits. The verifier checks the exact raw identifier, current Registry key/sequence, registered Storage audience, and the wallet JWT signature against the current key before returning the verified grant claims to Keycloak. It fails closed on Registry outage, missing/ambiguous/mismatched identity, key mismatch or invalid wallet signature.

Run the live integration with:

```bash
KC_ASSERTION_PRIVATE_KEY=/path/to/disposable-key.pem ./scripts/run-podman-cluster-test.sh
```

The fixture/verifier prerequisite is now verified; the full Keycloak integration is not. Nine Python tests pass (with one dependency deprecation warning), and clean Podman runs pass writer-independent exact Identity/key/sequence read-back, resolution inside the verifier image, and HTTP 200 with exact verified claims through the running Uvicorn endpoint. See [Registry fixture prerequisite](https://github.com/jetpen/decent-simple-storage/issues/19).

### Preflight only

From this prototype directory, run:

```bash
KC_PREFLIGHT_ONLY=1 KC_ASSERTION_PRIVATE_KEY=/path/to/disposable-key.pem ./scripts/run-podman-cluster-test.sh
```

This exits after testing the actual Registry/verifier topology, before starting PostgreSQL or Keycloak. Safe gate/category and cleanup reports are retained under `$TMPDIR/keycloak-fixture-reports/` (override with `KC_TEST_REPORT_DIR`). Generated keys/imports live in a unique scratch directory and are removed on exit. Setting `REGISTRY_LISTEN_HOST=registry` reproduces the configuration failure and proves the gate stops before Keycloak tests.

For the tight Registry-only reproducer, using the sibling Registry environment:

```bash
/home/ben/projects/decent-registry/.venv/bin/python scripts/check-registry-fixture.py --report "$TMPDIR/registry-fixture.json"
```

Build the Registry and verifier images first with the Dockerfiles in this directory; the preflight runner does this automatically. The local `decent-identity` checkout currently has a pre-existing uncommitted dependency declaration and `uv.lock`; the image explicitly installs both sibling packages, and reports record source revisions/dirty state rather than claiming clean pinned builds.

### Diagnosed integration defects

- `REGISTRY_HOST` is the resolver's **local listen IP**, not the seed's DNS name. `registry` in an `/ip4/` multiaddr raises `StringParseError`; use `0.0.0.0`, and reach the remote Registry using its bootstrap multiaddr.
- The libp2p resolver requires **Trio**, while Uvicorn serves requests on **asyncio**. Direct awaiting raises an `AttributeError` in Trio's runtime. The private verifier now runs a bounded Trio lookup in an AnyIO worker thread, with ephemeral client ports for concurrent requests. Tests demonstrate the old failure and the corrected HTTP positive control.
- A `Value not found` log during genesis publication can describe the pre-write lookup; it did not prove publication failed. Fresh read-back succeeded after the writer exited.

The cluster runner and Java test changes remain an unfinished prototype: no fresh Keycloak signed-token or cluster proof is claimed here. The existing test named `concurrentRequestsAcrossTwoClusterNodesDoNotCrossContaminateClaims` currently makes sequential requests; it must be corrected to genuinely concurrent exchanges in the Keycloak prototype task. Cluster membership, simultaneous replay atomicity, outage/owner-key rotation, resource enforcement, and upgrade compatibility remain unproven. The copied `run-single-node-test.sh` is a historical runner and is not verified against the current live-verifier configuration; use the published earlier commit for the original fixture-only baseline.
