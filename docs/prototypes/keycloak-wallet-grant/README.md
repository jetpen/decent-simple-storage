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

The fixture/verifier prerequisite and the live two-node slice below are verified; the full issue acceptance criteria are not. Nine Python tests pass (with one dependency deprecation warning), and clean Podman runs pass writer-independent exact Identity/key/sequence read-back, resolution inside the verifier image, and HTTP 200 with exact verified claims through the running Uvicorn endpoint. See [Registry fixture prerequisite](https://github.com/jetpen/decent-simple-storage/issues/19).

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

The local `decent-identity` checkout still has a pre-existing uncommitted dependency declaration and `uv.lock`, left untouched. The pinned acceptance entry point below exports its exact committed revision instead; a passing clean run proves that dirty metadata is not required. Direct worktree runs are development-only. The old `check-registry-fixture.py` standalone command requires prebuilt legacy local tags; the pinned acceptance entry point and its integrated preflight use immutable image IDs and are the current verification path.

### Diagnosed integration defects

- `REGISTRY_HOST` is the resolver's **local listen IP**, not the seed's DNS name. `registry` in an `/ip4/` multiaddr raises `StringParseError`; use `0.0.0.0`, and reach the remote Registry using its bootstrap multiaddr.
- The libp2p resolver requires **Trio**, while Uvicorn serves requests on **asyncio**. Direct awaiting raises an `AttributeError` in Trio's runtime. The private verifier now runs a bounded Trio lookup in an AnyIO worker thread, with ephemeral client ports for concurrent requests. Tests demonstrate the old failure and the corrected HTTP positive control.
- A `Value not found` log during genesis publication can describe the pre-write lookup; it did not prove publication failed. Fresh read-back succeeded after the writer exited.

### Live two-node result

The latest run passes three unit tests (context isolation and verifier transport policy) and thirteen real integration tests with zero failures/errors/skips. Both nodes report the same two-member Infinispan cluster view. A `BeforeAll` positive control verifies real Registry-backed issuance and exact claims on each node before negative tests run. Eight barrier-synchronized distinct-grant rounds verify token signatures and exact object/actions/purpose/audience/jti/consent fields without cross-contamination. Twelve identical-assertion races across both nodes each issue exactly one token and reject the other request. A paused Registry fails closed with no token; after unpause a fresh grant succeeds. Key mismatch, unregistered audience, tampering and sequential cross-node replay are rejected. No refresh token is issued. See `evidence/keycloak-live-cluster.json`.

Two additional defects were exposed and fixed: Java HttpClient attempted an h2c upgrade that caused the Uvicorn endpoint to see a missing body; the private verifier client now explicitly uses HTTP/1.1. The initial token expiration was capped by assertion expiry but could outlive the shorter wallet consent; the mapper now caps token `exp` at verified consent expiry, and real-token tests fail without that change.

### Owner-key rotation and resource boundary

`rotate-live-identity.py` performs a legitimate predecessor-authorized transition from the fixture's legacy sequence 1 to version-1 sequence 2. The old key signs the canonical successor update hash; the successor installs a complete 2-of-3 Registry signer set. Exact direct remote read-back precedes fresh Identity resolution, which validates retained Registry history. The test then rejects the old-key grant and issues successor-key grants on both Keycloak nodes with the new fingerprint and sequence 2. A successor-self-signed installation is rejected by the real local transition validator. This proves one peer's accepted lineage, not globally latest state or threshold-signed wallet grants. Generated successor/cosigner private keys are scratch-only and removed by runner cleanup.

**Signature ownership correction:** Keycloak core checks the declared algorithm, token time/audience, replay and federated user link; cryptographic signature verification in the stock grant is performed by its IdP implementation. Our custom IdP does not inherit that implementation. The private verifier performs the actual wallet JWT signature validation against the current Registry owner key. A signature-only mutation test rejects with a working positive control. The imported `publicKeySignatureVerifier` setting is not the wallet authorization authority in this custom path; rotation succeeds without changing it. The current prototype authenticates this AS-to-verifier boundary with mutual TLS as described below; production credential issuance/rotation/revocation and deployment policy remain required.

The mapper now also sets standard JWT `aud` from verified Storage audience (not merely the custom `storage_aud` claim). Real-token tests reproduced the missing standard audience before the fix. A throwaway loopback HTTP resource-server test verifies the actual issued signature/issuer/audience/expiry/scope and then checks in-memory current entitlement, object, quota and revocation policy on seven protected requests. Policy changes deny the same token, required-state unavailability returns 503, and recovery does not revive revoked consent. A request counter stays zero during token issuance. This is an executable boundary demonstration, **not an implemented Storage service, quota ledger, object persistence or complete enrollment/revocation state machine**.

### Authenticated AS-to-verifier transport

The runner generates a disposable one-day PKI with separate server and client trust anchors. The verifier receives only its server key/certificate and dedicated client CA; each Keycloak node receives only its own client key/certificate and server CA. CA private keys never persist. Read-only mounts and private permissions protect the files; rootless Podman ownership is restored before cleanup. Keys/certificates are generated under the approved unique scratch directory and removed on both success and failure.

The Java verifier requires an HTTPS origin with no URL credentials/query/fragment/path; it disables redirects, loads dedicated trust/client files, and retains the JVM's hostname checks. File paths come from operator workload environment (`VERIFIER_TLS_CA`, `VERIFIER_TLS_CLIENT_CERT`, `VERIFIER_TLS_CLIENT_KEY`), never a user/client grant attribute. The Uvicorn image defaults to a TLS-only startup script requiring client certificates and refuses startup without TLS files. The host preflight port is loopback-bound. No trust-all or plaintext fallback exists.

Live preflight proves missing client certificate, rogue-CA client, wrong server trust anchor, wrong hostname and plaintext HTTP are rejected, while an authorized client succeeds. A Java integration test exercises the same absent/rogue/untrusted credential failures through real handshakes and a valid-client HTTP response; the complete live grant/rotation/race suite then succeeds through each node's authenticated Java verifier path. `evidence/verifier-transport-red-green.json` preserves the insecure pre-change controls and fresh corrected results. The first TLS attempt exposed strict X.509 authority/subject-key-identifier requirements and rootless mount cleanup ownership; those were corrected and the failed-run scratch was removed.

This authenticates possession of a certificate issued by the dedicated client CA, not arbitrary CN-based workload authorization. Production CA issuance/rotation/revocation, least-privilege workload policies, certificate reload, end-to-end external TLS, and trust-boundary review remain outstanding. Other local test links (token endpoints/DB/Registry) retain their isolated test configuration. The Compose file is a parsing-checked topology sketch requiring `KC_TLS_ROOT`; the direct Podman runner is the executed acceptance path.

### Clean revision-pinned acceptance

From this directory:

```bash
python3 scripts/pinned_acceptance.py --source-revision FULL_40_HEX_STORAGE_COMMIT --report-dir "$TMPDIR/kc-pinned-report"
```

Requires Git, uv, Podman, OpenSSL, Java 21/Maven and the named local repositories with the selected commits available. The command rejects moving refs, exports committed Git archives into a private temporary sibling layout, installs an isolated Python 3.12 environment from a hash-locked dependency list, and builds source packages with `--no-deps --no-build-isolation`. Clean Identity metadata has no declared runtime dependencies; the prototype lock explicitly supplies those dependencies without editing that repo.

`build/pinned-inputs.json` pins Registry/Identity commits and base Keycloak/Python/PostgreSQL/Alpine OCI digests. Each run creates unique derived-image tags, records immutable image IDs, and passes those IDs to every runtime client/container, including the rotation helper. Generated derived tags, containers, volumes, keys and scratch sources are removed at exit. The receipt records the code actually executed, dependency-lock hash, immutable images, exact mandatory case identities and cleanup outcome. Uncommitted checkout modifications and ambient test/service filters are not execution inputs.

The reviewed `build/mandatory-tests.json` inventory currently contains 41 required cases (25 Python tests, 3 Java unit tests, 13 real integration tests). Native counter mismatches, skipped/failed/error cases, duplicate identities, hidden failure-plus-skip and equal-count identity substitutions cannot produce a passing receipt. The contract tests also prove Git exports omit dirty and untracked inputs. To exercise a real failed live gate and teardown, add `--force-preflight-failure`; it must return nonzero and a failed receipt, never a passing result.

The recorded clean acceptance run executed storage revision `ff34baee6038a2f8f337f776075eebcde0e6a2fd` and passed all 33 exact mandatory cases with zero skips/failures/errors, despite deliberately supplied ambient test/image filters and the dirty Identity checkout. The forced-preflight-failure run returned exit 1, retained a failed receipt, preserved the original failure and reported successful cleanup. Both isolated workspaces were removed. See `evidence/pinned-acceptance.json`; later evidence-only commits do not change which code revision that receipt proves.

This pins source content, third-party Python distribution hashes and runtime image identities. It is **not bit-identical, hermetic or offline build reproducibility**: Debian apt metadata/compiler packages, Maven transitive artifacts, host Java/Maven and available package registries are external. The direct development runner can use local overrides; the pinned acceptance wrapper clears those inputs and enforces its policy. Compose remains an unexecuted sketch and is not this reproducibility proof.

### Next-release upgrade gate

Primary-source preflight is executable:

```bash
python3 scripts/probe_keycloak_upgrade.py --report "$TMPDIR/keycloak-upgrade-availability.json"
```

Exit 2 means **blocked/not tested**, never compatible. The latest recorded check found GitHub's latest released version and Maven Central's newest API version both `26.8.0`, no newer numeric Maven release, and `quay.io/keycloak/keycloak:26.8.1` unavailable (`manifest unknown`, exit 125). It does not guess a nightly build as a released successor. See `evidence/upgrade-gate.json`.

When a newer matching release/API exists, resolve the official container to its immutable digest, review that release's migration notes and the private SPI changes, then run:

```bash
python3 scripts/pinned_acceptance.py \
  --source-revision FULL_40_HEX_STORAGE_COMMIT \
  --candidate-version RELEASED_VERSION \
  --candidate-image quay.io/keycloak/keycloak@sha256:FULL_64_HEX_DIGEST \
  --report-dir "$TMPDIR/keycloak-upgrade-report"
```

The candidate path requires paired numeric-version/digest inputs, pulls the immutable candidate, verifies `kc.sh --version` matches, compiles the provider **and tests** against that API (`-Dkeycloak.version`), and exercises the complete unchanged mandatory inventory against that candidate runtime with mTLS/live Registry/two nodes. The baseline lock remains unchanged; candidate intent, exact digest and source revision are recorded. A runtime-version mismatch fails before live acceptance. No baseline rerun, missing case or skip may be presented as a forward upgrade.

The executable candidate path was smoke-tested on `26.8.0`: all 41 mandatory cases passed, and the receipt explicitly marks `forward_upgrade=false`, fresh-start conformance `passed`, and forward-release fresh-start `not-tested`. Labelling that same digest as `26.8.1` failed with no mandatory-pass receipt. These controls most recently executed revision `18d98b3dfb09fc84f68e3c028754f75d61d62942` and removed their isolated workspaces. A genuine successor run remains blocked.

Receipt `compatibility_scope` explicitly marks persisted-state migration, mixed-version rolling, backup/rollback restoration and optimized startup `not-tested`; it no longer emits the overbroad `upgrade_compatibility=forward-tested` label for a fresh install. Regression tests cover baseline, hypothetical newer-version success and failed-candidate claim boundaries.

This gate proves extension compile/fresh-start/runtime behavior only. It does **not** establish in-place production database migration, persisted realm/session upgrade, mixed-version/rolling-cluster safety or rollback. Follow the [official upgrade guide](https://www.keycloak.org/docs/latest/upgrading/index.html): review migration changes first, rebuild custom providers before server build, and test backed-up/restored disposable state separately before production upgrade.

This remains a limited prototype, not a global replay or production guarantee. A `podman manifest inspect quay.io/keycloak/keycloak:26.8.1` compatibility preflight returned `manifest unknown` (exit 125); no next-release runtime compatibility is claimed. Full hermetic/bit-identical reproducibility, production workload certificate lifecycle/authorization, complete provider policy implementation and broader failure/partition coverage remain outstanding. The copied `run-single-node-test.sh` is a historical runner and is not verified against the current live-verifier configuration; use the published earlier commit for the original fixture-only baseline.
