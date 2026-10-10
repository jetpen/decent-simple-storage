#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REGISTRY_ROOT=${KC_REGISTRY_ROOT:-/home/ben/projects/decent-registry}
IDENTITY_ROOT=${KC_IDENTITY_ROOT:-/home/ben/projects/decent-identity}
BUILD_CONTEXT=${KC_BUILD_CONTEXT:-/home/ben/projects}
HELPER_PYTHON=${KC_HELPER_PYTHON:-$REGISTRY_ROOT/.venv/bin/python}
STACK=decent-kc-prototype-$$
NETWORK=${STACK}_decent-test
VOL_REG=${STACK}_registry-data
VOL_BOOT=${STACK}_registry-bootstrap
VOL_DB=${STACK}_keycloak-db
REPORT_DIR=${KC_TEST_REPORT_DIR:-${TMPDIR:-/home/ben/.hermes/cache/scratch}/keycloak-fixture-reports/$STACK}
mkdir -p "$REPORT_DIR"
SCRATCH=$(mktemp -d "${TMPDIR:-/home/ben/.hermes/cache/scratch}/$STACK.XXXXXX")
KEY_PATH=${KC_ASSERTION_PRIVATE_KEY:-}
cleanup() {
  local original_status=$? cleanup_failed=0
  trap - EXIT
  # Retain only whitelisted verifier categories, never complete service logs.
  podman logs "$STACK-verifier-1" 2>&1 | python3 -c 'import re,sys;print("\n".join(re.findall(r"(?:Identity verification category=[a-z_]+|Grant schema rejected fields=[a-z_,]+ kinds=[a-z_,]+)",sys.stdin.read())))' > "$REPORT_DIR/verifier-categories.txt" || true
  for container in "$STACK-keycloak1-1" "$STACK-keycloak2-1" "$STACK-verifier-1" "$STACK-bootstrap-init-1" "$STACK-db-1" "$STACK-registry-1"; do
    if podman container exists "$container"; then
      podman rm -f "$container" >/dev/null 2>&1 || cleanup_failed=1
      if podman container exists "$container"; then cleanup_failed=1; fi
    fi
  done
  if podman network exists "$NETWORK"; then podman network rm "$NETWORK" >/dev/null 2>&1 || cleanup_failed=1; fi
  for volume in "$VOL_REG" "$VOL_BOOT" "$VOL_DB"; do
    if podman volume exists "$volume"; then podman volume rm "$volume" >/dev/null 2>&1 || cleanup_failed=1; fi
  done
  if [ -f "$SCRATCH/rotation-report.json" ]; then cp "$SCRATCH/rotation-report.json" "$REPORT_DIR/rotation.json"; fi
  for node in keycloak1 keycloak2; do
    if [ -d "$SCRATCH/tls-$node" ]; then podman unshare chown -R 0:0 "$SCRATCH/tls-$node" || cleanup_failed=1; fi
  done
  for image in "localhost/$STACK-kc:local" "localhost/$STACK-registry:local" "localhost/$STACK-verifier:local"; do
    if podman image exists "$image"; then podman rmi "$image" >/dev/null 2>&1 || cleanup_failed=1; fi
  done
  rm -rf "$SCRATCH" || cleanup_failed=1
  [ ! -e "$SCRATCH" ] || cleanup_failed=1
  printf 'original_exit=%s cleanup_failed=%s\n' "$original_status" "$cleanup_failed" > "$REPORT_DIR/cleanup.txt"
  if [ "$original_status" -ne 0 ]; then exit "$original_status"; fi
  exit "$cleanup_failed"
}
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
JAVA_HOME=${JAVA_HOME:-$(mise where java@21.0.2)}
export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS
MAVEN_VERSION_ARGS=()
if [ -n "${KC_API_VERSION:-}" ]; then MAVEN_VERSION_ARGS=("-Dkeycloak.version=$KC_API_VERSION"); fi
cd "$ROOT"
if [ -n "$KEY_PATH" ]; then cp "$KEY_PATH" "$SCRATCH/issuer.key"; else openssl genpkey -algorithm ED25519 -out "$SCRATCH/issuer.key" >/dev/null 2>&1; fi
cp "$ROOT/container/realm.json" "$SCRATCH/realm.json"
openssl genpkey -algorithm ED25519 -out "$SCRATCH/owner.key" >/dev/null 2>&1
chmod 600 "$SCRATCH/owner.key"
WALLET_PUB=$(openssl pkey -in "$SCRATCH/owner.key" -pubout -outform DER | python3 -c 'import sys;print(sys.stdin.buffer.read()[-32:].hex())')
python3 - "$SCRATCH/issuer.key" "$SCRATCH/realm.json" <<'PY2'
import sys,base64,json,subprocess
pub=subprocess.run(['openssl','pkey','-in',sys.argv[1],'-pubout','-outform','DER'],check=True,capture_output=True).stdout
realm=json.load(open(sys.argv[2]));realm['identityProviders'][0]['config']['publicKeySignatureVerifier']='-----BEGIN PUBLIC KEY-----\\n'+base64.b64encode(pub).decode()+'\\n-----END PUBLIC KEY-----';json.dump(realm,open(sys.argv[2],'w'))
PY2
export KC_WALLET_PUBLIC_KEY_HEX="$WALLET_PUB"
"$HELPER_PYTHON" "$ROOT/scripts/create_verifier_tls.py" "$SCRATCH/tls"
# Workloads receive only their own key/certificate and their peer trust anchor.
for node in keycloak1 keycloak2; do
  mkdir -m 700 "$SCRATCH/tls-$node"
  cp "$SCRATCH/tls/server-ca.crt" "$SCRATCH/tls-$node/ca.crt"
  cp "$SCRATCH/tls/$node.crt" "$SCRATCH/tls-$node/client.crt"
  cp "$SCRATCH/tls/$node.key" "$SCRATCH/tls-$node/client.key"
  podman unshare chown -R 1000:1000 "$SCRATCH/tls-$node"
done
mkdir -m 700 "$SCRATCH/tls-verifier"
cp "$SCRATCH/tls/server.crt" "$SCRATCH/tls-verifier/server.crt"
cp "$SCRATCH/tls/server.key" "$SCRATCH/tls-verifier/server.key"
cp "$SCRATCH/tls/client-ca.crt" "$SCRATCH/tls-verifier/client-ca.crt"
env -u MAVEN_OPTS -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS -u JDK_JAVA_OPTIONS MAVEN_OPTS= mvn -B "${MAVEN_VERSION_ARGS[@]}" -DskipTests package
eval "$(python3 - "$ROOT/build/pinned-inputs.json" <<'PINS'
import json,sys,shlex
for name,reference in json.load(open(sys.argv[1]))['images'].items():
 print('PIN_'+name.upper()+'='+shlex.quote(reference))
PINS
)"
KC_BASE=${KC_KEYCLOAK_BASE:-$PIN_KEYCLOAK}
PY_BASE=${KC_PYTHON_BASE:-$PIN_PYTHON}
POSTGRES_IMAGE=${KC_POSTGRES_BASE:-$PIN_POSTGRES}
ALPINE_IMAGE=${KC_ALPINE_BASE:-$PIN_ALPINE}
podman build --build-arg "KEYCLOAK_BASE=$KC_BASE" -f "$ROOT/container/Dockerfile" -t "localhost/$STACK-kc:local" "$ROOT"
podman build --build-arg "PYTHON_BASE=$PY_BASE" -f "$ROOT/registry/Dockerfile" -t "localhost/$STACK-registry:local" "$BUILD_CONTEXT"
podman build --build-arg "PYTHON_BASE=$PY_BASE" -f "$ROOT/verifier/Dockerfile" -t "localhost/$STACK-verifier:local" "$BUILD_CONTEXT"
KC_IMAGE=$(podman image inspect "localhost/$STACK-kc:local" --format '{{.Id}}')
REGISTRY_IMAGE=$(podman image inspect "localhost/$STACK-registry:local" --format '{{.Id}}')
VERIFIER_IMAGE=$(podman image inspect "localhost/$STACK-verifier:local" --format '{{.Id}}')
export KC_REGISTRY_IMAGE="$REGISTRY_IMAGE" KC_VERIFIER_IMAGE="$VERIFIER_IMAGE"
python3 - "$REPORT_DIR/images.json" "$KC_IMAGE" "$REGISTRY_IMAGE" "$VERIFIER_IMAGE" "$KC_BASE" "$PY_BASE" "$POSTGRES_IMAGE" "$ALPINE_IMAGE" <<'IMAGES'
import sys,json
json.dump(dict(zip(('keycloak','registry','verifier','keycloak_base','python_base','postgres_base','alpine_base'),sys.argv[2:])),open(sys.argv[1],'w'),indent=2)
IMAGES
podman volume create "$VOL_REG" >/dev/null
podman volume create "$VOL_BOOT" >/dev/null
podman volume create "$VOL_DB" >/dev/null
podman network create "$NETWORK" >/dev/null
podman run -d --name "$STACK-registry-1" --network "$NETWORK" --network-alias registry -v "$VOL_REG:/var/lib/decent/registry" -v "$VOL_BOOT:/bootstrap" "$REGISTRY_IMAGE" node --host 0.0.0.0 --port 9000 --datastore-path /var/lib/decent/registry -v >/dev/null
for _ in $(seq 1 90); do
  BOOT=$(podman logs "$STACK-registry-1" 2>&1 | python3 -c 'import re,sys; m=re.search(r"\[BOOTSTRAP\] (\S+)",sys.stdin.read()); print(m.group(1) if m else "")')
  [ -n "$BOOT" ] && break
  sleep 1
done
[ -n "${BOOT:-}" ] || { podman logs "$STACK-registry-1"; exit 1; }
BOOTSTRAP_PEER=${BOOT##*/p2p/}
REGISTRY_IP=$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$STACK-registry-1")
BOOT="/ip4/${REGISTRY_IP}/tcp/9000/p2p/${BOOTSTRAP_PEER}"
printf '%s\n' "$BOOT" > "$SCRATCH/bootstrap.multiaddr"
podman run --rm -v "$SCRATCH:/src:ro" -v "$VOL_BOOT:/dst" "$ALPINE_IMAGE" sh -ec 'cp /src/bootstrap.multiaddr /dst/bootstrap.multiaddr'
mkdir -p "$SCRATCH/registry-cli"
"$HELPER_PYTHON" - "$SCRATCH/registry-cli/registry.yaml" "$BOOT" <<'PY2'
import sys, yaml
cfg = {
  "network": {"host": "0.0.0.0", "port": 9100, "bootstrap": [sys.argv[2]]},
  "datastore": {"path": "/scratch/client-registry.lmdb"},
  "crypto": {"owner_privkey_pem_path": "/scratch/registry-owner.key"},
  "logging": {"verbosity": 0},
}
open(sys.argv[1], "w", encoding="utf-8").write(yaml.safe_dump(cfg))
PY2
OWNER_NAME_HEX=$(python3 -c 'print("mailto:alice@example.org".encode().hex())')
cp "$SCRATCH/owner.key" "$SCRATCH/registry-owner.key"
podman run --rm --network "$NETWORK" -v "$SCRATCH:/scratch" "$REGISTRY_IMAGE" put identity --config /scratch/registry-cli/registry.yaml --owner-name "$OWNER_NAME_HEX" --owner-privkey /scratch/registry-owner.key --seq 1 >/dev/null
# Start the private verifier with the same bootstrap multiaddr.

podman run -d --name "$STACK-verifier-1" --network "$NETWORK" --network-alias verifier -p 127.0.0.1:18082:8000 -v "$SCRATCH/tls-verifier:/tls:ro" -e REGISTRY_HOST="${REGISTRY_LISTEN_HOST:-0.0.0.0}" -e REGISTRY_CLIENT_PORT=0 -e REGISTRY_BOOTSTRAP_FILE=/bootstrap/bootstrap.multiaddr -v "$VOL_BOOT:/bootstrap:ro" -e REGISTRY_QUORUM=1 -e STORAGE_AUDIENCES=https://storage.example.test/instance/alpha,https://storage.example.test/instance/beta "$VERIFIER_IMAGE" >/dev/null
for _ in $(seq 1 60); do curl -fsS --cacert "$SCRATCH/tls/server-ca.crt" --cert "$SCRATCH/tls/preflight.crt" --key "$SCRATCH/tls/preflight.key" https://127.0.0.1:18082/healthz >/dev/null 2>&1 && break; sleep 1; done
"$HELPER_PYTHON" "$ROOT/scripts/check_verifier_tls.py" --url https://127.0.0.1:18082 --tls-dir "$SCRATCH/tls" --report "$REPORT_DIR/transport.json"
# Gate the actual topology, not an unrelated fixture, before Keycloak starts.
"$HELPER_PYTHON" "$ROOT/scripts/verify-live-fixture.py" --network "$NETWORK" --bootstrap "$BOOT" --key "$SCRATCH/owner.key" --verifier-url https://127.0.0.1:18082 --tls-dir "$SCRATCH/tls" --report "$REPORT_DIR/preflight.json"
if [ "${KC_PREFLIGHT_ONLY:-0}" = 1 ]; then exit 0; fi
podman run -d --name "$STACK-db-1" --network "$NETWORK" --network-alias db -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=prototype-only -v "$VOL_DB:/var/lib/postgresql/data" "$POSTGRES_IMAGE" >/dev/null
for _ in $(seq 1 60); do podman exec "$STACK-db-1" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 1; done
podman exec "$STACK-db-1" pg_isready -U keycloak -d keycloak >/dev/null
# Write the actual known throwaway public key and registered audience/verifier configuration into import realm.
python3 - "$SCRATCH/realm.json" "$SCRATCH/owner.key" "$WALLET_PUB" <<'PY2'
import sys,json,subprocess,base64
p=sys.argv[1]; d=json.load(open(p)); pub=subprocess.run(['openssl','pkey','-in',sys.argv[2],'-pubout','-outform','DER'],check=True,capture_output=True).stdout
d['identityProviders'][0]['config'].update({'publicKeySignatureVerifier':'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(pub).decode()+'\n-----END PUBLIC KEY-----','verifierUrl':'https://verifier:8000','jwtGrantAudiences':'http://127.0.0.1:18080/realms/decent,http://127.0.0.1:18081/realms/decent,http://keycloak1:8080/realms/decent,http://keycloak2:8080/realms/decent','storageAudiences':'https://storage.example.test/instance/alpha,https://storage.example.test/instance/beta'});json.dump(d,open(p,'w'))
PY2
podman run -d --name "$STACK-keycloak1-1" --network "$NETWORK" --network-alias keycloak1 -p 18080:8080 -v "$SCRATCH/tls-keycloak1:/verifier-tls:ro" -e VERIFIER_TLS_CA=/verifier-tls/ca.crt -e VERIFIER_TLS_CLIENT_CERT=/verifier-tls/client.crt -e VERIFIER_TLS_CLIENT_KEY=/verifier-tls/client.key -e KC_DB=postgres -e KC_DB_URL=jdbc:postgresql://db:5432/keycloak -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=prototype-only -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true -e KC_CACHE=ispn -e KC_CACHE_STACK=jdbc-ping -e KC_CACHE_EMBEDDED_MTLS_ENABLED=false -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false -v "$SCRATCH/realm.json:/opt/keycloak/data/import/realm.json:ro" "$KC_IMAGE" start --cache=ispn --cache-stack=jdbc-ping --cache-embedded-mtls-enabled=false --http-enabled=true --hostname-strict=false --import-realm >/dev/null
for _ in $(seq 1 120); do curl -fsS http://127.0.0.1:18080/realms/decent/.well-known/openid-configuration >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:18080/realms/decent/.well-known/openid-configuration >/dev/null
podman run -d --name "$STACK-keycloak2-1" --network "$NETWORK" --network-alias keycloak2 -p 18081:8080 -v "$SCRATCH/tls-keycloak2:/verifier-tls:ro" -e VERIFIER_TLS_CA=/verifier-tls/ca.crt -e VERIFIER_TLS_CLIENT_CERT=/verifier-tls/client.crt -e VERIFIER_TLS_CLIENT_KEY=/verifier-tls/client.key -e KC_DB=postgres -e KC_DB_URL=jdbc:postgresql://db:5432/keycloak -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=prototype-only -e KC_HEALTH_ENABLED=true -e KC_CACHE=ispn -e KC_CACHE_STACK=jdbc-ping -e KC_CACHE_EMBEDDED_MTLS_ENABLED=false -e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false "$KC_IMAGE" start --cache=ispn --cache-stack=jdbc-ping --cache-embedded-mtls-enabled=false --http-enabled=true --hostname-strict=false >/dev/null
for _ in $(seq 1 120); do curl -fsS http://127.0.0.1:18081/realms/decent/.well-known/openid-configuration >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:18081/realms/decent/.well-known/openid-configuration >/dev/null
python3 "$ROOT/scripts/check-keycloak-cluster.py" --node "$STACK-keycloak1-1" --node "$STACK-keycloak2-1" --report "$REPORT_DIR/cluster.json"
# Only the test JVM needs the disposable signing key; never print it.
export KC_ASSERTION_PRIVATE_KEY="$(<"$SCRATCH/owner.key")"
export KC_REGISTRY_CONTAINER="$STACK-registry-1"
export KC_TEST_TLS_DIR="$SCRATCH/tls"
export KC_TEST_SCRATCH="$SCRATCH" KC_TEST_NETWORK="$NETWORK" KC_TEST_BOOTSTRAP="$BOOT"
export KC_URL=http://127.0.0.1:18080 KC_URL_2=http://127.0.0.1:18081 VERIFIER_URL=http://verifier:8000 KC_CLIENT_SECRET=prototype-secret KC_WALLET_PUBLIC_KEY_HEX="$WALLET_PUB"
env -u MAVEN_OPTS -u JAVA_TOOL_OPTIONS -u _JAVA_OPTIONS -u JDK_JAVA_OPTIONS MAVEN_OPTS= JAVA_HOME="$JAVA_HOME" PATH="$PATH" mvn -B "${MAVEN_VERSION_ARGS[@]}" -Dtest=GrantClaimContextTest,VerifierTransportTest -Dit.test=RealTokenIsolationIT -DfailIfNoTests=false verify
