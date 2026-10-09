#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${KC_ASSERTION_PRIVATE_KEY:?Set KC_ASSERTION_PRIVATE_KEY to a test Ed25519 PKCS#8 PEM file path}"
KEY_PATH=$(realpath "$KC_ASSERTION_PRIVATE_KEY")
mkdir -p "$ROOT/.scratch"
rm -f "$ROOT/.scratch/issuer.key" "$ROOT/.scratch/realm.json" "$ROOT/.scratch/wallet-private.der" "$ROOT/.scratch/wallet-public.der"
cleanup(){ podman rm -f decent-kc-it >/dev/null 2>&1 || true; rm -f "$ROOT/.scratch/issuer.key" "$ROOT/.scratch/realm.json" "$ROOT/.scratch/wallet-private.der" "$ROOT/.scratch/wallet-public.der"; }
trap cleanup EXIT
export JAVA_HOME="${JAVA_HOME:-$(mise where java@21.0.2)}";export PATH="$JAVA_HOME/bin:$PATH"
cd "$ROOT"
cp "$KEY_PATH" "$ROOT/.scratch/issuer.key"
cp "$ROOT/container/realm.json" "$ROOT/.scratch/realm.json"
mvn -B -DskipTests package
podman build -f "$ROOT/container/Dockerfile" -t localhost/decent-kc-grant-prototype:26.8.0 "$ROOT"
python3 - "$ROOT/.scratch/issuer.key" "$ROOT/.scratch/realm.json" <<'PY2'
import sys,base64,json,subprocess
p=subprocess.run(['openssl','pkey','-in',sys.argv[1],'-pubout','-outform','DER'],check=True,capture_output=True).stdout
j=json.load(open(sys.argv[2]));j['identityProviders'][0]['config']['publicKeySignatureVerifier']='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(p).decode()+'\n-----END PUBLIC KEY-----';json.dump(j,open(sys.argv[2],'w'))
PY2
podman rm -f decent-kc-it >/dev/null 2>&1 || true
podman run -d --name decent-kc-it -p 18080:8080 -e KC_HEALTH_ENABLED=true -v "$ROOT/.scratch/realm.json:/opt/keycloak/data/import/realm.json:ro" localhost/decent-kc-grant-prototype:26.8.0 start-dev --import-realm >/dev/null
ready=0
for _ in $(seq 1 60); do if curl -fsS http://127.0.0.1:18080/realms/decent/.well-known/openid-configuration >/dev/null 2>&1; then ready=1;break;fi;sleep 2;done
[ "$ready" = 1 ] || { podman logs decent-kc-it; exit 1; }
export KC_ASSERTION_PRIVATE_KEY="$(cat "$ROOT/.scratch/issuer.key")" KC_CLIENT_SECRET=prototype-secret
JAVA_HOME="$JAVA_HOME" PATH="$PATH" mvn -B -DskipTests=false -Dtest=GrantClaimContextTest -Dit.test=RealTokenIsolationIT -DfailIfNoTests=false verify
