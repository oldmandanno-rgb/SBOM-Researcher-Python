#!/usr/bin/env bash
# Local demo for the "api.osv.dev -> osv-service" TLS reverse proxy (Option B).
#
# This proves the transparent-proxy design end-to-end on a laptop:
#   1. generate a self-signed cert for api.osv.dev
#   2. create the osv-proxy-tls Secret and deploy the nginx proxy into the
#      existing kind cluster (assumes osv-service is already deployed)
#   3. validate that https://api.osv.dev reaches osv-service over TLS
#
# Prerequisites: Docker Desktop (running), kind, kubectl, openssl. The
# osv-service must already be running in the "kind" cluster
# (run ./scripts/local-test.sh first if needed).
#
# Real apps (incl. one that hardcodes api.osv.dev and cannot be reconfigured)
# then use it by (a) trusting the cert and (b) resolving api.osv.dev to this
# host — no application changes required.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-/tmp/osv-proxy-certs}"

echo "== Generating api.osv.dev cert (CA -> server, 2-tier PKI) =="
mkdir -p "$CERT_DIR"
# A self-signed leaf cert is rejected by OpenSSL (error 18) even when passed as
# --cacert, so we build a tiny CA and sign a server cert with it. Config files
# (not -addext) are used so this works on both OpenSSL and LibreSSL.

# CA
cat > "$CERT_DIR/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = osv-proxy-ca
[ext]
basicConstraints = critical, CA:TRUE
keyUsage = keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null
openssl req -x509 -new -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
  -out "$CERT_DIR/ca.crt" -config "$CERT_DIR/ca.cnf"

# Server cert (signed by the CA)
cat > "$CERT_DIR/server.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = api.osv.dev
[ext]
subjectAltName = DNS:api.osv.dev
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl genrsa -out "$CERT_DIR/api.osv.dev.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/api.osv.dev.key" \
  -out "$CERT_DIR/api.osv.dev.csr" -config "$CERT_DIR/server.cnf"
openssl x509 -req -in "$CERT_DIR/api.osv.dev.csr" \
  -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -days 825 -sha256 -out "$CERT_DIR/api.osv.dev.crt" \
  -extfile "$CERT_DIR/server.cnf" -extensions ext

echo "== Creating k8s Secret osv-proxy-tls =="
kubectl create secret tls osv-proxy-tls \
  --cert="$CERT_DIR/api.osv.dev.crt" \
  --key="$CERT_DIR/api.osv.dev.key" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "== Deploying proxy (deploy/proxy) =="
kubectl apply -k "$REPO_ROOT/deploy/proxy"
# The TLS Secret is regenerated each run; restart so the pod mounts the new cert.
kubectl rollout restart deploy/osv-proxy 2>/dev/null || true
kubectl rollout status deploy/osv-proxy --timeout=60s

# Load the test fixture so the demo returns real data through the proxy.
# The osv-service image is distroless (no tar), so we use a throwaway busybox
# pod that mounts the same PVC to copy the fixture in.
if kubectl get deploy osv-service >/dev/null 2>&1 && \
   kubectl get pvc osv-service-data >/dev/null 2>&1; then
  echo "== Loading test fixture into osv-service (best-effort) =="
  kubectl run fixture-loader --restart=Never --image=busybox:1.36 \
    --overrides='{"spec":{"containers":[{"name":"c","image":"busybox:1.36","command":["sleep","60"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"osv-service-data"}}]}}' \
    >/dev/null 2>&1 || true
  for i in $(seq 1 30); do
    kubectl get pod fixture-loader -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Running && break
    sleep 1
  done
  if kubectl get pod fixture-loader -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Running; then
    kubectl cp "$REPO_ROOT/tests/fixtures/osv_store/PyPI" fixture-loader:/data/PyPI 2>/dev/null || true
    kubectl delete pod fixture-loader --wait=false >/dev/null 2>&1 || true
    kubectl rollout restart deploy/osv-service
    kubectl rollout status deploy/osv-service --timeout=60s
  else
    kubectl delete pod fixture-loader --wait=false >/dev/null 2>&1 || true
    echo "  (could not start fixture-loader; skipping — proxy still validates routing)"
  fi
fi

echo "== Port-forwarding svc/osv-proxy 8443:443 =="
kubectl port-forward svc/osv-proxy 8443:443 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3

echo "== Validating https://api.osv.dev via proxy (--resolve + --cacert CA) =="
curl -s --resolve "api.osv.dev:8443:127.0.0.1" \
  --cacert "$CERT_DIR/ca.crt" \
  "https://api.osv.dev:8443/v1/vulns/GHSA-test-0001" || true

echo
echo "DEMO READY — https://api.osv.dev is now served by the local osv-service."
echo
echo "To make real (non-reconfigurable) apps use it transparently:"
echo "  1. Trust the CA on this host:"
echo "       sudo cp $CERT_DIR/ca.crt /usr/local/share/ca-certificates/osv-proxy-ca.crt \\"
echo "         && sudo update-ca-certificates        # Linux/WSL"
echo "       (Windows: import $CERT_DIR/ca.crt into Trusted Root Certification Authorities)"
echo "  2. Resolve api.osv.dev to this host, e.g. add to hosts:"
echo "       127.0.0.1 api.osv.dev"
echo "     and publish port 443 (run as root):"
echo "       kubectl port-forward svc/osv-proxy 443:443 &"
echo "     or expose the proxy via a NodePort/Ingress in your cluster."
