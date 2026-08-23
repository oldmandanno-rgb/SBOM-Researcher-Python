#!/usr/bin/env bash
# Local, on-demand test of the osv-service container + k8s manifests.
#
# Prerequisites (install once, then only run when you actually want to test):
#   - Docker Desktop (running)
#   - kind  -> https://kind.sigs.k8s.io/docs/user/quick-start/#installation
#   - kubectl
#
# This mirrors exactly what .github/workflows/build-osv-service.yml does, so
# "passes locally" == "passes in CI".
#
# Usage:
#   ./scripts/local-test.sh            # build, kind cluster, deploy, smoke test
#   ./scripts/local-test.sh --no-kind  # just the plain `docker run` smoke test
#   ./scripts/local-test.sh --cleanup  # delete the kind cluster afterwards
set -euo pipefail

IMAGE="osv-service:local"
CLEANUP_KIND=0
NO_KIND=0
for arg in "$@"; do
  case "$arg" in
    --cleanup) CLEANUP_KIND=1 ;;
    --no-kind) NO_KIND=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

echo "== Building image $IMAGE =="
docker build -t "$IMAGE" .

echo "== Container smoke test =="
docker run -d --name osv-smoke -p 8000:8000 \
  -v "$PWD/tests/fixtures/osv_store:/data:ro" "$IMAGE"
trap 'docker rm -f osv-smoke >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 30); do
  if curl -s -o /dev/null http://localhost:8000/v1/vulns/x; then break; fi
  sleep 1
done
curl -s http://localhost:8000/v1/vulns/GHSA-test-0001 | grep -q GHSA-test-0001
curl -s -X POST http://localhost:8000/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package":{"ecosystem":"PyPI","name":"example"},"version":"1.0.0"}' \
  | grep -q GHSA-test-0001
echo "CONTAINER SMOKE TEST OK"
docker rm -f osv-smoke >/dev/null
trap - EXIT

if [ "$NO_KIND" -eq 1 ]; then
  echo "== Skipping kind (--no-kind) =="
  exit 0
fi

echo "== Creating kind cluster =="
if ! kind get clusters 2>/dev/null | grep -q '^kind$'; then
  kind create cluster --wait 120s
fi

echo "== Loading image into kind =="
kind load docker-image "$IMAGE"

echo "== Deploying (deploy/test overlay) =="
kubectl apply -k deploy/test
kubectl rollout status deployment/osv-service --timeout=120s

echo "== k8s smoke test =="
kubectl port-forward svc/osv-service 8000:8000 &
PF=$!
for i in $(seq 1 30); do
  if curl -s -o /dev/null http://localhost:8000/v1/vulns/x; then break; fi
  sleep 1
done
curl -s http://localhost:8000/v1/vulns/x | grep -q "not found"
echo "K8S TEST OK"
kill "$PF" || true

if [ "$CLEANUP_KIND" -eq 1 ]; then
  echo "== Deleting kind cluster =="
  kind delete cluster
fi
echo "DONE"
