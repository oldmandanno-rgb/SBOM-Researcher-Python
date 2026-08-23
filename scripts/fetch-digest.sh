#!/usr/bin/env bash
set -euo pipefail
REGISTRY="cgr.dev"
REPO="chainguard/python"
for tag in latest latest-dev; do
  # Trigger a 401 to learn the auth realm/service/scope
  www=$(curl -s -D - -o /dev/null "https://${REGISTRY}/v2/${REPO}/manifests/${tag}")
  realm=$(echo "$www" | grep -i 'www-authenticate' | sed -E 's/.*realm="([^"]+)".*/\1/')
  service=$(echo "$www" | grep -i 'www-authenticate' | sed -E 's/.*service="([^"]+)".*/\1/')
  scope=$(echo "$www" | grep -i 'www-authenticate' | sed -E 's/.*scope="([^"]+)".*/\1/')
  # Fetch the registry token to a temp file, then parse it (avoid curl | python).
  curl -s "${realm}?service=${service}&scope=${scope}" -o /tmp/osv_token.json
  token=$(python3 -c 'import json;print(json.load(open("/tmp/osv_token.json"))["token"])')
  # Fetch the manifest to a temp file, then parse the digest (avoid curl | python).
  curl -s -H "Authorization: Bearer ${token}" -H "Accept: application/vnd.oci.image.index.v1+json" "https://${REGISTRY}/v2/${REPO}/manifests/${tag}" -o /tmp/osv_manifest.json
  digest=$(python3 -c 'import json;d=json.load(open("/tmp/osv_manifest.json"));print(d.get("digest") or d.get("manifests",[{}])[0].get("digest","?"))')
  echo "${tag} => ${digest}"
done
