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
  token=$(curl -s "${realm}?service=${service}&scope=${scope}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  digest=$(curl -s -H "Authorization: Bearer ${token}" -H "Accept: application/vnd.oci.image.index.v1+json" "https://${REGISTRY}/v2/${REPO}/manifests/${tag}" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("digest") or d.get("manifests",[{}])[0].get("digest","?"))')
  echo "${tag} => ${digest}"
done
