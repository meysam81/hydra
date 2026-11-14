#!/usr/bin/env bash
# Runs an image against the Postgres on localhost:5432 (postgres/secret, or
# SMOKE_DSN) and checks that it reports its version, migrates, serves and
# issues a token.
#
#   .github/smoke-test.sh <image> <version>
set -euo pipefail

image=$1
version=$2
dsn=${SMOKE_DSN:-postgres://postgres:secret@localhost:5432/postgres?sslmode=disable}
trap 'docker rm -f hydra-smoke >/dev/null 2>&1 || true' EXIT

docker run --rm "$image" version | grep -F "$version"

docker run --rm --network host -e DSN="$dsn" "$image" migrate sql up --yes --read-from-env
docker run -d --name hydra-smoke --network host -e DSN="$dsn" \
  -e SECRETS_SYSTEM=smoke-test-system-secret-0123456789 \
  -e URLS_SELF_ISSUER=http://localhost:4444 \
  "$image" serve all --dev --sqa-opt-out >/dev/null

if ! curl -fsS --retry 30 --retry-delay 1 --retry-all-errors -o /dev/null http://localhost:4444/health/ready; then
  docker logs hydra-smoke
  exit 1
fi
curl -fsS http://localhost:4444/.well-known/openid-configuration | jq -e '.issuer == "http://localhost:4444"' >/dev/null

# A client and a token: a database write and a signed JWT end to end.
client=$(curl -fsS http://localhost:4445/admin/clients -H 'Content-Type: application/json' \
  -d '{"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}')
curl -fsS http://localhost:4444/oauth2/token \
  -d grant_type=client_credentials \
  -d "client_id=$(jq -r .client_id <<<"$client")" \
  -d "client_secret=$(jq -r .client_secret <<<"$client")" | jq -e '.access_token | length > 0' >/dev/null

echo "smoke test passed: $image ($version)"
