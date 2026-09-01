#!/bin/sh
set -eu

stack_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$stack_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}
env_file=${1:-"$repo_root/.env"}
test -r "$env_file" || { echo "missing root configuration: $env_file" >&2; exit 78; }

env_value() {
  key="$1"
  awk -v wanted="$key" 'index($0, wanted "=") == 1 { value=substr($0, length(wanted) + 2) } END { print value }' "$env_file"
}

WAZUH_INDEXER_ADMIN_PASSWORD=$(env_value WAZUH_INDEXER_ADMIN_PASSWORD)
WAZUH_KIBANASERVER_PASSWORD=$(env_value WAZUH_KIBANASERVER_PASSWORD)
WAZUH_TRIAGE_READER_PASSWORD=$(env_value WAZUH_TRIAGE_READER_PASSWORD)
WAZUH_API_PASSWORD=$(env_value WAZUH_API_PASSWORD)
test -n "$WAZUH_INDEXER_ADMIN_PASSWORD" || { echo "WAZUH_INDEXER_ADMIN_PASSWORD is required" >&2; exit 78; }
test -n "$WAZUH_KIBANASERVER_PASSWORD" || { echo "WAZUH_KIBANASERVER_PASSWORD is required" >&2; exit 78; }
test -n "$WAZUH_TRIAGE_READER_PASSWORD" || { echo "WAZUH_TRIAGE_READER_PASSWORD is required" >&2; exit 78; }
test -n "$WAZUH_API_PASSWORD" || { echo "WAZUH_API_PASSWORD is required" >&2; exit 78; }

hash_password() {
  printf '%s\n' "$1" | docker run --rm -i wazuh/wazuh-indexer:4.14.7 \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
    | tr -d '\r' | grep '^\$2' | tail -n 1
}

umask 077
WAZUH_ADMIN_HASH=$(hash_password "$WAZUH_INDEXER_ADMIN_PASSWORD")
WAZUH_KIBANASERVER_HASH=$(hash_password "$WAZUH_KIBANASERVER_PASSWORD")
WAZUH_TRIAGE_READER_HASH=$(hash_password "$WAZUH_TRIAGE_READER_PASSWORD")
test -n "$WAZUH_ADMIN_HASH"
test -n "$WAZUH_KIBANASERVER_HASH"
test -n "$WAZUH_TRIAGE_READER_HASH"

render_env=$(mktemp)
trap 'rm -f "$render_env"' EXIT HUP INT TERM
printf '%s\n' \
  "WAZUH_ADMIN_HASH=$WAZUH_ADMIN_HASH" \
  "WAZUH_KIBANASERVER_HASH=$WAZUH_KIBANASERVER_HASH" \
  "WAZUH_TRIAGE_READER_HASH=$WAZUH_TRIAGE_READER_HASH" \
  "WAZUH_API_PASSWORD=$WAZUH_API_PASSWORD" > "$render_env"

docker run --rm \
  --env-file "$render_env" \
  --volume "$host_repo_root:/repo" \
  --workdir /repo \
  node:22.23.2-alpine3.24 \
  node deploy/stacks/wazuh/tools/render-config.mjs
test -s "$stack_dir/generated/internal_users.yml"
test -s "$stack_dir/generated/wazuh.yml"
echo "Wazuh runtime configuration prepared"
