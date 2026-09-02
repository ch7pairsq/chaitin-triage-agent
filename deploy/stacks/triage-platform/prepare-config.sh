#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}
env_file="$repo_root/.env"

if [ ! -r "$env_file" ]; then
  echo "missing root configuration: $env_file" >&2
  exit 78
fi

docker run --rm \
  --env-file "$env_file" \
  --volume "$host_repo_root:/repo" \
  --workdir /repo \
  node:22.23.2-alpine3.24 \
  node deploy/stacks/triage-platform/tools/render-config.mjs

# OctoBus runs as uid 999 and reads only the four instance files below from
# the generated directory. Keep all other tokens and Agent settings owned by
# root while granting the service the minimum private access it requires.
docker run --rm \
  --volume "$host_repo_root:/repo" \
  --workdir /repo \
  node:22.23.2-alpine3.24 \
  sh -ec '
    chown 999:999 deploy/stacks/triage-platform/generated
    chmod 0700 deploy/stacks/triage-platform/generated
    chown 999:999 \
      deploy/stacks/triage-platform/generated/wazuh-connector.config.json \
      deploy/stacks/triage-platform/generated/wazuh-connector.secret.json \
      deploy/stacks/triage-platform/generated/security-ops.config.json \
      deploy/stacks/triage-platform/generated/security-ops.secret.json
    chmod 0600 \
      deploy/stacks/triage-platform/generated/wazuh-connector.config.json \
      deploy/stacks/triage-platform/generated/wazuh-connector.secret.json \
      deploy/stacks/triage-platform/generated/security-ops.config.json \
      deploy/stacks/triage-platform/generated/security-ops.secret.json
  '
