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
