#!/bin/sh
set -eu

trace_id=${1:-}
case "$trace_id" in
  ""|*[!A-Za-z0-9._:-]*) echo "usage: $0 TRACE_ID" >&2; exit 64 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}

docker run --rm --network chaitin-net \
  --env "TRACE_ID=$trace_id" \
  --volume "$host_repo_root/deploy/stacks/triage-platform/tools/verify-trace.mjs:/app/verify-trace.mjs:ro" \
  --volume "$host_repo_root/deploy/stacks/triage-platform/generated/triage-ops-token:/run/secrets/triage-ops-token:ro" \
  node:22.23.2-alpine3.24 \
  node /app/verify-trace.mjs
