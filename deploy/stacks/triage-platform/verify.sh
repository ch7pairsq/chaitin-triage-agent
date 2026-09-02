#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
generated="$script_dir/generated"

for container in wazuh.manager wazuh.indexer wazuh.dashboard octobus agent-compose agent-compose-ui; do
  running=$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || true)
  test "$running" = "true" || { echo "container is not running: $container" >&2; exit 1; }
done

role_exit=$(docker inspect --format '{{.State.ExitCode}}' wazuh-role-bootstrap 2>/dev/null || true)
test "$role_exit" = "0" || { echo "Wazuh least-privilege role bootstrap did not complete successfully" >&2; exit 1; }
wazuh_status=$(docker exec wazuh.manager /var/ossec/bin/wazuh-control status 2>&1 || true)
printf '%s\n' "$wazuh_status" | grep -F 'wazuh-remoted is running' >/dev/null || {
  echo "Wazuh syslog receiver is not running" >&2
  exit 1
}

docker exec agent-compose agent-compose version
docker exec agent-compose agent-compose project ls --json
schedulers=$(docker exec agent-compose agent-compose -p chaitin-triage-agent scheduler ls --json)
for scheduler in wazuh-intake wazuh-alert; do
  printf '%s' "$schedulers" | grep -F "$scheduler" >/dev/null || { echo "scheduler is missing: $scheduler" >&2; exit 1; }
done
for removed_scheduler in wazuh-alert-poll hourly-security-triage; do
  if printf '%s' "$schedulers" | grep -F "$removed_scheduler" >/dev/null; then
    echo "obsolete scheduler is still registered: $removed_scheduler" >&2
    exit 1
  fi
done

octobus() {
  docker exec --env-file "$generated/octobus-admin.env" octobus octobus "$@"
}
octobus status
octobus service get wazuh-connector
octobus service get security-ops
octobus instance get wazuh-indexer
octobus instance get security-ops-main
octobus admin-token get agent-wazuh
octobus admin-token get agent-triage
octobus catalog wazuh-ingress --mcp --json
octobus catalog triage-runner --mcp --json
octobus catalog triage-ops --mcp --json

repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}
docker run --rm --network chaitin-net \
  --volume "$host_repo_root/deploy/stacks/triage-platform/tools/verify-readiness.mjs:/app/verify-readiness.mjs:ro" \
  --volume "$host_repo_root/deploy/stacks/triage-platform/generated/triage-ops-token:/run/secrets/triage-ops-token:ro" \
  node:22.23.2-alpine3.24 \
  node /app/verify-readiness.mjs

echo "triage platform verification passed"
