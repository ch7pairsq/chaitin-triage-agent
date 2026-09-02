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

docker exec agent-compose agent-compose version
docker exec agent-compose agent-compose project ls --json
schedulers=$(docker exec agent-compose agent-compose -p chaitin-triage-agent scheduler ls --json)
for scheduler in wazuh-alert-poll wazuh-alert hourly-security-triage; do
  printf '%s' "$schedulers" | grep -F "$scheduler" >/dev/null || { echo "scheduler is missing: $scheduler" >&2; exit 1; }
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

echo "triage platform verification passed"
