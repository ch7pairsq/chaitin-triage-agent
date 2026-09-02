#!/bin/sh
# Secret-safe daemon entrypoint. Values are loaded from the root-only project
# .env and are never printed. OctoBus project tokens remain in the daemon and
# are not injected into the Agent guest.
set -eu

PROJECT_ENV="${PROJECT_ENV_FILE:-/deploy/chaitin-triage-agent/.env}"

if [ ! -r "${PROJECT_ENV}" ]; then
  echo "agent-compose: project .env is missing or unreadable: ${PROJECT_ENV}" >&2
  exit 78
fi

set -a
# shellcheck disable=SC1090
. "${PROJECT_ENV}"
set +a

if [ -z "${OCTOBUS_BASE_URL:-}" ]; then
  echo "agent-compose: required variable is empty: OCTOBUS_BASE_URL" >&2
  exit 78
fi
require_non_empty() {
  name="$1"
  case "$name" in
    WAZUH_INGRESS_TOKEN) value="${WAZUH_INGRESS_TOKEN:-}" ;;
    TRIAGE_RUNNER_TOKEN) value="${TRIAGE_RUNNER_TOKEN:-}" ;;
    AGENT_COMPOSE_GUEST_IMAGE) value="${AGENT_COMPOSE_GUEST_IMAGE:-}" ;;
    LLM_API_PROTOCOL) value="${LLM_API_PROTOCOL:-}" ;;
    *) echo "agent-compose: unsupported required variable: ${name}" >&2; exit 78 ;;
  esac
  if [ -z "$value" ]; then
    echo "agent-compose: required variable is empty: ${name}" >&2
    exit 78
  fi
}

for name in WAZUH_INGRESS_TOKEN TRIAGE_RUNNER_TOKEN AGENT_COMPOSE_GUEST_IMAGE LLM_API_PROTOCOL; do
  require_non_empty "$name"
done

exec /usr/bin/tini -- /app/agent-compose daemon
