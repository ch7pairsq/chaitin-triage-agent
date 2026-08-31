#!/bin/sh
# Secret-safe daemon entrypoint. Values are loaded from the root-only project
# .env and are never printed. The business workflow receives only variables
# explicitly declared as secret in agent-compose.yml.
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
if [ -z "${OCTOBUS_TOKEN:-}" ]; then
  echo "agent-compose: required variable is empty: OCTOBUS_TOKEN" >&2
  exit 78
fi

exec /usr/bin/tini -- /app/agent-compose daemon
