#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}
helper_image=node:22.23.2-alpine3.24

rounds=2
empty_cycles=10
profile=acceptance
timeout_seconds=240
allow_bulk=false

usage() {
  echo "usage: $0 [--rounds 1..99] [--empty-cycles 0..100] [--profile quick|acceptance|coverage] [--timeout-seconds 30..300] [--allow-bulk]" >&2
}

bounded_integer() {
  value=$1
  minimum=$2
  maximum=$3
  label=$4
  case "$value" in
    ""|*[!0-9]*) echo "$label must be an integer between $minimum and $maximum" >&2; exit 64 ;;
  esac
  if [ "$value" -lt "$minimum" ] || [ "$value" -gt "$maximum" ]; then
    echo "$label must be an integer between $minimum and $maximum" >&2
    exit 64
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --rounds) [ "$#" -ge 2 ] || { usage; exit 64; }; rounds=$2; shift 2 ;;
    --empty-cycles) [ "$#" -ge 2 ] || { usage; exit 64; }; empty_cycles=$2; shift 2 ;;
    --profile) [ "$#" -ge 2 ] || { usage; exit 64; }; profile=$2; shift 2 ;;
    --timeout-seconds) [ "$#" -ge 2 ] || { usage; exit 64; }; timeout_seconds=$2; shift 2 ;;
    --allow-bulk) allow_bulk=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

bounded_integer "$rounds" 1 99 rounds
bounded_integer "$empty_cycles" 0 100 empty-cycles
bounded_integer "$timeout_seconds" 30 300 timeout-seconds
case "$profile" in
  quick|acceptance|coverage) ;;
  *) usage; exit 64 ;;
esac
if [ "$rounds" -gt 15 ] && [ "$allow_bulk" != true ]; then
  echo "more than 15 rounds requires --allow-bulk because every round creates a ticket and a Feishu delivery" >&2
  exit 64
fi

for required in +  "$script_dir/tools/verify-e2e.mjs" +  "$script_dir/generated/wazuh-ingress-token" +  "$script_dir/generated/triage-ops-token"; do
  test -r "$required" || { echo "required verification file is missing: $required" >&2; exit 1; }
done

run_helper() {
  docker run --rm -i --network chaitin-net +    --env "EXPECTED_SOURCE_EVENT_ID=${EXPECTED_SOURCE_EVENT_ID:-}" +    --env "EXPECTED_SCENARIO_ID=${EXPECTED_SCENARIO_ID:-}" +    --env "EXPECTED_BUSINESS_EVENT_ID=${EXPECTED_BUSINESS_EVENT_ID:-}" +    --env "E2E_TIMEOUT_SECONDS=$timeout_seconds" +    --volume "$host_repo_root/deploy/stacks/triage-platform/tools/verify-e2e.mjs:/app/verify-e2e.mjs:ro" +    --volume "$host_repo_root/deploy/stacks/triage-platform/generated/wazuh-ingress-token:/run/secrets/wazuh-ingress-token:ro" +    "$helper_image" node /app/verify-e2e.mjs "$@"
}

echo "stage=platform-preflight"
/bin/sh "$script_dir/verify.sh"

cycle=1
while [ "$cycle" -le "$empty_cycles" ]; do
  echo "stage=empty-intake cycle=$cycle/$empty_cycles"
  intake_output=$(docker exec agent-compose agent-compose -p chaitin-triage-agent +    scheduler invoke wazuh-intake --payload '{"mode":"cycle"}' --timeout 30s --json)
  printf '%s' "$intake_output" | run_helper validate-intake >/dev/null
  cycle=$((cycle + 1))
done

seen_source_events=" "
seen_traces=" "
round=1
while [ "$round" -le "$rounds" ]; do
  sequence=$((round - 1))
  echo "stage=inject round=$round/$rounds profile=$profile sequence=$sequence"
  injection_output=$(docker exec +    -e INJECT_ENABLED=true +    -e INJECT_ONCE=true +    -e "INJECT_PROFILE=$profile" +    -e "INJECT_SEQUENCE=$sequence" +    wazuh-event-injector node src/index.js)
  injection_fields=$(printf '%s' "$injection_output" | run_helper parse-injection)
  set -- $injection_fields
  [ "$#" -eq 4 ] || { echo "injector receipt field count is invalid" >&2; exit 1; }
  source_event_id=$1
  scenario_id=$2
  domain_id=$3
  attack_type_id=$4
  case "$seen_source_events" in
    *" $source_event_id "*) echo "duplicate source event id: $source_event_id" >&2; exit 1 ;;
  esac
  seen_source_events="$seen_source_events$source_event_id "

  echo "stage=resolve-wazuh round=$round/$rounds source_event_id=$source_event_id"
  EXPECTED_SOURCE_EVENT_ID=$source_event_id
  EXPECTED_SCENARIO_ID=$scenario_id
  wazuh_alert_id=$(run_helper resolve-alert </dev/null)
  EXPECTED_BUSINESS_EVENT_ID="wazuh:$wazuh_alert_id"

  echo "stage=intake round=$round/$rounds wazuh_alert_id=$wazuh_alert_id"
  intake_output=$(docker exec agent-compose agent-compose -p chaitin-triage-agent +    scheduler invoke wazuh-intake --payload '{"mode":"cycle"}' --timeout 30s --json)
  printf '%s' "$intake_output" | run_helper validate-intake >/dev/null

  echo "stage=agent-wait round=$round/$rounds"
  deadline=$(( $(date +%s) + timeout_seconds ))
  run_fields=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    runs_output=$(docker exec agent-compose agent-compose -p chaitin-triage-agent +      scheduler runs --trigger wazuh-alert --limit 30 --json)
    if run_fields=$(printf '%s' "$runs_output" | run_helper find-run); then
      break
    else
      status=$?
      [ "$status" -eq 75 ] || exit "$status"
    fi
    sleep 2
  done
  [ -n "$run_fields" ] || { echo "matching Agent run did not complete within $timeout_seconds seconds" >&2; exit 1; }
  set -- $run_fields
  [ "$#" -eq 3 ] || { echo "Agent run field count is invalid" >&2; exit 1; }
  run_id=$1
  trace_id=$2
  duration_ms=$3
  case "$seen_traces" in
    *" $trace_id "*) echo "duplicate trace id: $trace_id" >&2; exit 1 ;;
  esac
  seen_traces="$seen_traces$trace_id "

  echo "stage=trace round=$round/$rounds trace_id=$trace_id"
  /bin/sh "$script_dir/verify-trace.sh" "$trace_id" completed >/dev/null
  printf '{"round":%s,"scenarioId":"%s","domainId":"%s","attackTypeId":"%s","sourceEventId":"%s","wazuhAlertId":"%s","runId":"%s","traceId":"%s","agentDurationMs":%s,"status":"passed"}\n' +    "$round" "$scenario_id" "$domain_id" "$attack_type_id" "$source_event_id" "$wazuh_alert_id" "$run_id" "$trace_id" "$duration_ms"
  round=$((round + 1))
done

echo "stage=platform-postflight"
/bin/sh "$script_dir/verify.sh"
echo "end-to-end verification passed: rounds=$rounds empty_cycles=$empty_cycles profile=$profile"
