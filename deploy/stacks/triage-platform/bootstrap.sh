#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_repo_root=${TRIAGE_HOST_REPO_ROOT:-$repo_root}
generated="$script_dir/generated"

if [ ! -r "$repo_root/services/security-ops/resources/knowledge.jsonl" ]; then
  echo "approved runtime knowledge is missing; complete the knowledge review registry and build resources/knowledge.jsonl first" >&2
  exit 78
fi
for file in agent-compose.env octobus-admin.env wazuh-connector.config.json wazuh-connector.secret.json security-ops.config.json security-ops.secret.json wazuh-ingress-token triage-runner-token triage-ops-token octobus-admin-token agent-webhook-token; do
  if [ ! -r "$generated/$file" ]; then
    echo "missing generated private file: $generated/$file" >&2
    exit 78
  fi
done

octobus() {
  docker exec --env-file "$generated/octobus-admin.env" octobus octobus "$@"
}

for attempt in $(seq 1 30); do
  if octobus status >/dev/null 2>&1; then break; fi
  if [ "$attempt" -eq 30 ]; then echo "OctoBus did not become ready" >&2; exit 1; fi
  sleep 2
done

if ! octobus admin-token get bootstrap >/dev/null 2>&1; then
  docker exec -i --env-file "$generated/octobus-admin.env" octobus \
    octobus admin-token add bootstrap --name "bootstrap" --token-stdin \
    < "$generated/octobus-admin-token"
fi

octobus service import wazuh-connector /repo/services/wazuh-connector --name "Wazuh Alert Connector" --source-mode remote --reinstall
octobus service import security-ops /repo/services/security-ops --name "Security Operations" --source-mode remote --reinstall

upsert_instance() {
  instance_id="$1"
  service_id="$2"
  config_path="$3"
  secret_path="$4"
  if octobus instance get "$instance_id" >/dev/null 2>&1; then
    octobus instance update-config "$instance_id" --config "$config_path"
    octobus instance update-secret "$instance_id" --secret "$secret_path" --restart
  else
    octobus instance create "$instance_id" --service "$service_id" --config "$config_path" --secret "$secret_path"
  fi
}

upsert_instance wazuh-indexer wazuh-connector \
  /repo/deploy/stacks/triage-platform/generated/wazuh-connector.config.json \
  /repo/deploy/stacks/triage-platform/generated/wazuh-connector.secret.json
upsert_instance security-ops-main security-ops \
  /repo/deploy/stacks/triage-platform/generated/security-ops.config.json \
  /repo/deploy/stacks/triage-platform/generated/security-ops.secret.json

ensure_capset() {
  capset_id="$1"
  capset_name="$2"
  if octobus capset get "$capset_id" >/dev/null 2>&1; then
    octobus capset update "$capset_id" --name "$capset_name" --enabled=true
  else
    octobus capset create "$capset_id" --name "$capset_name"
  fi
}

reset_instance() {
  capset_id="$1"
  instance_id="$2"
  octobus capset remove-instance "$capset_id" "$instance_id" >/dev/null 2>&1 || true
  octobus capset add-instance "$capset_id" "$instance_id" --no-all-methods
}

select_method() {
  octobus capset select-method "$1" "$2" "$3" --mcp-tool "$4"
}

ensure_capset wazuh-ingress "Wazuh ingress"
reset_instance wazuh-ingress wazuh-indexer
reset_instance wazuh-ingress security-ops-main
select_method wazuh-ingress wazuh-indexer /wazuh.connector.v1.WazuhConnectorService/ListAlerts wazuh__list_alerts
select_method wazuh-ingress security-ops-main /security.ops.v1.SecurityOpsService/IngestAlertEvent security_ops__ingest_alert_event
select_method wazuh-ingress security-ops-main /security.ops.v1.SecurityOpsService/RequeueStalledAlerts security_ops__requeue_stalled_alerts

ensure_capset triage-runner "Security triage runner"
reset_instance triage-runner security-ops-main
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/ClaimAlert security_ops__claim_alert
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/GetAlertContext security_ops__get_alert_context
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/EnrichAlert security_ops__enrich_alert
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/MatchKnowledge security_ops__match_knowledge
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/EvaluatePolicy security_ops__evaluate_policy
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/RecordTriageResult security_ops__record_triage_result
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/CreateManualTicket security_ops__create_manual_ticket
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/QueueFeishuNotification security_ops__queue_feishu_notification
select_method triage-runner security-ops-main /security.ops.v1.SecurityOpsService/FinalizeTriage security_ops__finalize_triage

ensure_capset triage-ops "Security triage operations"
reset_instance triage-ops security-ops-main
select_method triage-ops security-ops-main /security.ops.v1.SecurityOpsService/GetTriageTrace security_ops__get_triage_trace
select_method triage-ops security-ops-main /security.ops.v1.SecurityOpsService/RecoverDelivery security_ops__recover_delivery
select_method triage-ops security-ops-main /security.ops.v1.SecurityOpsService/PutAuthorizationRecord security_ops__put_authorization_record

replace_token() {
  capset_id="$1"
  token_file="$2"
  octobus capset remove-token "$capset_id" runtime >/dev/null 2>&1 || true
  docker exec -i --env-file "$generated/octobus-admin.env" octobus \
    octobus capset add-token "$capset_id" runtime --name "runtime" --token-stdin \
    < "$token_file"
}
replace_token wazuh-ingress "$generated/wazuh-ingress-token"
replace_token triage-runner "$generated/triage-runner-token"
replace_token triage-ops "$generated/triage-ops-token"

# agent-compose has one server-side token per OctoBus endpoint. It uses that
# token both to read the protected admin catalog that becomes the sandbox MPI
# guide and to invoke the selected capset through the data-plane proxy. Register
# the two project-scoped tokens in both roles; they never enter the guest.
replace_agent_catalog_token() {
  token_id="$1"
  token_name="$2"
  token_file="$3"
  octobus admin-token delete "$token_id" >/dev/null 2>&1 || true
  docker exec -i --env-file "$generated/octobus-admin.env" octobus \
    octobus admin-token add "$token_id" --name "$token_name" --token-stdin \
    < "$token_file"
}
replace_agent_catalog_token agent-wazuh "agent-compose wazuh catalog" "$generated/wazuh-ingress-token"
replace_agent_catalog_token agent-triage "agent-compose triage catalog" "$generated/triage-runner-token"

docker run --rm --network chaitin-net \
  --volume "$host_repo_root/deploy/stacks/triage-platform/tools/configure-agent-webhook.mjs:/app/configure-agent-webhook.mjs:ro" \
  --volume "$host_repo_root/deploy/stacks/triage-platform/generated/agent-webhook-token:/run/secrets/agent-webhook-token:ro" \
  node:22.23.2-alpine3.24 \
  node /app/configure-agent-webhook.mjs

docker exec agent-compose sh -ec '
  set -a
  . /run/secrets/agent-compose.env
  set +a
  cd /repo
  agent-compose -f agent-compose.yml project up
'
docker exec agent-compose agent-compose project ls --json
docker exec agent-compose agent-compose -p chaitin-triage-agent scheduler ls --json
octobus catalog wazuh-ingress --mcp --json
octobus catalog triage-runner --mcp --json
octobus catalog triage-ops --mcp --json
