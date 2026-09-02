#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqualArrays(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${message}: ${JSON.stringify(actual)}`);
}

function parseYaml(relativePath) {
  const document = parseDocument(read(relativePath), { prettyErrors: true });
  if (document.errors.length > 0) {
    throw new Error(`${relativePath}: ${document.errors.map((error) => error.message).join("; ")}`);
  }
  return document.toJS();
}

function parseJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function runNodeCheck(relativePath) {
  const result = spawnSync(process.execPath, ["--check", path.join(root, relativePath)], {
    encoding: "utf8"
  });
  if (result.error) throw result.error;
  assert(result.status === 0, `${relativePath}: ${result.stderr || result.stdout}`);
}

function runShellCheck(relativePath) {
  if (process.platform === "win32") return;
  const result = spawnSync("/bin/sh", ["-n", path.join(root, relativePath)], { encoding: "utf8" });
  if (result.error) throw result.error;
  assert(result.status === 0, `${relativePath}: ${result.stderr || result.stdout}`);
}

function runRenderer(relativePath, env) {
  const result = spawnSync(process.execPath, [path.join(root, relativePath)], {
    encoding: "utf8",
    env: { ...process.env, ...env }
  });
  if (result.error) throw result.error;
  assert(result.status === 0, `${relativePath}: ${result.stderr || result.stdout}`);
}

const yamlFiles = [
  "agent-compose.yml",
  "deploy/stacks/wazuh/docker-compose.yml",
  "deploy/stacks/wazuh/generate-indexer-certs.yml",
  "deploy/stacks/triage-platform/docker-compose.yml",
  "deploy/stacks/release-webhook/docker-compose.yml"
];
const documents = new Map(yamlFiles.map((file) => [file, parseYaml(file)]));

for (const file of [
  "services/security-ops/service.json",
  "services/security-ops/config.schema.json",
  "services/security-ops/secret.schema.json",
  "services/wazuh-connector/service.json",
  "services/wazuh-connector/config.schema.json",
  "services/wazuh-connector/secret.schema.json"
]) parseJson(file);

const agentCompose = documents.get("agent-compose.yml");
assert(agentCompose?.env_file === "/run/secrets/agent-compose.env", "agent-compose project env file must use the mounted absolute path");
assert(!String(agentCompose?.env_file).includes("${"), "agent-compose project env file must not rely on unsupported interpolation");
assert(agentCompose?.octobus_servers?.wazuh, "agent-compose.yml must declare the Wazuh OctoBus server");
assert(agentCompose?.octobus_servers?.triage, "agent-compose.yml must declare the triage OctoBus server");
assert(
  JSON.stringify(agentCompose?.agents?.["wazuh-intake"]?.capset_ids) === JSON.stringify(["wazuh/wazuh-ingress"]),
  "wazuh-intake must use only the Wazuh ingress capset"
);
assert(
  JSON.stringify(agentCompose?.agents?.["triage-operator"]?.capset_ids) === JSON.stringify(["triage/triage-runner"]),
  "triage-operator must use only the triage runner capset"
);
assert(agentCompose.agents["wazuh-intake"].scheduler?.sandbox_policy === "sticky", "wazuh-intake must use a sticky scheduler sandbox");
assert(agentCompose.agents["wazuh-intake"].scheduler?.concurrency_policy === "skip", "wazuh-intake must skip overlapping scheduler runs");
assert(agentCompose.agents["triage-operator"].scheduler?.sandbox_policy === "new", "triage-operator must use a new sandbox per run");
assert(agentCompose.agents["triage-operator"].scheduler?.concurrency_policy === "parallel", "triage-operator must allow parallel event runs");
assert(
  agentCompose?.agents?.["wazuh-intake"]?.image === "chaitin/agent-compose-guest@sha256:1c18be6907ad7d0ad4f13d95aa89530615412c0a016a01a0f9548503112b2ee0",
  "wazuh-intake image must be pinned explicitly because the deployed agent-compose version does not interpolate this field"
);
assert(
  agentCompose?.agents?.["triage-operator"]?.image === "chaitin/agent-compose-guest@sha256:1c18be6907ad7d0ad4f13d95aa89530615412c0a016a01a0f9548503112b2ee0",
  "triage-operator image must be pinned explicitly because the deployed agent-compose version does not interpolate this field"
);

const wazuhStack = documents.get("deploy/stacks/wazuh/docker-compose.yml");
assert(wazuhStack?.services?.["wazuh.manager"], "Wazuh manager service is missing");
assert(wazuhStack?.services?.["wazuh.indexer"], "Wazuh indexer service is missing");
assert(wazuhStack?.services?.["wazuh-role-bootstrap"], "Wazuh read-only role bootstrap is missing");
assert(wazuhStack.services["wazuh-role-bootstrap"].user === "1000:1000", "Wazuh role bootstrap must use the certificate owner identity");
assert(
  wazuhStack?.services?.["wazuh-event-injector"]?.environment?.INJECT_STAY_ALIVE === "true",
  "disabled Wazuh event injector must stay available for one-shot execution"
);
const wazuhManagerConfig = read("deploy/stacks/wazuh/config/wazuh_cluster/wazuh_manager.conf");
const wazuhRemoteBlocks = [...wazuhManagerConfig.matchAll(/<remote>([\s\S]*?)<\/remote>/g)].map((match) => match[1]);
const wazuhSyslogRemote = wazuhRemoteBlocks.find((block) => /<connection>\s*syslog\s*<\/connection>/.test(block));
assert(wazuhSyslogRemote, "Wazuh syslog remote input is missing");
assert(!/<queue_size>/.test(wazuhSyslogRemote), "Wazuh syslog remote must not declare secure-only queue_size");

const platformStack = documents.get("deploy/stacks/triage-platform/docker-compose.yml");
assert(platformStack?.services?.octobus, "OctoBus service is missing from triage-platform");
assert(platformStack?.services?.["agent-compose"], "agent-compose service is missing from triage-platform");
assert(platformStack?.networks?.["chaitin-net"]?.external === true, "triage-platform must join the Wazuh network");

const releaseStack = documents.get("deploy/stacks/release-webhook/docker-compose.yml");
const receiverVolumes = releaseStack?.services?.["release-webhook"]?.volumes ?? [];
const workerVolumes = releaseStack?.services?.["release-worker"]?.volumes ?? [];
assert(!receiverVolumes.some((item) => String(item).includes("/var/run/docker.sock")), "release receiver must not mount the Docker socket");
assert(!receiverVolumes.some((item) => String(item).includes(":/workspace")), "release receiver must not mount the repository");
assert(workerVolumes.some((item) => String(item).includes("/var/run/docker.sock")), "release worker must mount the Docker socket");
assert(workerVolumes.some((item) => String(item).includes(":/workspace")), "release worker must mount the repository");
assert(workerVolumes.some((item) => String(item).includes("/data/chaitin:/host-data/chaitin")), "release worker must mount the state root for backups");
const releaseWorker = read("tools/release-webhook/src/worker.js");
assert(
  releaseWorker.includes('path.join(config.workspace, "deploy/update-stacks.sh")'),
  "release worker must delegate deployment to the shared update script"
);
assert(!releaseWorker.includes('compose(["-f"'), "release worker must not keep a second Stack update implementation");

for (const file of [
  "deploy/stacks/wazuh/tools/configure-triage-role.mjs",
  "deploy/stacks/wazuh/tools/render-config.mjs",
  "deploy/stacks/triage-platform/tools/configure-agent-webhook.mjs",
  "deploy/stacks/triage-platform/tools/render-config.mjs",
  "deploy/stacks/triage-platform/tools/verify-readiness.mjs",
  "deploy/stacks/triage-platform/tools/verify-trace.mjs",
  "deploy/stacks/release-webhook/tools/render-secret.mjs"
]) runNodeCheck(file);

for (const file of [
  "deploy/_daemon_entry.sh",
  "deploy/update-stacks.sh",
  "deploy/stacks/wazuh/prepare-config.sh",
  "deploy/stacks/triage-platform/prepare-config.sh",
  "deploy/stacks/triage-platform/bootstrap.sh",
  "deploy/stacks/triage-platform/verify.sh",
  "deploy/stacks/triage-platform/verify-trace.sh",
  "deploy/stacks/release-webhook/prepare-config.sh"
]) runShellCheck(file);

const wazuhPrepare = fs.readFileSync(path.join(root, "deploy/stacks/wazuh/prepare-config.sh"), "utf8");
assert(/hash\.sh[\s\\]*\n[\s-]*-env WAZUH_HASH_PASSWORD/.test(wazuhPrepare), "Wazuh password hashing must use the official environment-variable input");
assert(/--env-file "\$password_env"/.test(wazuhPrepare), "Wazuh password hashing must read a private environment file");
assert(!/hash\.sh[\s\\]*\n[\s|]*\|/.test(wazuhPrepare), "Wazuh password hashing must not rely on console stdin");
assert(/chown 1000:1000[\s\\]*\n[\s\S]*root-ca\.pem[\s\\]*\n[\s\S]*internal_users\.yml[\s\\]*\n[\s\S]*wazuh\.yml/.test(wazuhPrepare), "Wazuh runtime files must belong to the uid 1000 service identity");
assert(/chmod 0444 deploy\/stacks\/wazuh\/config\/wazuh_indexer_ssl_certs\/root-ca\.pem/.test(wazuhPrepare), "Wazuh public CA must be readable by both Wazuh and OctoBus runtime identities");
assert(/chmod 0600[\s\\]*\n[\s\S]*internal_users\.yml[\s\\]*\n[\s\S]*wazuh\.yml/.test(wazuhPrepare), "Wazuh generated credential files must remain owner-readable only");
assert(!/chmod[^\n]*(?:-key\.pem|admin\.pem)/.test(wazuhPrepare), "Wazuh private key permissions must not be relaxed by prepare-config");

const platformPrepare = fs.readFileSync(path.join(root, "deploy/stacks/triage-platform/prepare-config.sh"), "utf8");
assert(/chown 999:999 deploy\/stacks\/triage-platform\/generated/.test(platformPrepare), "OctoBus must own the private generated directory");
for (const file of [
  "wazuh-connector.config.json",
  "wazuh-connector.secret.json",
  "security-ops.config.json",
  "security-ops.secret.json"
]) {
  assert(platformPrepare.includes(`deploy/stacks/triage-platform/generated/${file}`), `OctoBus runtime permission is missing for ${file}`);
}
assert(/chmod 0700 deploy\/stacks\/triage-platform\/generated/.test(platformPrepare), "OctoBus generated directory must remain private");
assert(/chmod 0600[\s\S]*wazuh-connector\.config\.json[\s\S]*security-ops\.secret\.json/.test(platformPrepare), "OctoBus instance files must remain owner-readable only");

const platformBootstrap = fs.readFileSync(path.join(root, "deploy/stacks/triage-platform/bootstrap.sh"), "utf8");
assert(
  /set -a[\s\S]*\. \/run\/secrets\/agent-compose\.env[\s\S]*set \+a[\s\S]*agent-compose -f agent-compose\.yml project up/.test(platformBootstrap),
  "agent-compose project apply must load interpolation values into the CLI process"
);

function selectedMethods(capsetId) {
  return [...platformBootstrap.matchAll(new RegExp(`^select_method ${capsetId} [^ ]+ (/[^ ]+) [^\\s]+$`, "gm"))]
    .map((match) => match[1]);
}

assertEqualArrays(selectedMethods("wazuh-ingress"), [
  "/wazuh.connector.v1.WazuhConnectorService/ListAlerts",
  "/security.ops.v1.SecurityOpsService/IngestAlertEvent",
  "/security.ops.v1.SecurityOpsService/RequeueStalledAlerts"
], "wazuh-ingress methods must be exact");
assertEqualArrays(selectedMethods("triage-runner"), [
  "/security.ops.v1.SecurityOpsService/ClaimAlert",
  "/security.ops.v1.SecurityOpsService/GetAlertContext",
  "/security.ops.v1.SecurityOpsService/EnrichAlert",
  "/security.ops.v1.SecurityOpsService/MatchKnowledge",
  "/security.ops.v1.SecurityOpsService/EvaluatePolicy",
  "/security.ops.v1.SecurityOpsService/RecordTriageResult",
  "/security.ops.v1.SecurityOpsService/CreateManualTicket",
  "/security.ops.v1.SecurityOpsService/QueueFeishuNotification",
  "/security.ops.v1.SecurityOpsService/FinalizeTriage"
], "triage-runner methods must be exact");
assertEqualArrays(selectedMethods("triage-ops"), [
  "/security.ops.v1.SecurityOpsService/GetTriageTrace",
  "/security.ops.v1.SecurityOpsService/RecoverDelivery",
  "/security.ops.v1.SecurityOpsService/PutAuthorizationRecord",
  "/security.ops.v1.SecurityOpsService/GetWorkerReadiness"
], "triage-ops methods must be exact");

const intakeScheduler = read("scheduler/wazuh-intake.js");
const triageScheduler = read("scheduler/triage-scheduler.js");
for (const [name, source] of [["wazuh-intake", intakeScheduler], ["triage-operator", triageScheduler]]) {
  assert(!/\bfetch\s*\(|node:sqlite|better-sqlite3|open\.feishu\.cn|wazuh\.indexer:9200/i.test(source), `${name} must not call a business backend directly`);
  assert(source.includes("CAP_GRPC_TARGET"), `${name} must call business capabilities through the agent-compose gateway`);
}
assert(!triageScheduler.includes("ListPendingAlerts"), "triage Agent must not receive the pending-alert operational method");

const releasePrepare = read("deploy/stacks/release-webhook/prepare-config.sh");
assert(
  /chown 1000:1000[\s\\]*\n[\s\S]*generated[\s\\]*\n[\s\S]*generated\/github-webhook-secret/.test(releasePrepare),
  "release webhook secret must belong to the uid 1000 runtime identity"
);
assert(
  /chmod 0600 deploy\/stacks\/release-webhook\/generated\/github-webhook-secret/.test(releasePrepare),
  "release webhook secret must remain owner-readable only"
);

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "triage-deployment-validation-"));
try {
  const commonEnv = {
    REPO_ROOT: "/srv/chaitin-triage-agent",
    WAZUH_INGRESS_TOKEN: "wazuh-ingress-token-0000000000000001",
    TRIAGE_RUNNER_TOKEN: "triage-runner-token-0000000000000001",
    TRIAGE_OPS_TOKEN: "triage-ops-token-0000000000000000001",
    OCTOBUS_ADMIN_TOKEN: "octobus-admin-token-000000000000001",
    AGENT_WEBHOOK_TOKEN: "agent-webhook-token-000000000000001",
    SCRIPT_SERVICE_TOKEN: "script-service-token-00000000000001",
    DECISION_TOKEN_SECRET: "decision-token-secret-00000000000000000001",
    WAZUH_TRIAGE_READER_PASSWORD: "reader-password-000001",
    AGENT_COMPOSE_GUEST_IMAGE: "chaitin/agent-compose-guest@sha256:0000000000000000000000000000000000000000000000000000000000000000",
    LLM_API_ENDPOINT: "https://llm.invalid/v1",
    LLM_API_KEY: "llm-key-for-configuration-validation",
    LLM_MODEL: "validation-model",
    LLM_API_PROTOCOL: "chat_completions",
    AUTH_USERNAME: "admin",
    AUTH_PASSWORD: "ui-password-000001",
    AUTH_SECRET: "ui-auth-secret-0000000000000000000001",
    FEISHU_WEBHOOK_URL: "https://open.feishu.cn/open-apis/bot/v2/hook/configuration-validation"
  };
  const platformOutput = path.join(temporaryRoot, "platform");
  runRenderer("deploy/stacks/triage-platform/tools/render-config.mjs", {
    ...commonEnv,
    TRIAGE_CONFIG_OUTPUT_DIR: platformOutput
  });
  for (const file of [
    "wazuh-connector.config.json",
    "wazuh-connector.secret.json",
    "security-ops.config.json",
    "security-ops.secret.json"
  ]) JSON.parse(fs.readFileSync(path.join(platformOutput, file), "utf8"));
  const renderedWazuhConnector = JSON.parse(fs.readFileSync(path.join(platformOutput, "wazuh-connector.config.json"), "utf8"));
  assert(renderedWazuhConnector.required_rule_group === "triage_input", "Wazuh connector must select only triage_input alerts");

  const releaseOutput = path.join(temporaryRoot, "release");
  runRenderer("deploy/stacks/release-webhook/tools/render-secret.mjs", {
    GITHUB_WEBHOOK_SECRET: "github-webhook-secret-00000000000000000001",
    RELEASE_CONFIG_OUTPUT_DIR: releaseOutput
  });
  assert(fs.readFileSync(path.join(releaseOutput, "github-webhook-secret"), "utf8").trim().length >= 32, "release secret renderer produced an invalid file");
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

console.log(`deployment configuration is valid${process.platform === "win32" ? "; shell syntax check deferred to Linux" : ""}`);
