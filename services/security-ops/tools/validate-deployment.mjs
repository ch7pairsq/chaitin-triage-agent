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
  JSON.stringify(agentCompose?.agents?.["triage-operator"]?.capset_ids) === JSON.stringify([
    "wazuh/wazuh-ingress",
    "triage/triage-runner"
  ]),
  "triage-operator must use only the two declared OctoBus capsets"
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
const releaseWorker = read("tools/release-webhook/src/worker.js");
assert(
  releaseWorker.includes('"--force-recreate", "agent-compose", "agent-compose-ui"'),
  "release worker must recreate single-file bind mounts after fast-forward"
);

for (const file of [
  "deploy/stacks/wazuh/tools/configure-triage-role.mjs",
  "deploy/stacks/wazuh/tools/render-config.mjs",
  "deploy/stacks/triage-platform/tools/configure-agent-webhook.mjs",
  "deploy/stacks/triage-platform/tools/render-config.mjs",
  "deploy/stacks/triage-platform/tools/verify-trace.mjs",
  "deploy/stacks/release-webhook/tools/render-secret.mjs"
]) runNodeCheck(file);

for (const file of [
  "deploy/_daemon_entry.sh",
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
assert(/chmod 0400 deploy\/stacks\/wazuh\/config\/wazuh_indexer_ssl_certs\/root-ca\.pem/.test(wazuhPrepare), "Wazuh public CA must remain owner-readable only");
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
