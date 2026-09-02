#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const outputDir = process.env.TRIAGE_CONFIG_OUTPUT_DIR
  ? path.resolve(process.env.TRIAGE_CONFIG_OUTPUT_DIR)
  : "/repo/deploy/stacks/triage-platform/generated";

function required(name, { minLength = 1, pattern } = {}) {
  const value = String(process.env[name] ?? "").trim();
  if (value.length < minLength) throw new Error(`${name} must contain at least ${minLength} characters`);
  if (/[\r\n\0]/.test(value)) throw new Error(`${name} contains a forbidden control character`);
  if (pattern && !pattern.test(value)) throw new Error(`${name} has an invalid format`);
  return value;
}

function optional(name) {
  const value = String(process.env[name] ?? "").trim();
  if (/[\r\n\0]/.test(value)) throw new Error(`${name} contains a forbidden control character`);
  return value;
}

function writePrivate(name, content) {
  const target = path.join(outputDir, name);
  fs.writeFileSync(target, content, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(target, 0o600);
}

function shellValue(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

const tokenPattern = /^[A-Za-z0-9._~-]+$/;
const repoRoot = required("REPO_ROOT");
if (!repoRoot.startsWith("/")) throw new Error("REPO_ROOT must be an absolute Linux path");
required("AUTH_USERNAME");
required("AUTH_PASSWORD", { minLength: 12 });
required("AUTH_SECRET", { minLength: 32 });

const feishuWebhookUrl = required("FEISHU_WEBHOOK_URL");
const feishu = new URL(feishuWebhookUrl);
if (feishu.protocol !== "https:" || feishu.hostname !== "open.feishu.cn" || !/^\/open-apis\/bot\/v2\/hook\/[A-Za-z0-9_-]+$/.test(feishu.pathname)) {
  throw new Error("FEISHU_WEBHOOK_URL must be an open.feishu.cn custom robot webhook URL");
}

const values = {
  WAZUH_INGRESS_TOKEN: required("WAZUH_INGRESS_TOKEN", { minLength: 24, pattern: tokenPattern }),
  TRIAGE_RUNNER_TOKEN: required("TRIAGE_RUNNER_TOKEN", { minLength: 24, pattern: tokenPattern }),
  TRIAGE_OPS_TOKEN: required("TRIAGE_OPS_TOKEN", { minLength: 24, pattern: tokenPattern }),
  OCTOBUS_ADMIN_TOKEN: required("OCTOBUS_ADMIN_TOKEN", { minLength: 24, pattern: tokenPattern }),
  AGENT_WEBHOOK_TOKEN: required("AGENT_WEBHOOK_TOKEN", { minLength: 24, pattern: tokenPattern }),
  SCRIPT_SERVICE_TOKEN: required("SCRIPT_SERVICE_TOKEN", { minLength: 24, pattern: tokenPattern }),
  DECISION_TOKEN_SECRET: required("DECISION_TOKEN_SECRET", { minLength: 32 }),
  WAZUH_TRIAGE_READER_PASSWORD: required("WAZUH_TRIAGE_READER_PASSWORD", { minLength: 12 }),
  AGENT_COMPOSE_GUEST_IMAGE: required("AGENT_COMPOSE_GUEST_IMAGE"),
  LLM_API_ENDPOINT: required("LLM_API_ENDPOINT"),
  LLM_API_KEY: required("LLM_API_KEY"),
  LLM_MODEL: required("LLM_MODEL"),
  LLM_API_PROTOCOL: required("LLM_API_PROTOCOL", { pattern: /^(responses|chat_completions)$/ })
};

fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
fs.chmodSync(outputDir, 0o700);

writePrivate("wazuh-connector.config.json", `${JSON.stringify({
  indexer_url: "https://wazuh.indexer:9200",
  index_pattern: "wazuh-alerts-*",
  minimum_rule_level: 3,
  request_timeout_ms: 10000,
  ca_path: "/repo/deploy/stacks/wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem",
  max_alert_bytes: 262144
}, null, 2)}\n`);
writePrivate("wazuh-connector.secret.json", `${JSON.stringify({
  indexer_username: "triage_reader",
  indexer_password: values.WAZUH_TRIAGE_READER_PASSWORD
}, null, 2)}\n`);
writePrivate("security-ops.config.json", `${JSON.stringify({
  database_path: "triage.db",
  knowledge_path: "resources/knowledge.jsonl",
  agent_webhook_url: "http://agent-compose:7410/api/webhooks/webhook.wazuh.alert",
  trigger_poll_interval_ms: 1000,
  delivery_poll_interval_ms: 3000
}, null, 2)}\n`);
const feishuWebhookSecret = optional("FEISHU_WEBHOOK_SECRET");
writePrivate("security-ops.secret.json", `${JSON.stringify({
  agent_webhook_token: values.AGENT_WEBHOOK_TOKEN,
  decision_token_secret: values.DECISION_TOKEN_SECRET,
  feishu_webhook_url: feishuWebhookUrl,
  ...(feishuWebhookSecret ? { feishu_webhook_secret: feishuWebhookSecret } : {})
}, null, 2)}\n`);

const daemonEnvNames = [
  "LLM_API_ENDPOINT", "LLM_API_KEY", "LLM_MODEL", "LLM_API_PROTOCOL", "AGENT_COMPOSE_GUEST_IMAGE",
  "SCRIPT_SERVICE_TOKEN", "WAZUH_INGRESS_TOKEN", "TRIAGE_RUNNER_TOKEN"
];
writePrivate("agent-compose.env", `${daemonEnvNames.map((name) => `${name}=${shellValue(values[name])}`).join("\n")}\nOCTOBUS_BASE_URL='http://octobus:9000'\n`);
writePrivate("octobus-admin.env", `OCTOBUS_ADMIN_TOKEN=${values.OCTOBUS_ADMIN_TOKEN}\n`);
writePrivate("wazuh-ingress-token", `${values.WAZUH_INGRESS_TOKEN}\n`);
writePrivate("triage-runner-token", `${values.TRIAGE_RUNNER_TOKEN}\n`);
writePrivate("triage-ops-token", `${values.TRIAGE_OPS_TOKEN}\n`);
writePrivate("octobus-admin-token", `${values.OCTOBUS_ADMIN_TOKEN}\n`);
writePrivate("agent-webhook-token", `${values.AGENT_WEBHOOK_TOKEN}\n`);
writePrivate("script-service-token", `${values.SCRIPT_SERVICE_TOKEN}\n`);

console.log("triage-platform private configuration rendered");
