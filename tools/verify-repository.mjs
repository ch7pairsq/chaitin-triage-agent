#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCache = path.join(root, ".tmp", "npm-cache");
mkdirSync(npmCache, { recursive: true });
const mode = process.argv[2] ?? "--all";
if (!["--check", "--test", "--all"].includes(mode)) throw new Error("use --check, --test or --all");

for (const relativePath of ["scheduler/wazuh-intake.js", "scheduler/triage-scheduler.js"]) {
  const source = readFileSync(path.join(root, relativePath), "utf8");
  if (/\bfetch\s*\(|node:sqlite|better-sqlite3|open\.feishu\.cn|wazuh\.indexer:9200/i.test(source)) {
    throw new Error(`${relativePath} contains a direct business-backend call`);
  }
  if (!source.includes("CAP_GRPC_TARGET")) {
    throw new Error(`${relativePath} does not use the agent-compose capability gateway`);
  }
}

const readme = readFileSync(path.join(root, "README.md"), "utf8");
for (const stale of ["hourly-security-triage", "wazuh-alert-poll", "scheduler trigger wazuh-intake", "minimum_rule_level: 3"]) {
  if (readme.includes(stale)) throw new Error(`README.md contains obsolete text: ${stale}`);
}
for (const required of [
  "wazuh-intake",
  "RequeueStalledAlerts",
  "claimToken",
  "trigger_outbox",
  "manual_tickets",
  "delivery_outbox",
  "executableRule",
  "evaluation_json",
  "移除知识会使确认匹配消失",
  "/bin/sh deploy/update-stacks.sh",
  "Portainer",
  "X-Hub-Signature-256",
  "Wazuh Dashboard 仅用于可视化"
]) {
  if (!readme.includes(required)) throw new Error(`README.md is missing current design text: ${required}`);
}
if (readme.includes("npm run generate") || readme.includes("decisionToken` 是否原样传递")) {
  throw new Error("README.md contains a removed authoring or token-relay step");
}
if (existsSync(path.join(root, "knowledge-authoring/tools/generate.mjs"))) {
  throw new Error("the removed bulk knowledge generator must not be restored");
}
const sourceRegistry = JSON.parse(readFileSync(path.join(root, "knowledge-authoring/sources.json"), "utf8"));
if (!Array.isArray(sourceRegistry.sources) || sourceRegistry.sources.length < 10) {
  throw new Error("knowledge source registry is incomplete");
}
const knowledgeEngine = readFileSync(path.join(root, "services/security-ops/src/knowledge-rule-engine.js"), "utf8");
const securityOpsService = readFileSync(path.join(root, "services/security-ops/src/service.js"), "utf8");
if (!knowledgeEngine.includes("ALLOWED_OPERATORS") || !securityOpsService.includes("evaluateKnowledgeRule")) {
  throw new Error("executable knowledge is not consumed by SecurityOps");
}

const packages = [
  ["knowledge-authoring", ["check", "test"]],
  ["services/security-ops", ["check", "test", "validate:package", "validate:deployment", "pack:check"]],
  ["services/wazuh-connector", ["check", "test", "validate:package", "pack:check"]],
  ["scheduler", ["check", "test"]],
  ["tools/wazuh-event-injector", ["check", "test"]],
  ["tools/release-webhook", ["check", "test"]]
];

for (const [directory, scripts] of packages) {
  for (const script of scripts) {
    if (mode === "--check" && script !== "check" && script !== "validate:package" && script !== "validate:deployment") continue;
    if (mode === "--test" && script !== "test") continue;
    const npmCli = process.env.npm_execpath;
    const executable = npmCli ? process.execPath : "npm";
    const args = npmCli ? [npmCli, "run", script] : ["run", script];
    const result = spawnSync(executable, args, {
      cwd: path.join(root, directory),
      stdio: "inherit",
      env: { ...process.env, NPM_CONFIG_CACHE: npmCache }
    });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}

if (mode !== "--check") {
  const result = spawnSync(process.execPath, ["--test", path.join(root, "deploy/test/update-stacks.test.mjs")], {
    cwd: root,
    stdio: "inherit",
    env: { ...process.env, NPM_CONFIG_CACHE: npmCache }
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

console.log(`repository ${mode.slice(2)} verification passed`);
