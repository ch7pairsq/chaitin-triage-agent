#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npmCache = path.join(root, ".tmp", "npm-cache");
mkdirSync(npmCache, { recursive: true });
const mode = process.argv[2] ?? "--all";
if (!["--check", "--test", "--all"].includes(mode)) throw new Error("use --check, --test or --all");

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

console.log(`repository ${mode.slice(2)} verification passed`);
