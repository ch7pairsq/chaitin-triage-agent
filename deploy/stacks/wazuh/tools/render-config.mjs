import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = ["WAZUH_ADMIN_HASH", "WAZUH_KIBANASERVER_HASH", "WAZUH_TRIAGE_READER_HASH", "WAZUH_API_PASSWORD"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}

mkdirSync(path.join(root, "generated"), { recursive: true, mode: 0o700 });
const usersTemplate = readFileSync(path.join(root, "config", "wazuh_indexer", "internal_users.template.yml"), "utf8");
const users = usersTemplate
  .replace("__ADMIN_HASH__", process.env.WAZUH_ADMIN_HASH)
  .replace("__KIBANASERVER_HASH__", process.env.WAZUH_KIBANASERVER_HASH)
  .replace("__TRIAGE_READER_HASH__", process.env.WAZUH_TRIAGE_READER_HASH);
writeFileSync(path.join(root, "generated", "internal_users.yml"), users, { mode: 0o600 });

const dashboardTemplate = readFileSync(path.join(root, "config", "wazuh_dashboard", "wazuh.template.yml"), "utf8");
const dashboard = dashboardTemplate.replace("__WAZUH_API_PASSWORD__", yamlDoubleQuoted(process.env.WAZUH_API_PASSWORD));
writeFileSync(path.join(root, "generated", "wazuh.yml"), dashboard, { mode: 0o600 });

function yamlDoubleQuoted(value) {
  return JSON.stringify(String(value)).slice(1, -1);
}
