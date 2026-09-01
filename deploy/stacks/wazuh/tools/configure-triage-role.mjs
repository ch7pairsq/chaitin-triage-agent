#!/usr/bin/env node
const baseUrl = String(process.env.WAZUH_INDEXER_URL ?? "").replace(/\/$/, "");
const password = String(process.env.WAZUH_INDEXER_ADMIN_PASSWORD ?? "");
if (baseUrl !== "https://wazuh.indexer:9200") throw new Error("unexpected WAZUH_INDEXER_URL");
if (password.length < 12) throw new Error("WAZUH_INDEXER_ADMIN_PASSWORD is missing");

const authorization = `Basic ${Buffer.from(`admin:${password}`).toString("base64")}`;
const role = {
  cluster_permissions: ["cluster_composite_ops_ro"],
  index_permissions: [{ index_patterns: ["wazuh-alerts-*"], allowed_actions: ["read"] }],
  tenant_permissions: []
};
const mapping = { backend_roles: [], hosts: [], users: ["triage_reader"] };

async function put(path, body) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "PUT",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}: ${text.slice(0, 512)}`);
}

for (let attempt = 1; attempt <= 60; attempt += 1) {
  try {
    await put("/_plugins/_security/api/roles/triage_alert_reader", role);
    await put("/_plugins/_security/api/rolesmapping/triage_alert_reader", mapping);
    console.log("triage_alert_reader role configured");
    process.exit(0);
  } catch (error) {
    if (attempt === 60) throw error;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}
