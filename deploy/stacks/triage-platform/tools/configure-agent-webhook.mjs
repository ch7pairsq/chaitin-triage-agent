#!/usr/bin/env node
import fs from "node:fs";

const token = fs.readFileSync(process.env.AGENT_WEBHOOK_TOKEN_FILE ?? "/run/secrets/agent-webhook-token", "utf8").trim();
if (!token) throw new Error("agent webhook token is empty");

const response = await fetch("http://agent-compose:7410/api/webhook-sources/wazuh", {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    name: "Wazuh Alerts",
    enabled: true,
    provider: "generic",
    topic_prefix: "webhook.wazuh.",
    token,
    token_header: "Authorization",
    signature_type: "none",
    clear_signature: true,
    body_limit_bytes: 16384
  }),
  signal: AbortSignal.timeout(10000)
});

const body = await response.text();
if (!response.ok) throw new Error(`agent-compose webhook source update failed: HTTP ${response.status}: ${body.slice(0, 512)}`);
const result = JSON.parse(body);
if (
  result?.source?.id !== "wazuh"
  || result?.source?.enabled !== true
  || result?.source?.provider !== "generic"
  || result?.source?.topic_prefix !== "webhook.wazuh."
  || result?.source?.signature_type !== "none"
  || result?.source?.body_limit_bytes !== 16384
  || !result?.source?.has_token
) {
  throw new Error("agent-compose returned an unexpected webhook source");
}
console.log(JSON.stringify(result));
