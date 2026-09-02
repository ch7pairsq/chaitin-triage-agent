import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import { WazuhConnectorError, WazuhIndexerClient } from "../src/client.js";

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("queries the real Wazuh alerts index contract and returns minimized records", async () => {
  await withServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      assert.equal(req.method, "POST");
      assert.equal(req.url, "/wazuh-alerts-*/_search");
      assert.equal(req.headers.authorization, `Basic ${Buffer.from("reader:strong-password").toString("base64")}`);
      const query = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      assert.equal(query.size, 10);
      assert.deepEqual(query.query.bool.filter[1], { range: { "rule.level": { gte: 7 } } });
      assert.deepEqual(query.query.bool.filter[2], { term: { "rule.groups": "triage_input" } });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ hits: { hits: [{ _id: "wazuh-alert-42", _source: {
        timestamp: "2026-09-02T01:02:03.000Z",
        rule: { id: "100001", level: 9, description: "vehicle gateway authentication failures" },
        data: { domain: "vehicle_networking_platform", attackType: "brute_force" }
      } }] } }));
    });
  }, async (indexerUrl) => {
    const client = new WazuhIndexerClient({
      indexerUrl,
      username: "reader",
      password: "strong-password",
      minimumRuleLevel: 7,
      requiredRuleGroup: "triage_input",
      now: () => new Date("2026-09-02T01:10:00.000Z")
    });
    const result = await client.listAlerts({ lookbackSeconds: 600, limit: 10 });
    assert.equal(result.alerts.length, 1);
    assert.equal(result.alerts[0].alertId, "wazuh-alert-42");
    assert.equal(result.alerts[0].correlationId, "wazuh-alert-42");
    assert.match(result.alerts[0].alertJson, /vehicle gateway/);
  });
});

test("rejects backend authentication failures without leaking response bodies", async () => {
  await withServer((_req, res) => {
    res.writeHead(401, { "content-type": "text/plain" });
    res.end("sensitive backend detail");
  }, async (indexerUrl) => {
    const client = new WazuhIndexerClient({ indexerUrl, username: "reader", password: "strong-password" });
    await assert.rejects(
      () => client.listAlerts(),
      (error) => error instanceof WazuhConnectorError && error.code === "UNAUTHENTICATED" && !error.message.includes("sensitive")
    );
  });
});

test("rejects unsafe index paths and malformed request bounds", async () => {
  assert.throws(
    () => new WazuhIndexerClient({ indexerUrl: "http://localhost:9200", username: "reader", password: "strong-password", indexPattern: "../secret" }),
    /index_pattern is invalid/
  );
  assert.throws(
    () => new WazuhIndexerClient({ indexerUrl: "http://localhost:9200", username: "reader", password: "strong-password", requiredRuleGroup: "bad/group" }),
    /required_rule_group is invalid/
  );
  const client = new WazuhIndexerClient({ indexerUrl: "http://localhost:9200", username: "reader", password: "strong-password" });
  await assert.rejects(() => client.listAlerts({ lookbackSeconds: 1 }), /lookbackSeconds/);
});
