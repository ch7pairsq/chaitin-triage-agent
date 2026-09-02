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

test("retries only timeout, HTTP 429 and HTTP 5xx within the seventeen-second budget", async () => {
  for (const [error, expectedAttempts] of [
    [new WazuhConnectorError("DEADLINE_EXCEEDED", "timeout"), 2],
    [new WazuhConnectorError("UNAVAILABLE", "limited", { httpStatus: 429 }), 2],
    [new WazuhConnectorError("UNAVAILABLE", "backend", { httpStatus: 503 }), 2],
    [new WazuhConnectorError("INVALID_ARGUMENT", "bad request", { httpStatus: 400 }), 1],
    [new WazuhConnectorError("UNAUTHENTICATED", "denied", { httpStatus: 401 }), 1],
    [new WazuhConnectorError("UNAVAILABLE", "network"), 1]
  ]) {
    let attempts = 0;
    const delays = [];
    const timeouts = [];
    const client = new WazuhIndexerClient({
      indexerUrl: "https://wazuh.indexer:9200",
      username: "reader",
      password: "strong-password",
      requestTimeoutMs: 8000,
      requestImpl: async ({ timeoutMs }) => {
        attempts += 1;
        timeouts.push(timeoutMs);
        throw error;
      },
      sleepImpl: async (delayMs) => delays.push(delayMs),
      random: () => 0
    });
    await assert.rejects(() => client.listAlerts(), (actual) => actual === error);
    assert.equal(attempts, expectedAttempts, `${error.code}:${error.details.httpStatus ?? "none"}`);
    assert.ok(timeouts.every((value) => value === 8000));
    assert.ok(timeouts.reduce((total, value) => total + value, 0) + delays.reduce((total, value) => total + value, 0) < 17_000);
  }
});

test("failed retries do not advance the last successful query marker", async () => {
  let fail = false;
  const client = new WazuhIndexerClient({
    indexerUrl: "https://wazuh.indexer:9200",
    username: "reader",
    password: "strong-password",
    now: () => new Date("2026-09-02T01:10:00.000Z"),
    requestImpl: async () => {
      if (fail) throw new WazuhConnectorError("DEADLINE_EXCEEDED", "timeout");
      return { hits: { hits: [] } };
    },
    sleepImpl: async () => {}
  });
  await client.listAlerts();
  assert.equal(client.lastSuccessfulQueryAt, "2026-09-02T01:10:00.000Z");
  fail = true;
  await assert.rejects(() => client.listAlerts());
  assert.equal(client.lastSuccessfulQueryAt, "2026-09-02T01:10:00.000Z");
});

test("default query includes triage_input and does not impose an unsupported level threshold", async () => {
  let capturedBody;
  const client = new WazuhIndexerClient({
    indexerUrl: "https://wazuh.indexer:9200",
    username: "reader",
    password: "strong-password",
    requestImpl: async ({ body }) => {
      capturedBody = JSON.parse(body);
      return { hits: { hits: [] } };
    }
  });
  await client.listAlerts();
  assert.deepEqual(capturedBody.query.bool.filter[1], { range: { "rule.level": { gte: 0 } } });
  assert.deepEqual(capturedBody.query.bool.filter[2], { term: { "rule.groups": "triage_input" } });
});
