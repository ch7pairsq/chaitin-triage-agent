import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { AgentWebhookClient, DeliveryError, FeishuWebhookClient, OutboxWorker } from "../src/outbox.js";
import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

test("agent webhook publishes only opaque event identifiers with idempotency headers", async () => {
  let captured;
  const client = new AgentWebhookClient({
    url: "http://agent-compose:7410/api/webhooks/webhook.wazuh.alert",
    token: "internal-source-token-1234567890",
    fetchImpl: async (url, request) => {
      captured = { url, request };
      return { status: 202, json: async () => ({ accepted: true, event_id: "evt-agent-1" }) };
    }
  });
  const result = await client.send({
    idempotencyKey: "event-1",
    payload: { eventId: "event-1", correlationId: "wazuh-1", unexpected: "must-not-leave" }
  });
  assert.deepEqual(result, { accepted: true, eventId: "evt-agent-1" });
  assert.equal(captured.request.headers["idempotency-key"], "event-1");
  assert.equal(captured.request.headers["x-correlation-id"], "wazuh-1");
  assert.deepEqual(JSON.parse(captured.request.body), { eventId: "event-1", correlationId: "wazuh-1" });
  assert.doesNotMatch(captured.request.body, /unexpected|internal-source-token/);
});

test("Feishu webhook uses the official endpoint and adds a request signature", async () => {
  let captured;
  const client = new FeishuWebhookClient({
    url: "https://open.feishu.cn/open-apis/bot/v2/hook/test-hook-id",
    secret: "feishu-signing-secret",
    now: () => new Date("2026-09-01T00:00:00.000Z"),
    fetchImpl: async (url, request) => {
      captured = { url, request };
      return { ok: true, status: 200, json: async () => ({ code: 0 }) };
    }
  });
  await client.send({ payload: { msg_type: "text", content: { text: "人工工单已创建" } } });
  const body = JSON.parse(captured.request.body);
  assert.equal(body.timestamp, "1788220800");
  assert.ok(body.sign);
  assert.equal(body.msg_type, "text");
  assert.doesNotMatch(captured.request.body, /feishu-signing-secret/);
  assert.throws(
    () => new FeishuWebhookClient({ url: "https://example.com/open-apis/bot/v2/hook/test" }),
    /official custom bot endpoint/
  );
});

test("trigger outbox is delivered once and not reclaimed", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-trigger-"));
  let sequence = 0;
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now: () => new Date("2026-09-01T00:00:00.000Z"),
    idFactory: () => `id-${++sequence}`
  });
  try {
    const service = new SecurityOpsService({ store, eventIdFactory: () => "event-1" });
    service.ingestAlertEvent({
      eventId: "event-1",
      wazuhAlertId: "wazuh-1",
      occurredAt: "2026-09-01T00:00:00.000Z",
      alertJson: { rule: { id: "5710" } }
    });
    const worker = new OutboxWorker({
      store,
      agentWebhookClient: { send: async () => ({ accepted: true }) },
      feishuWebhookClient: { send: async () => ({ delivered: true }) }
    });
    assert.deepEqual(await worker.runOnce(), { triggerDelivered: 1, triggerFailed: 0, feishuDelivered: 0, feishuFailed: 0 });
    assert.deepEqual(await worker.runOnce(), { triggerDelivered: 0, triggerFailed: 0, feishuDelivered: 0, feishuFailed: 0 });
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("outbox worker preserves retryable failures for compensation", async () => {
  const calls = [];
  const logs = [];
  const trigger = { deliveryId: "trigger-1", attempts: 0 };
  const delivery = { deliveryId: "feishu-1", attempts: 0 };
  const store = {
    claimTriggerDeliveries: () => [trigger],
    claimFeishuDeliveries: () => [delivery],
    markTriggerDelivered: () => calls.push("trigger-delivered"),
    markFeishuDelivered: () => calls.push("feishu-delivered"),
    markTriggerFailed: (_entry, options) => {
      calls.push(["trigger-failed", options.retryable]);
      return { status: "pending", attempts: 1, nextAttemptAt: "2026-09-01T00:00:30.000Z" };
    },
    markFeishuFailed: (_entry, options) => {
      calls.push(["feishu-failed", options.retryable]);
      return { status: "manual", attempts: 1, nextAttemptAt: null };
    }
  };
  const worker = new OutboxWorker({
    store,
    agentWebhookClient: { send: async () => { throw new DeliveryError("temporary", { retryable: true }); } },
    feishuWebhookClient: { send: async () => { throw new DeliveryError("bad request", { retryable: false }); } },
    logger: { error: (entry) => logs.push(entry) }
  });
  assert.deepEqual(await worker.runOnce(), { triggerDelivered: 0, triggerFailed: 1, feishuDelivered: 0, feishuFailed: 1 });
  assert.deepEqual(calls, [["trigger-failed", true], ["feishu-failed", false]]);
  assert.deepEqual(logs.map((entry) => ({
    worker: entry.worker,
    attempt: entry.attempt,
    nextStatus: entry.nextStatus,
    nextAttemptAt: entry.nextAttemptAt
  })), [
    { worker: "trigger_outbox", attempt: 1, nextStatus: "pending", nextAttemptAt: "2026-09-01T00:00:30.000Z" },
    { worker: "delivery_outbox", attempt: 1, nextStatus: "manual", nextAttemptAt: null }
  ]);
});

test("delivery recovery includes failed agent triggers and respects manual opt-in", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-recover-"));
  let sequence = 0;
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now: () => new Date("2026-09-01T00:00:00.000Z"),
    idFactory: () => `id-${++sequence}`
  });
  try {
    const service = new SecurityOpsService({ store, eventIdFactory: () => "event-1" });
    service.ingestAlertEvent({
      eventId: "event-1",
      wazuhAlertId: "wazuh-1",
      occurredAt: "2026-09-01T00:00:00.000Z",
      alertJson: { rule: { id: "5710" } }
    });
    const [trigger] = store.claimTriggerDeliveries({ limit: 1 });
    store.markTriggerFailed(trigger, { error: "permanent failure", retryable: false });
    assert.deepEqual(service.recoverDelivery({ limit: 10, includeManual: false }), { recovered: 0, pending: 0, manual: 1 });
    assert.deepEqual(service.recoverDelivery({ limit: 10, includeManual: true }), { recovered: 1, pending: 1, manual: 0 });
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("trigger dispatch reserves only the two available triage slots", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-slots-"));
  let sequence = 0;
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now: () => new Date("2026-09-01T00:00:00.000Z"),
    idFactory: () => `id-${++sequence}`
  });
  try {
    const service = new SecurityOpsService({ store });
    for (let index = 1; index <= 3; index += 1) {
      service.ingestAlertEvent({
        eventId: `event-${index}`,
        wazuhAlertId: `wazuh-${index}`,
        occurredAt: "2026-09-01T00:00:00Z",
        alertJson: { rule: { id: "5710" } }
      });
    }
    const firstBatch = store.claimTriggerDeliveries({ limit: 20 });
    assert.equal(firstBatch.length, 2);
    assert.equal(store.database.prepare("SELECT COUNT(*) AS count FROM ingress_events WHERE status = 'claimed'").get().count, 2);
    assert.equal(store.claimTriggerDeliveries({ limit: 20 }).length, 0);

    store.markTriggerFailed(firstBatch[0], { error: "temporary", retryable: true });
    assert.equal(store.database.prepare("SELECT COUNT(*) AS count FROM ingress_events WHERE status = 'claimed'").get().count, 1);
  } finally {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
