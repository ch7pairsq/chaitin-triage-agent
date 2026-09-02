import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { SecurityOpsError } from "../src/errors.js";
import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-"));
  let id = 0;
  const now = () => new Date("2026-09-01T00:00:00.000Z");
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now,
    idFactory: () => `delivery-${++id}`
  });
  const service = new SecurityOpsService({
    store,
    now,
    eventIdFactory: () => "event-generated-1"
  });
  return {
    directory,
    store,
    service,
    close() {
      store.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

function wazuhAlert(overrides = {}) {
  return {
    eventId: "event-1",
    wazuhAlertId: "174001",
    correlationId: "174001",
    occurredAt: "2026-09-01T08:00:00+08:00",
    alertJson: {
      rule: { id: "5710", level: 10, description: "Multiple authentication failures" },
      agent: { id: "001", name: "vehicle-platform-gateway" },
      data: { srcip: "198.51.100.18", dstuser: "platform-admin" }
    },
    ...overrides
  };
}

test("IngestAlertEvent writes the alert and trigger outbox atomically", () => {
  const context = fixture();
  try {
    const result = context.service.ingestAlertEvent(wazuhAlert());
    assert.deepEqual(result, {
      eventId: "event-1",
      correlationId: "174001",
      wazuhAlertId: "174001",
      status: "pending",
      duplicate: false,
      receivedAt: "2026-09-01T00:00:00.000Z"
    });
    assert.deepEqual(context.store.inspectCounts(), { ingressEvents: 1, triggerOutbox: 1 });
    assert.equal(context.service.listPendingAlerts({ limit: 10 }).alerts.length, 1);
    assert.equal(context.store.getAlertContext("event-1").alert.rule.id, "5710");
  } finally {
    context.close();
  }
});

test("duplicate Wazuh alerts are idempotent and do not enqueue twice", () => {
  const context = fixture();
  try {
    context.service.ingestAlertEvent(wazuhAlert());
    const duplicate = context.service.ingestAlertEvent(wazuhAlert({ eventId: "event-retry" }));
    assert.equal(duplicate.eventId, "event-1");
    assert.equal(duplicate.duplicate, true);
    assert.deepEqual(context.store.inspectCounts(), { ingressEvents: 1, triggerOutbox: 1 });
  } finally {
    context.close();
  }
});

test("an unfinished claimed alert remains visible but cannot be claimed concurrently", () => {
  const context = fixture();
  try {
    context.service.ingestAlertEvent(wazuhAlert());
    const claim = context.service.claimAlert({ eventId: "event-1", schedulerRunId: "event-run", sandboxId: "sandbox-1" });
    assert.equal(claim.status, "acquired");
    const resumable = context.service.listPendingAlerts({ limit: 10 }).alerts;
    assert.equal(resumable.length, 1);
    assert.equal(resumable[0].eventId, "event-1");
    assert.equal(resumable[0].status, "processing");
    const duplicate = context.service.claimAlert({ eventId: "event-1", schedulerRunId: "retry-run" });
    assert.equal(duplicate.traceId, claim.traceId);
    assert.equal(duplicate.status, "busy");
  } finally {
    context.close();
  }
});

test("enrichment returns only Wazuh-provided classification and evidence fields", () => {
  const context = fixture();
  try {
    context.service.ingestAlertEvent(wazuhAlert({
      alertJson: {
        rule: { id: "100501", level: 10 },
        data: {
          domain_id: "vehicle_platform",
          attack_type_id: "brute_force",
          observed_evidence: ["认证失败与成功日志", "来源地址与设备身份"]
        }
      }
    }));
    const claim = context.service.claimAlert({ eventId: "event-1" });
    const enrichment = context.service.enrichAlert({ traceId: claim.traceId, claimToken: claim.claimToken });
    assert.equal(enrichment.domainId, "vehicle_platform");
    assert.equal(enrichment.attackTypeId, "brute_force");
    assert.deepEqual(enrichment.context.observedEvidence, ["认证失败与成功日志", "来源地址与设备身份"]);
  } finally {
    context.close();
  }
});

test("missing Wazuh classification is returned as a server-owned manual fallback", () => {
  const context = fixture();
  try {
    context.service.ingestAlertEvent(wazuhAlert());
    const claim = context.service.claimAlert({ eventId: "event-1" });
    const enrichment = context.service.enrichAlert({ traceId: claim.traceId, claimToken: claim.claimToken });
    assert.equal(enrichment.domainId, "unclassified");
    assert.equal(enrichment.attackTypeId, "other_attack");
    assert.deepEqual(enrichment.context.observedEvidence, []);
  } finally {
    context.close();
  }
});

test("one event id cannot be rebound to another Wazuh alert", () => {
  const context = fixture();
  try {
    context.service.ingestAlertEvent(wazuhAlert());
    assert.throws(
      () => context.service.ingestAlertEvent(wazuhAlert({ wazuhAlertId: "174002", correlationId: "174002" })),
      (error) => error instanceof SecurityOpsError && error.code === "FAILED_PRECONDITION"
    );
    assert.deepEqual(context.store.inspectCounts(), { ingressEvents: 1, triggerOutbox: 1 });
  } finally {
    context.close();
  }
});

test("runtime validation rejects malformed Wazuh requests", () => {
  const context = fixture();
  try {
    assert.throws(
      () => context.service.ingestAlertEvent(wazuhAlert({ wazuhAlertId: "bad id with spaces" })),
      (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
    );
    assert.throws(
      () => context.service.ingestAlertEvent(wazuhAlert({ alertJson: "not-json" })),
      (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
    );
    assert.deepEqual(context.store.inspectCounts(), { ingressEvents: 0, triggerOutbox: 0 });
  } finally {
    context.close();
  }
});

test("runtime exposes all OctoBus unary methods through the SDK CLI", () => {
  const testDirectory = path.dirname(fileURLToPath(import.meta.url));
  const runtimePath = path.resolve(testDirectory, "../src/runtime.js");
  const result = spawnSync(process.execPath, [runtimePath, "--help"], {
    encoding: "utf8",
    env: { ...process.env, NODE_NO_WARNINGS: "1" }
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /ingest-alert-event/);
  assert.match(result.stdout, /get-triage-trace/);
  assert.match(result.stdout, /queue-feishu-notification/);
  assert.equal(result.stderr, "");
});
