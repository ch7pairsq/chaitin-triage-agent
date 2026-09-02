import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-recovery-"));
  let currentMs = Date.parse("2026-09-01T00:00:00.000Z");
  let id = 0;
  let token = 0;
  const now = () => new Date(currentMs);
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now,
    idFactory: () => `id-${++id}`,
    tokenFactory: () => Buffer.alloc(32, ++token).toString("base64url")
  });
  const service = new SecurityOpsService({ store, now });
  service.ingestAlertEvent({
    eventId: "event-1",
    wazuhAlertId: "wazuh-1",
    correlationId: "wazuh-1",
    occurredAt: "2026-09-01T00:00:00Z",
    alertJson: { rule: { id: "5710" }, agent: { name: "vehicle-platform-gateway" } }
  });
  return {
    store,
    service,
    advance(ms) { currentMs += ms; },
    close() {
      store.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

test("stalled triage is requeued after three minutes with one idempotent recovery delivery", () => {
  const context = fixture();
  try {
    const initial = context.service.claimAlert({ eventId: "event-1" });
    context.advance(179_999);
    assert.deepEqual(context.service.requeueStalledAlerts({}), { scanned: 0, requeued: 0, manualized: 0, eventIds: [] });
    context.advance(1);
    assert.deepEqual(context.service.requeueStalledAlerts({}), { scanned: 1, requeued: 1, manualized: 0, eventIds: ["event-1"] });
    assert.deepEqual(context.service.requeueStalledAlerts({}), { scanned: 0, requeued: 0, manualized: 0, eventIds: [] });

    const run = context.store.database.prepare("SELECT state, attempt, claim_token_hash FROM triage_runs WHERE trace_id = ?").get(initial.traceId);
    assert.equal(run.state, "requeued");
    assert.equal(run.attempt, 2);
    assert.equal(run.claim_token_hash, null);
    const recovery = context.store.database.prepare("SELECT * FROM trigger_outbox WHERE delivery_kind = 'recovery'").get();
    assert.equal(recovery.recovery_attempt, 1);
    assert.equal(recovery.idempotency_key, "triage:event-1:recovery:1");

    const reclaimed = context.service.claimAlert({ eventId: "event-1", schedulerRunId: "recovery-run" });
    assert.equal(reclaimed.status, "acquired");
    assert.equal(reclaimed.attempt, 2);
    assert.notEqual(reclaimed.claimToken, initial.claimToken);
  } finally {
    context.close();
  }
});

test("the third stalled handling enters a traceable safe manual state", () => {
  const context = fixture();
  try {
    let claim = context.service.claimAlert({ eventId: "event-1" });
    for (let recovery = 1; recovery <= 2; recovery += 1) {
      context.advance(180_000);
      const outcome = context.service.requeueStalledAlerts({});
      assert.equal(outcome.requeued, 1);
      claim = context.service.claimAlert({ eventId: "event-1", schedulerRunId: `recovery-${recovery}` });
      assert.equal(claim.attempt, recovery + 1);
    }

    context.advance(180_000);
    const exhausted = context.service.requeueStalledAlerts({});
    assert.deepEqual(exhausted, { scanned: 1, requeued: 0, manualized: 1, eventIds: ["event-1"] });
    const trace = context.service.getTriageTrace({ traceId: claim.traceId });
    assert.equal(trace.state, "manual");
    assert.equal(trace.result.decision, "manual_review");
    assert.equal(trace.result.action, "request_additional_evidence");
    assert.ok(trace.result.evidenceRefs.length >= 2);
    assert.equal(trace.ticket.status, "open");
    assert.equal(trace.delivery.status, "pending");
    assert.equal(trace.steps.at(-1).method, "FailSafeManualization");
    assert.equal(trace.steps.some((step) => step.method === "FinalizeTriage"), false);
    assert.equal(context.service.claimAlert({ eventId: "event-1" }).status, "manual");
  } finally {
    context.close();
  }
});
