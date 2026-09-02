import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { BUSINESS_REASONS, SecurityOpsError } from "../src/errors.js";
import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-leases-"));
  let currentMs = Date.parse("2026-09-01T00:00:00.000Z");
  let id = 0;
  let token = 0;
  const now = () => new Date(currentMs);
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now,
    idFactory: () => `id-${++id}`,
    tokenFactory: () => Buffer.alloc(32, ++token).toString("base64url"),
    maxActiveTriage: 2,
    claimLeaseMs: 180_000
  });
  const service = new SecurityOpsService({ store, now });
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

function ingest(service, suffix) {
  return service.ingestAlertEvent({
    eventId: `event-${suffix}`,
    wazuhAlertId: `wazuh-${suffix}`,
    correlationId: `wazuh-${suffix}`,
    occurredAt: "2026-09-01T00:00:00Z",
    alertJson: { rule: { id: "5710" }, agent: { name: `asset-${suffix}` } }
  });
}

test("claim returns a secret lease while duplicate and terminal claims do not", () => {
  const context = fixture();
  try {
    ingest(context.service, "1");
    const claim = context.service.claimAlert({ eventId: "event-1", schedulerRunId: "run-1" });
    assert.equal(claim.status, "acquired");
    assert.equal(claim.attempt, 1);
    assert.match(claim.claimToken, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(claim.leaseUntil, "2026-09-01T00:03:00.000Z");
    const stored = context.store.database.prepare("SELECT claim_token_hash FROM triage_runs WHERE trace_id = ?").get(claim.traceId);
    assert.notEqual(stored.claim_token_hash, claim.claimToken);

    const duplicate = context.service.claimAlert({ eventId: "event-1", schedulerRunId: "run-2" });
    assert.equal(duplicate.status, "busy");
    assert.equal(duplicate.claimToken, undefined);

    context.store.database.prepare("UPDATE triage_runs SET state = 'completed' WHERE trace_id = ?").run(claim.traceId);
    context.store.database.prepare("UPDATE ingress_events SET status = 'completed' WHERE event_id = ?").run("event-1");
    assert.equal(context.service.claimAlert({ eventId: "event-1" }).status, "completed");
  } finally {
    context.close();
  }
});

test("workflow calls validate and refresh the claim lease", () => {
  const context = fixture();
  try {
    ingest(context.service, "1");
    const claim = context.service.claimAlert({ eventId: "event-1" });
    context.advance(30_000);
    context.service.getAlertContext({ eventId: "event-1", claimToken: claim.claimToken });
    let run = context.store.database.prepare("SELECT lease_until, last_activity_at FROM triage_runs WHERE trace_id = ?").get(claim.traceId);
    assert.equal(run.lease_until, "2026-09-01T00:03:30.000Z");
    assert.equal(run.last_activity_at, "2026-09-01T00:00:30.000Z");

    assert.throws(
      () => context.service.enrichAlert({ traceId: claim.traceId, claimToken: "B".repeat(43) }),
      (error) => error instanceof SecurityOpsError && error.details.reason === BUSINESS_REASONS.CLAIM_FENCED
    );

    context.advance(181_000);
    assert.throws(
      () => context.service.enrichAlert({ traceId: claim.traceId, claimToken: claim.claimToken }),
      (error) => error instanceof SecurityOpsError && error.details.reason === BUSINESS_REASONS.LEASE_EXPIRED
    );
  } finally {
    context.close();
  }
});

test("a rotated token fences the previous Agent", () => {
  const context = fixture();
  try {
    ingest(context.service, "1");
    const claim = context.service.claimAlert({ eventId: "event-1" });
    const replacement = "C".repeat(43);
    const replacementHash = createHash("sha256").update(replacement).digest("hex");
    context.store.database.prepare("UPDATE triage_runs SET claim_token_hash = ? WHERE trace_id = ?")
      .run(replacementHash, claim.traceId);
    assert.throws(
      () => context.service.enrichAlert({ traceId: claim.traceId, claimToken: claim.claimToken }),
      (error) => error instanceof SecurityOpsError && error.details.reason === BUSINESS_REASONS.CLAIM_FENCED
    );
    assert.equal(context.service.enrichAlert({ traceId: claim.traceId, claimToken: replacement }).traceId, claim.traceId);
  } finally {
    context.close();
  }
});

test("SecurityOps enforces a global maximum of two active triage runs", () => {
  const context = fixture();
  try {
    ingest(context.service, "1");
    ingest(context.service, "2");
    ingest(context.service, "3");
    assert.equal(context.service.claimAlert({ eventId: "event-1" }).status, "acquired");
    assert.equal(context.service.claimAlert({ eventId: "event-2" }).status, "acquired");
    const third = context.service.claimAlert({ eventId: "event-3" });
    assert.equal(third.status, "busy");
    assert.equal(third.traceId, undefined);
  } finally {
    context.close();
  }
});
