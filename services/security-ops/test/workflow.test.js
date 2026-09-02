import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { KnowledgeRepository } from "../src/knowledge-repository.js";
import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

const EVIDENCE = ["认证失败与成功日志", "来源地址与设备身份", "账号状态和授权变更记录"];
const FACTS = {
  auth_failures: 12,
  window_seconds: 180,
  distinct_accounts: 4,
  authorization_valid: false
};

function approvedKnowledge() {
  return {
    knowledgeId: "kb-vehicle_platform-brute_force",
    domainId: "vehicle_platform",
    attackTypeId: "brute_force",
    aliases: ["口令爆破", "密码猜测"],
    applicability: "direct",
    evidenceRequired: EVIDENCE,
    evidencePolicy: { kind: "minimum_independent_evidence", minimumIndependentEvidence: 2, statisticalThreshold: false },
    executableRule: {
      version: "1.0",
      requiredFacts: ["data.auth_failures", "data.window_seconds", "data.distinct_accounts"],
      confirmWhen: {
        all: [
          { predicateId: "failure-burst", path: "data.auth_failures", op: "gte", value: 8 },
          { predicateId: "short-window", path: "data.window_seconds", op: "lte", value: 300 }
        ],
        any: [{ predicateId: "account-spray", path: "data.distinct_accounts", op: "gte", value: 3 }],
        minimumAny: 1
      },
      excludeWhen: {
        any: [{ predicateId: "approved-change", path: "data.authorization_valid", op: "equals", value: true }]
      },
      thresholdBasis: {
        sourceIds: ["src-wazuh-reviewed-ticket-history"],
        statement: "复核记录确认的五分钟认证失败聚集边界。"
      }
    },
    wazuhMapping: { wazuhObservability: "full", additionalTelemetryRequired: [] },
    reviewStatus: "approved",
    reviewedBy: "security-operations-owner",
    reviewedAt: "2026-09-01T00:00:00.000Z",
    ticketRequired: true,
    autoCloseAllowed: false
  };
}

function fixture() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "security-ops-workflow-"));
  let sequence = 0;
  const now = () => new Date("2026-09-01T00:00:00.000Z");
  const store = new SecurityOpsStore({
    databasePath: path.join(directory, "triage.db"),
    now,
    idFactory: () => `id-${++sequence}`
  });
  const service = new SecurityOpsService({
    store,
    knowledgeRepository: new KnowledgeRepository([approvedKnowledge()]),
    now,
    eventIdFactory: () => "event-generated"
  });
  service.ingestAlertEvent({
    eventId: "event-vehicle-1",
    wazuhAlertId: "wazuh-9001",
    correlationId: "wazuh-9001",
    occurredAt: "2026-09-01T00:00:00.000Z",
    alertJson: {
      rule: { id: "5710", level: 10 },
      agent: { id: "001", name: "vehicle-platform-gateway" },
      data: { srcip: "198.51.100.18", dstuser: "platform-admin", ...FACTS }
    }
  });
  return {
    store,
    service,
    close() {
      store.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

test("SecurityOps completes a trace with an authoritative decision, ticket and Feishu outbox", () => {
  const context = fixture();
  try {
    const claim = context.service.claimAlert({ eventId: "event-vehicle-1", schedulerRunId: "scheduler-1", sandboxId: "sandbox-1" });
    const alert = context.service.getAlertContext({ eventId: "event-vehicle-1", claimToken: claim.claimToken });
    assert.equal(alert.wazuhAlertId, "wazuh-9001");
    const enrichment = context.service.enrichAlert({ traceId: claim.traceId, claimToken: claim.claimToken });
    const policyContext = {
      ...enrichment.context,
      observedEvidence: EVIDENCE.slice(0, 2),
      evidenceRefs: enrichment.evidenceRefs,
      authorizationRecord: false
    };
    const matches = context.service.matchKnowledge({
      traceId: claim.traceId,
      domainId: "vehicle_platform",
      attackTypeId: "brute_force",
      context: policyContext,
      claimToken: claim.claimToken
    });
    assert.equal(matches.matches.length, 1);
    assert.deepEqual(matches.matches[0].missingEvidence, []);
    assert.equal(matches.matches[0].evaluation.outcome, "confirmed");

    const policy = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: policyContext,
      knowledgeIds: matches.matches.map((match) => match.knowledgeId),
      claimToken: claim.claimToken
    });
    assert.equal(policy.action, "escalate_with_manual_review");
    assert.equal(policy.ticketRequired, true);
    assert.equal(policy.autoCloseAllowed, false);
    assert.equal(policy.evaluation[0].outcome, "confirmed");

    const result = context.service.recordTriageResult({
      traceId: claim.traceId,
      narrative: "认证失败、来源身份和后续成功登录形成一致证据链，需人工复核。",
      claimToken: claim.claimToken
    });
    assert.equal(result.action, policy.action);
    const ticket = context.service.createManualTicket({ traceId: claim.traceId, resultId: result.resultId, claimToken: claim.claimToken });
    assert.equal(ticket.status, "open");
    const delivery = context.service.queueFeishuNotification({ traceId: claim.traceId, ticketId: ticket.ticketId, claimToken: claim.claimToken });
    assert.equal(delivery.status, "pending");
    assert.equal(delivery.payload.msg_type, "interactive");
    const terminal = context.service.finalizeTriage({ traceId: claim.traceId, claimToken: claim.claimToken });
    assert.equal(terminal.state, "completed");

    const trace = context.service.getTriageTrace({ traceId: claim.traceId });
    assert.equal(trace.wazuhAlertId, "wazuh-9001");
    assert.equal(trace.schedulerRunId, "scheduler-1");
    assert.equal(trace.sandboxId, "sandbox-1");
    assert.equal(trace.result.resultId, result.resultId);
    assert.equal(trace.ticket.ticketId, ticket.ticketId);
    assert.equal(trace.delivery.deliveryId, delivery.deliveryId);
    assert.equal(trace.policy.decisionToken, undefined);
    assert.ok(trace.steps.length >= 8);
  } finally {
    context.close();
  }
});

test("business writes are idempotent across Agent retries", () => {
  const context = fixture();
  try {
    const firstClaim = context.service.claimAlert({ eventId: "event-vehicle-1", schedulerRunId: "scheduler-1", sandboxId: "sandbox-1" });
    const secondClaim = context.service.claimAlert({ eventId: "event-vehicle-1", schedulerRunId: "scheduler-retry", sandboxId: "sandbox-retry" });
    assert.equal(secondClaim.traceId, firstClaim.traceId);
    assert.equal(secondClaim.duplicate, true);
    assert.equal(secondClaim.status, "busy");
    const enrichment = context.service.enrichAlert({ traceId: firstClaim.traceId, claimToken: firstClaim.claimToken });
    const policy = context.service.evaluatePolicy({
      traceId: firstClaim.traceId,
      context: { data: FACTS, observedEvidence: EVIDENCE, evidenceRefs: enrichment.evidenceRefs },
      knowledgeIds: ["kb-vehicle_platform-brute_force"],
      claimToken: firstClaim.claimToken
    });
    const duplicatePolicy = context.service.evaluatePolicy({
      traceId: firstClaim.traceId,
      context: { data: { ...FACTS, auth_failures: 1 }, observedEvidence: EVIDENCE, evidenceRefs: enrichment.evidenceRefs },
      knowledgeIds: ["kb-vehicle_platform-brute_force"],
      claimToken: firstClaim.claimToken
    });
    assert.equal(duplicatePolicy.duplicate, true);
    assert.equal(duplicatePolicy.action, policy.action);
    assert.equal(duplicatePolicy.evaluation[0].outcome, "confirmed");
    const result = context.service.recordTriageResult({ traceId: firstClaim.traceId, narrative: "需要人工复核。", claimToken: firstClaim.claimToken });
    const duplicateResult = context.service.recordTriageResult({ traceId: firstClaim.traceId, narrative: "重试说明不会覆盖首次记录。", claimToken: firstClaim.claimToken });
    assert.equal(duplicateResult.resultId, result.resultId);
    assert.equal(duplicateResult.duplicate, true);
    const ticket = context.service.createManualTicket({ traceId: firstClaim.traceId, resultId: result.resultId, claimToken: firstClaim.claimToken });
    const duplicateTicket = context.service.createManualTicket({ traceId: firstClaim.traceId, resultId: result.resultId, claimToken: firstClaim.claimToken });
    assert.equal(duplicateTicket.ticketId, ticket.ticketId);
    const delivery = context.service.queueFeishuNotification({ traceId: firstClaim.traceId, ticketId: ticket.ticketId, claimToken: firstClaim.claimToken });
    const duplicateDelivery = context.service.queueFeishuNotification({ traceId: firstClaim.traceId, ticketId: ticket.ticketId, claimToken: firstClaim.claimToken });
    assert.equal(duplicateDelivery.deliveryId, delivery.deliveryId);
  } finally {
    context.close();
  }
});

test("missing evidence and untrusted authorization flags never produce automatic closure", () => {
  const context = fixture();
  try {
    const claim = context.service.claimAlert({ eventId: "event-vehicle-1" });
    const missing = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: { data: { auth_failures: 12, window_seconds: 180 }, observedEvidence: EVIDENCE.slice(0, 1), evidenceRefs: ["wazuh-alert:wazuh-9001"] },
      knowledgeIds: ["kb-vehicle_platform-brute_force"],
      claimToken: claim.claimToken
    });
    assert.equal(missing.action, "request_additional_evidence");
    assert.equal(missing.autoCloseAllowed, false);
  } finally {
    context.close();
  }

  const authorized = fixture();
  try {
    const claim = authorized.service.claimAlert({ eventId: "event-vehicle-1" });
    const policy = authorized.service.evaluatePolicy({
      traceId: claim.traceId,
      context: { data: FACTS, observedEvidence: EVIDENCE, evidenceRefs: ["wazuh-alert:wazuh-9001"], authorizationRecord: true },
      knowledgeIds: ["kb-vehicle_platform-brute_force"],
      claimToken: claim.claimToken
    });
    assert.equal(policy.action, "escalate_with_manual_review");
    assert.equal(policy.ticketRequired, true);
    assert.equal(policy.autoCloseAllowed, false);
  } finally {
    authorized.close();
  }
});

test("only an active unexpired scope-matching authorization record can suppress", () => {
  const context = fixture();
  try {
    context.service.putAuthorizationRecord({
      authorizationId: "auth-active",
      status: "active",
      scopeType: "asset",
      scopeValue: "vehicle-platform-gateway",
      validFrom: "2026-08-31T23:00:00Z",
      validUntil: "2026-09-01T01:00:00Z",
      evidenceRefs: ["change:approved-1"]
    });
    context.service.putAuthorizationRecord({
      authorizationId: "auth-expired",
      status: "active",
      scopeType: "asset",
      scopeValue: "vehicle-platform-gateway",
      validFrom: "2026-08-31T20:00:00Z",
      validUntil: "2026-08-31T21:00:00Z",
      evidenceRefs: ["change:expired"]
    });
    context.service.putAuthorizationRecord({
      authorizationId: "auth-revoked",
      status: "revoked",
      scopeType: "asset",
      scopeValue: "vehicle-platform-gateway",
      validFrom: "2026-08-31T23:00:00Z",
      validUntil: "2026-09-01T01:00:00Z",
      evidenceRefs: ["change:revoked"]
    });
    context.service.putAuthorizationRecord({
      authorizationId: "auth-mismatch",
      status: "active",
      scopeType: "asset",
      scopeValue: "different-asset",
      validFrom: "2026-08-31T23:00:00Z",
      validUntil: "2026-09-01T01:00:00Z",
      evidenceRefs: ["change:mismatch"]
    });

    for (const [authorizationRecordId, expectedAction] of [
      ["auth-active", "suppress_with_manual_review"],
      ["auth-expired", "escalate_with_manual_review"],
      ["auth-revoked", "escalate_with_manual_review"],
      ["auth-mismatch", "escalate_with_manual_review"],
      ["auth-missing", "escalate_with_manual_review"]
    ]) {
      const isolated = fixture();
      try {
        for (const record of context.store.database.prepare("SELECT * FROM authorization_records").all()) {
          isolated.store.database.prepare(`
            INSERT INTO authorization_records
              (authorization_id, status, scope_type, scope_value, valid_from, valid_until, evidence_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(record.authorization_id, record.status, record.scope_type, record.scope_value, record.valid_from, record.valid_until, record.evidence_json, record.created_at, record.updated_at);
        }
        const claim = isolated.service.claimAlert({ eventId: "event-vehicle-1" });
        const policy = isolated.service.evaluatePolicy({
          traceId: claim.traceId,
          context: {
            data: FACTS,
            agent: { name: "vehicle-platform-gateway" },
            observedEvidence: EVIDENCE,
            evidenceRefs: ["wazuh-alert:wazuh-9001"],
            authorizationRecord: true,
            authorizationRecordId
          },
          knowledgeIds: ["kb-vehicle_platform-brute_force"],
          claimToken: claim.claimToken
        });
        assert.equal(policy.action, expectedAction, authorizationRecordId);
        if (authorizationRecordId === "auth-active") {
          assert.ok(policy.evidenceRefs.includes("change:approved-1"));
        }
      } finally {
        isolated.close();
      }
    }
  } finally {
    context.close();
  }
});

test("RecordTriageResult ignores caller decision fields and uses the stored policy", () => {
  const context = fixture();
  try {
    const claim = context.service.claimAlert({ eventId: "event-vehicle-1" });
    const policy = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: { data: FACTS, observedEvidence: EVIDENCE, evidenceRefs: ["wazuh-alert:wazuh-9001"] },
      knowledgeIds: ["kb-vehicle_platform-brute_force"],
      claimToken: claim.claimToken
    });
    const result = context.service.recordTriageResult({
      traceId: claim.traceId,
      decision: "suppress",
      action: "auto_close",
      narrative: "调用方字段不得覆盖服务端策略。",
      claimToken: claim.claimToken
    });
    assert.equal(result.decision, policy.decision);
    assert.equal(result.action, policy.action);
  } finally {
    context.close();
  }
});
