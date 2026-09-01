import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { SecurityOpsError } from "../src/errors.js";
import { KnowledgeRepository } from "../src/knowledge-repository.js";
import { SecurityOpsService } from "../src/service.js";
import { SecurityOpsStore } from "../src/store.js";

const SECRET = "security-ops-test-decision-secret-1234567890";
const EVIDENCE = ["认证失败与成功日志", "来源地址与设备身份", "账号状态和授权变更记录"];

function approvedKnowledge() {
  return {
    knowledgeId: "kb-vehicle_platform-brute_force",
    domainId: "vehicle_platform",
    attackTypeId: "brute_force",
    aliases: ["口令爆破", "密码猜测"],
    applicability: "direct",
    evidenceRequired: EVIDENCE,
    evidencePolicy: { kind: "minimum_independent_evidence", minimumIndependentEvidence: 2, statisticalThreshold: false },
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
    decisionTokenSecret: SECRET,
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
      data: { srcip: "198.51.100.18", dstuser: "platform-admin" }
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
    const alert = context.service.getAlertContext({ eventId: "event-vehicle-1" });
    assert.equal(alert.wazuhAlertId, "wazuh-9001");
    const enrichment = context.service.enrichAlert({ traceId: claim.traceId });
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
      context: policyContext
    });
    assert.equal(matches.matches.length, 1);
    assert.deepEqual(matches.matches[0].missingEvidence, [EVIDENCE[2]]);

    const policy = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: policyContext,
      knowledgeIds: matches.matches.map((match) => match.knowledgeId)
    });
    assert.equal(policy.action, "escalate_with_manual_review");
    assert.equal(policy.ticketRequired, true);
    assert.equal(policy.autoCloseAllowed, false);
    assert.ok(policy.decisionToken);

    const result = context.service.recordTriageResult({
      traceId: claim.traceId,
      decisionToken: policy.decisionToken,
      narrative: "认证失败、来源身份和后续成功登录形成一致证据链，需人工复核。"
    });
    assert.equal(result.action, policy.action);
    const ticket = context.service.createManualTicket({ traceId: claim.traceId, resultId: result.resultId });
    assert.equal(ticket.status, "open");
    const delivery = context.service.queueFeishuNotification({ traceId: claim.traceId, ticketId: ticket.ticketId });
    assert.equal(delivery.status, "pending");
    assert.equal(delivery.payload.msg_type, "interactive");
    const terminal = context.service.finalizeTriage({ traceId: claim.traceId });
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
    const enrichment = context.service.enrichAlert({ traceId: firstClaim.traceId });
    const policy = context.service.evaluatePolicy({
      traceId: firstClaim.traceId,
      context: { observedEvidence: EVIDENCE, evidenceRefs: enrichment.evidenceRefs },
      knowledgeIds: ["kb-vehicle_platform-brute_force"]
    });
    const duplicatePolicy = context.service.evaluatePolicy({
      traceId: firstClaim.traceId,
      context: { observedEvidence: EVIDENCE, evidenceRefs: enrichment.evidenceRefs },
      knowledgeIds: ["kb-vehicle_platform-brute_force"]
    });
    assert.equal(duplicatePolicy.decisionToken, policy.decisionToken);
    assert.equal(duplicatePolicy.duplicate, true);
    const result = context.service.recordTriageResult({ traceId: firstClaim.traceId, decisionToken: policy.decisionToken, narrative: "需要人工复核。" });
    const duplicateResult = context.service.recordTriageResult({ traceId: firstClaim.traceId, decisionToken: policy.decisionToken, narrative: "重试说明不会覆盖首次记录。" });
    assert.equal(duplicateResult.resultId, result.resultId);
    assert.equal(duplicateResult.duplicate, true);
    const ticket = context.service.createManualTicket({ traceId: firstClaim.traceId, resultId: result.resultId });
    const duplicateTicket = context.service.createManualTicket({ traceId: firstClaim.traceId, resultId: result.resultId });
    assert.equal(duplicateTicket.ticketId, ticket.ticketId);
    const delivery = context.service.queueFeishuNotification({ traceId: firstClaim.traceId, ticketId: ticket.ticketId });
    const duplicateDelivery = context.service.queueFeishuNotification({ traceId: firstClaim.traceId, ticketId: ticket.ticketId });
    assert.equal(duplicateDelivery.deliveryId, delivery.deliveryId);
  } finally {
    context.close();
  }
});

test("missing evidence and authorization never produce automatic closure", () => {
  const context = fixture();
  try {
    const claim = context.service.claimAlert({ eventId: "event-vehicle-1" });
    const missing = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: { observedEvidence: EVIDENCE.slice(0, 1), evidenceRefs: ["wazuh-alert:wazuh-9001"] },
      knowledgeIds: ["kb-vehicle_platform-brute_force"]
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
      context: { observedEvidence: EVIDENCE, evidenceRefs: ["wazuh-alert:wazuh-9001"], authorizationRecord: true },
      knowledgeIds: ["kb-vehicle_platform-brute_force"]
    });
    assert.equal(policy.action, "suppress_with_manual_review");
    assert.equal(policy.ticketRequired, true);
    assert.equal(policy.autoCloseAllowed, false);
  } finally {
    authorized.close();
  }
});

test("RecordTriageResult rejects a modified decision token", () => {
  const context = fixture();
  try {
    const claim = context.service.claimAlert({ eventId: "event-vehicle-1" });
    const policy = context.service.evaluatePolicy({
      traceId: claim.traceId,
      context: { observedEvidence: EVIDENCE, evidenceRefs: ["wazuh-alert:wazuh-9001"] },
      knowledgeIds: ["kb-vehicle_platform-brute_force"]
    });
    const tampered = `${policy.decisionToken.slice(0, -1)}${policy.decisionToken.endsWith("A") ? "B" : "A"}`;
    assert.throws(
      () => context.service.recordTriageResult({ traceId: claim.traceId, decisionToken: tampered, narrative: "非法改写。" }),
      (error) => error instanceof SecurityOpsError && error.code === "FAILED_PRECONDITION"
    );
  } finally {
    context.close();
  }
});
