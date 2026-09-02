import { randomUUID } from "node:crypto";

import { hashDecisionToken, issueDecisionToken, verifyDecisionToken } from "./decision-token.js";
import { failedPrecondition, invalidArgument } from "./errors.js";
import { normalizeStringArray, parseContextJson } from "./knowledge-repository.js";
import {
  normalizeClaimToken,
  normalizeIngestAlertEvent,
  normalizeLimit,
  normalizePutAuthorizationRecord,
  normalizeRequeueStalledAlerts
} from "./validation.js";

export class SecurityOpsService {
  constructor({ store, knowledgeRepository = null, decisionTokenSecret = "", eventIdFactory = randomUUID, now = () => new Date() }) {
    if (!store) throw new TypeError("store is required");
    this.store = store;
    this.knowledgeRepository = knowledgeRepository;
    this.decisionTokenSecret = decisionTokenSecret;
    this.eventIdFactory = eventIdFactory;
    this.now = now;
  }

  ingestAlertEvent(request) {
    const event = normalizeIngestAlertEvent(request, {
      eventIdFactory: this.eventIdFactory,
      now: this.now()
    });
    return this.store.ingestAlertEvent(event);
  }

  listPendingAlerts(request = {}) {
    return { alerts: this.store.listPendingAlerts(request) };
  }

  requeueStalledAlerts(request = {}) {
    normalizeRequeueStalledAlerts(request);
    return this.store.requeueStalledAlerts();
  }

  putAuthorizationRecord(request) {
    return this.store.putAuthorizationRecord(normalizePutAuthorizationRecord(request));
  }

  getAlertContext(request) {
    const eventId = requiredId(request?.eventId, "eventId");
    const traceId = this.#traceForEvent(eventId);
    this.#assertClaim(traceId, request);
    const result = this.store.getAlertContext(eventId);
    this.store.appendStep({ traceId, method: "GetAlertContext", evidenceRefs: [`wazuh-alert:${result.wazuhAlertId}`] });
    return result;
  }

  claimAlert(request) {
    const eventId = requiredId(request?.eventId, "eventId");
    const result = this.store.claimAlert({
      eventId,
      schedulerRunId: optionalId(request?.schedulerRunId, "schedulerRunId"),
      sandboxId: optionalId(request?.sandboxId, "sandboxId")
    });
    if (result.status === "acquired") this.store.appendStep({ traceId: result.traceId, method: "ClaimAlert", evidenceRefs: [`event:${eventId}`] });
    return result;
  }

  enrichAlert(request) {
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const trace = this.store.getTriageTrace(traceId);
    const alert = this.store.getAlertContext(trace.eventId);
    const evidenceRefs = [`wazuh-alert:${alert.wazuhAlertId}`, `event:${trace.eventId}`];
    const alertData = alert.alert?.data && typeof alert.alert.data === "object" ? alert.alert.data : alert.alert;
    const domainId = optionalKnowledgeId(alertData?.domain_id ?? alertData?.domainId) || "unclassified";
    const attackTypeId = optionalKnowledgeId(alertData?.attack_type_id ?? alertData?.attackTypeId) || "other_attack";
    const observedEvidence = normalizeStringArray(alertData?.observed_evidence ?? alertData?.observedEvidence);
    const context = {
      ...alert.alert,
      eventId: trace.eventId,
      traceId,
      correlationId: trace.correlationId,
      evidenceRefs,
      domainId,
      attackTypeId,
      observedEvidence
    };
    this.store.appendStep({ traceId, method: "EnrichAlert", evidenceRefs });
    return { traceId, context, contextJson: JSON.stringify(context), evidenceRefs, domainId, attackTypeId };
  }

  matchKnowledge(request) {
    if (!this.knowledgeRepository) throw failedPrecondition("approved runtime knowledge is not configured");
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const domainId = requiredId(request?.domainId, "domainId");
    const attackTypeId = requiredId(request?.attackTypeId, "attackTypeId");
    const context = parseContextJson(request?.contextJson ?? request?.context);
    const matches = this.knowledgeRepository.match({ domainId, attackTypeId, context });
    const evidenceRefs = normalizeStringArray(matches.flatMap((match) => match.evidenceRefs));
    this.store.appendStep({ traceId, method: "MatchKnowledge", evidenceRefs });
    return { traceId, matches };
  }

  evaluatePolicy(request) {
    if (!this.knowledgeRepository) throw failedPrecondition("approved runtime knowledge is not configured");
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const context = parseContextJson(request?.contextJson ?? request?.context);
    const knowledgeRefs = normalizeStringArray(request?.knowledgeIds ?? request?.knowledgeRefs);
    const records = knowledgeRefs.map((knowledgeId) => this.knowledgeRepository.get(knowledgeId)).filter(Boolean);
    const evidenceRefs = normalizeStringArray(context.evidenceRefs);
    if (evidenceRefs.length === 0) evidenceRefs.push(`trace:${traceId}:alert-context`);
    const authorization = this.#resolveAuthorization(context);
    if (authorization) {
      evidenceRefs.push(`authorization:${authorization.authorizationId}`, ...authorization.evidenceRefs);
    }
    const observed = new Set(normalizeStringArray(context.observedEvidence));
    const insufficientIndependentEvidence = records.some((record) => {
      const minimum = Number(record.evidencePolicy?.minimumIndependentEvidence ?? record.evidenceRequired.length);
      const matched = record.evidenceRequired.filter((item) => observed.has(item)).length;
      return matched < minimum;
    });
    const needsAdditionalTelemetry = records.some((record) =>
      record.wazuhMapping?.wazuhObservability !== "full" &&
      (record.wazuhMapping?.additionalTelemetryRequired?.length ?? 0) > 0
    );
    let decision;
    let action;
    if (records.length === 0 || records.some((record) => record.attackTypeId === "other_attack")) {
      decision = "manual_review";
      action = "manual_classification";
    } else if (insufficientIndependentEvidence || needsAdditionalTelemetry || context.insufficientEvidence === true) {
      decision = "manual_review";
      action = "request_additional_evidence";
    } else if (authorization) {
      decision = "needs_review";
      action = "suppress_with_manual_review";
    } else {
      decision = "escalate";
      action = "escalate_with_manual_review";
    }
    const authoritative = {
      traceId,
      decision,
      action,
      evidenceRefs,
      knowledgeRefs: records.map((record) => record.knowledgeId),
      ticketRequired: true,
      policyStatus: "operational_knowledge",
      autoCloseAllowed: false
    };
    const decisionToken = issueDecisionToken(authoritative, { secret: this.decisionTokenSecret, now: this.now });
    const saved = this.store.savePolicyDecision({ ...authoritative, decisionToken, decisionTokenHash: hashDecisionToken(decisionToken) });
    if (!saved.duplicate) this.store.appendStep({ traceId, method: "EvaluatePolicy", evidenceRefs });
    return { ...authoritative, duplicate: saved.duplicate, decisionToken: saved.decisionToken };
  }

  recordTriageResult(request) {
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const decisionToken = String(request?.decisionToken ?? "");
    const tokenPayload = verifyDecisionToken(decisionToken, { secret: this.decisionTokenSecret, now: this.now });
    if (tokenPayload.traceId !== traceId) throw failedPrecondition("decisionToken belongs to another trace", { traceId });
    const narrative = String(request?.narrative ?? "").trim();
    if (!narrative || narrative.length > 4000) throw invalidArgument("narrative must contain between 1 and 4000 characters", { field: "narrative" });
    const result = this.store.recordTriageResult({ traceId, decisionTokenHash: hashDecisionToken(decisionToken), narrative });
    if (!result.duplicate) this.store.appendStep({ traceId, method: "RecordTriageResult", evidenceRefs: result.evidenceRefs });
    return result;
  }

  createManualTicket(request) {
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const resultId = requiredId(request?.resultId, "resultId");
    const ticket = this.store.createManualTicket({ traceId, resultId });
    if (!ticket.duplicate) this.store.appendStep({ traceId, method: "CreateManualTicket", evidenceRefs: [`result:${resultId}`] });
    return ticket;
  }

  queueFeishuNotification(request) {
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const ticketId = requiredId(request?.ticketId, "ticketId");
    const trace = this.store.getTriageTrace(traceId);
    const payload = {
      msg_type: "interactive",
      card: {
        header: { title: { tag: "plain_text", content: "安全告警人工复核" } },
        elements: [{ tag: "div", text: { tag: "lark_md", content: `事件 ${trace.eventId}\n工单 ${ticketId}\n动作 ${trace.result?.action ?? trace.policy?.action}` } }]
      }
    };
    const delivery = this.store.queueFeishuNotification({ traceId, ticketId, payload });
    if (!delivery.duplicate) this.store.appendStep({ traceId, method: "QueueFeishuNotification", evidenceRefs: [`ticket:${ticketId}`] });
    return delivery;
  }

  finalizeTriage(request) {
    const traceId = requiredId(request?.traceId, "traceId");
    this.#assertClaim(traceId, request);
    const result = this.store.finalizeTriage(traceId);
    if (!result.duplicate) this.store.appendStep({ traceId, method: "FinalizeTriage", evidenceRefs: [`trace:${traceId}:terminal`] });
    return result;
  }

  getTriageTrace(request) {
    return this.store.getTriageTrace(requiredId(request?.traceId, "traceId"));
  }

  recoverDelivery(request = {}) {
    const limit = normalizeLimit(request.limit);
    return this.store.recoverDelivery({ limit, includeManual: request.includeManual === true });
  }

  #traceForEvent(eventId) {
    const claim = this.store.findClaimForEvent(eventId);
    if (!claim) throw failedPrecondition("alert must be claimed before business methods are called", { eventId });
    return claim.traceId;
  }

  #assertClaim(traceId, request) {
    return this.store.assertClaim({
      traceId,
      claimToken: normalizeClaimToken(request?.claimToken)
    });
  }

  #resolveAuthorization(context) {
    const authorizationId = optionalId(
      context.authorizationRecordId ?? context.authorization_record_id ?? context.data?.authorization_record_id,
      "authorizationRecordId"
    );
    if (!authorizationId) return null;
    const record = this.store.getAuthorizationRecord(authorizationId);
    const nowMs = this.now().getTime();
    if (!record || record.status !== "active" || Date.parse(record.validFrom) > nowMs || Date.parse(record.validUntil) <= nowMs) {
      return null;
    }
    const candidates = authorizationScopeCandidates(record.scopeType, context);
    return candidates.has(record.scopeValue) && record.evidenceRefs.length > 0 ? record : null;
  }
}

function requiredId(value, field) {
  const normalized = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(normalized)) throw invalidArgument(`${field} is invalid`, { field });
  return normalized;
}

function optionalId(value, field) {
  return value === undefined || value === null || value === "" ? null : requiredId(value, field);
}

function optionalKnowledgeId(value) {
  const normalized = String(value ?? "").trim();
  return /^[a-z][a-z0-9_]{1,63}$/.test(normalized) ? normalized : "";
}

function authorizationScopeCandidates(scopeType, context) {
  const values = {
    asset: [context.assetId, context.asset_id, context.agent?.id, context.agent?.name, context.data?.asset_id],
    account: [context.account, context.accountId, context.data?.account, context.data?.dstuser, context.data?.user],
    rule: [context.rule?.id, context.ruleId, context.data?.rule_id],
    change_window: [context.changeWindowId, context.change_window_id, context.data?.change_window_id]
  }[scopeType] ?? [];
  return new Set(values.map((value) => String(value ?? "").trim()).filter(Boolean));
}
