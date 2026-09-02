import { readFileSync, mkdirSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { BUSINESS_REASONS, failedPrecondition, notFound } from "./errors.js";
import { normalizeLimit } from "./validation.js";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_MIGRATIONS_DIR = path.resolve(MODULE_DIR, "../migrations");
const STALE_AFTER_MS = 180_000;
const RECOVERY_BATCH_LIMIT = 5;
const MANUALIZE_ON_RECOVERY = 3;

function configureDatabase(database) {
  database.exec("PRAGMA journal_mode = WAL");
  database.exec("PRAGMA foreign_keys = ON");
  database.exec("PRAGMA busy_timeout = 5000");
}

function applyMigrations(database, migrationsDir, now) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    )
  `);
  const files = readdirSync(migrationsDir)
    .filter((name) => /^\d{3}_[a-z0-9_]+\.sql$/.test(name))
    .sort((left, right) => left.localeCompare(right));
  const seenVersions = new Set();
  for (const file of files) {
    const version = Number(file.slice(0, 3));
    if (!Number.isSafeInteger(version) || version < 1 || seenVersions.has(version)) {
      throw new Error(`invalid or duplicate migration version: ${file}`);
    }
    seenVersions.add(version);
    const applied = database.prepare("SELECT 1 FROM schema_migrations WHERE version = ?").get(version);
    if (applied) continue;
    database.exec("BEGIN IMMEDIATE");
    try {
      database.exec(readFileSync(path.join(migrationsDir, file), "utf8"));
      database.prepare("INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)")
        .run(version, now().toISOString());
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw new Error(`migration ${file} failed`, { cause: error });
    }
  }
}

export class SecurityOpsStore {
  constructor({
    databasePath,
    migrationsDir = DEFAULT_MIGRATIONS_DIR,
    now = () => new Date(),
    idFactory = randomUUID,
    tokenFactory = () => randomBytes(32).toString("base64url"),
    maxActiveTriage = 2,
    claimLeaseMs = 180_000
  }) {
    if (!databasePath) throw new TypeError("databasePath is required");
    this.now = now;
    this.idFactory = idFactory;
    this.tokenFactory = tokenFactory;
    this.maxActiveTriage = maxActiveTriage;
    this.claimLeaseMs = claimLeaseMs;
    if (maxActiveTriage !== 2) throw new TypeError("maxActiveTriage must be 2");
    if (!Number.isInteger(claimLeaseMs) || claimLeaseMs < 30_000 || claimLeaseMs > 900_000) {
      throw new TypeError("claimLeaseMs must be an integer between 30000 and 900000");
    }
    mkdirSync(path.dirname(path.resolve(databasePath)), { recursive: true });
    this.database = new DatabaseSync(path.resolve(databasePath));
    try {
      configureDatabase(this.database);
      applyMigrations(this.database, path.resolve(migrationsDir), this.now);
      this.statements = prepareStatements(this.database);
    } catch (error) {
      this.database.close();
      throw error;
    }
  }

  ingestAlertEvent(event) {
    const existingByWazuh = this.statements.findIngressByWazuh.get(event.wazuhAlertId);
    if (existingByWazuh) {
      if (existingByWazuh.event_id !== event.eventId && event.eventId) {
        return decodeIngress(existingByWazuh, true);
      }
      return decodeIngress(existingByWazuh, true);
    }
    const existingByEvent = this.statements.findIngressByEvent.get(event.eventId);
    if (existingByEvent) {
      if (existingByEvent.wazuh_alert_id !== event.wazuhAlertId) {
        throw failedPrecondition("eventId is already bound to another Wazuh alert", {
          eventId: event.eventId
        });
      }
      return decodeIngress(existingByEvent, true);
    }

    const now = this.now().toISOString();
    const deliveryId = this.idFactory();
    const payload = JSON.stringify({ eventId: event.eventId, correlationId: event.correlationId });
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.statements.insertIngress.run(
        event.eventId,
        event.wazuhAlertId,
        event.correlationId,
        event.occurredAt,
        event.alertJson,
        now,
        now
      );
      this.statements.insertTrigger.run(
        deliveryId,
        event.eventId,
        event.eventId,
        payload,
        now,
        now,
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return {
      eventId: event.eventId,
      correlationId: event.correlationId,
      wazuhAlertId: event.wazuhAlertId,
      status: "pending",
      duplicate: false,
      receivedAt: now
    };
  }

  listPendingAlerts({ limit } = {}) {
    const boundedLimit = normalizeLimit(limit);
    return this.statements.listPending.all(boundedLimit).map((row) => ({
      eventId: row.event_id,
      correlationId: row.correlation_id,
      wazuhAlertId: row.wazuh_alert_id,
      status: row.status,
      receivedAt: row.received_at
    }));
  }

  claimAlert({ eventId, schedulerRunId = null, sandboxId = null }) {
    const alert = this.statements.findIngressByEvent.get(eventId);
    if (!alert) throw notFound("alert event was not found", { eventId });
    const nowDate = this.now();
    const now = nowDate.toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const existingRun = this.statements.findRunByEvent.get(eventId);
      if (existingRun) {
        const existingClaim = this.statements.findClaimByEvent.get(eventId);
        if (existingRun.state === "requeued") {
          if (Number(this.statements.countActiveIngressExcluding.get(eventId).count) >= this.maxActiveTriage) {
            this.database.exec("COMMIT");
            return decodeClaim(existingClaim, existingRun, { status: "busy", duplicate: true });
          }
          const claimToken = this.tokenFactory();
          if (!/^[A-Za-z0-9_-]{43,128}$/.test(claimToken)) throw new TypeError("tokenFactory returned an invalid claim token");
          const leaseUntil = new Date(nowDate.getTime() + this.claimLeaseMs).toISOString();
          this.statements.reacquireRun.run(
            schedulerRunId,
            sandboxId,
            hashClaimToken(claimToken),
            leaseUntil,
            now,
            now,
            existingRun.trace_id
          );
          this.statements.updateClaim.run(schedulerRunId, sandboxId, now, eventId);
          this.statements.updateIngressStatus.run("processing", now, eventId);
          this.database.exec("COMMIT");
          return {
            ...decodeClaim(
              { ...existingClaim, scheduler_run_id: schedulerRunId, sandbox_id: sandboxId, claimed_at: now },
              { ...existingRun, scheduler_run_id: schedulerRunId, sandbox_id: sandboxId, lease_until: leaseUntil },
              { status: "acquired", duplicate: false }
            ),
            claimToken,
            leaseUntil
          };
        }
        this.database.exec("COMMIT");
        return decodeClaim(existingClaim, existingRun, {
          status: ["completed", "manual"].includes(existingRun.state) ? existingRun.state : "busy",
          duplicate: true
        });
      }
      if (!["pending", "claimed", "processing"].includes(alert.status)) {
        throw failedPrecondition("alert event is not claimable", { eventId, status: alert.status });
      }
      if (Number(this.statements.countActiveIngressExcluding.get(eventId).count) >= this.maxActiveTriage) {
        this.database.exec("COMMIT");
        return { eventId, status: "busy", duplicate: true };
      }
      const claimId = this.idFactory();
      const traceId = this.idFactory();
      const claimToken = this.tokenFactory();
      if (!/^[A-Za-z0-9_-]{43,128}$/.test(claimToken)) throw new TypeError("tokenFactory returned an invalid claim token");
      const claimTokenHash = hashClaimToken(claimToken);
      const leaseUntil = new Date(nowDate.getTime() + this.claimLeaseMs).toISOString();
      this.statements.insertClaim.run(claimId, eventId, traceId, schedulerRunId, sandboxId, now);
      this.statements.insertRun.run(traceId, eventId, schedulerRunId, sandboxId, claimTokenHash, leaseUntil, now, now);
      this.statements.updateIngressStatus.run("processing", now, eventId);
      this.database.exec("COMMIT");
      return {
        claimId,
        traceId,
        eventId,
        schedulerRunId,
        sandboxId,
        status: "acquired",
        duplicate: false,
        claimToken,
        attempt: 1,
        leaseUntil,
        claimedAt: now
      };
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  assertClaim({ traceId, claimToken }) {
    const run = this.statements.findRun.get(traceId);
    if (!run) throw notFound("triage run was not found", { traceId });
    if (run.state !== "processing" || !secureHashEquals(run.claim_token_hash, hashClaimToken(claimToken))) {
      throw failedPrecondition("claim token no longer owns this triage run", {
        traceId,
        reason: BUSINESS_REASONS.CLAIM_FENCED
      });
    }
    const nowDate = this.now();
    if (!run.lease_until || Date.parse(run.lease_until) <= nowDate.getTime()) {
      throw failedPrecondition("claim lease has expired", {
        traceId,
        reason: BUSINESS_REASONS.LEASE_EXPIRED,
        leaseUntil: run.lease_until
      });
    }
    const now = nowDate.toISOString();
    const leaseUntil = new Date(nowDate.getTime() + this.claimLeaseMs).toISOString();
    const refreshed = this.statements.refreshRunLease.run(leaseUntil, now, traceId, run.claim_token_hash);
    if (refreshed.changes !== 1) {
      throw failedPrecondition("claim token was fenced while refreshing the lease", {
        traceId,
        reason: BUSINESS_REASONS.CLAIM_FENCED
      });
    }
    return { traceId, eventId: run.event_id, attempt: Number(run.attempt), leaseUntil };
  }

  appendStep({ traceId, method, status = "completed", evidenceRefs = [] }) {
    const run = this.statements.findRun.get(traceId);
    if (!run) throw notFound("triage run was not found", { traceId });
    const sequence = Number(this.statements.nextStepSequence.get(traceId).sequence);
    const stepId = this.idFactory();
    this.statements.insertStep.run(stepId, traceId, sequence, method, status, JSON.stringify(evidenceRefs), this.now().toISOString());
    return { stepId, traceId, sequence, method, status, evidenceRefs };
  }

  savePolicyDecision(decision) {
    const existing = this.statements.findPolicyDecision.get(decision.traceId);
    if (existing) return decodePolicyDecision(existing, true);
    const now = this.now().toISOString();
    this.statements.insertPolicyDecision.run(
      decision.traceId,
      decision.decision,
      decision.action,
      JSON.stringify(decision.evidenceRefs),
      JSON.stringify(decision.knowledgeRefs),
      decision.policyStatus,
      decision.decisionToken,
      decision.decisionTokenHash,
      now
    );
    return { ...decision, ticketRequired: true, autoCloseAllowed: false, duplicate: false, createdAt: now };
  }

  getPolicyDecision(traceId) {
    const row = this.statements.findPolicyDecision.get(traceId);
    if (!row) throw notFound("policy decision was not found", { traceId });
    return decodePolicyDecision(row, false);
  }

  recordTriageResult({ traceId, decisionTokenHash, narrative }) {
    const existing = this.statements.findResultByTrace.get(traceId);
    if (existing) return decodeResult(existing, true);
    const decision = this.statements.findPolicyDecision.get(traceId);
    if (!decision) throw failedPrecondition("policy decision must be recorded first", { traceId });
    if (decision.decision_token_hash !== decisionTokenHash) {
      throw failedPrecondition("decisionToken does not match the authoritative policy decision", { traceId });
    }
    const resultId = this.idFactory();
    const now = this.now().toISOString();
    this.statements.insertResult.run(
      resultId,
      traceId,
      decision.decision,
      decision.action,
      decision.evidence_json,
      decision.knowledge_json,
      narrative,
      decisionTokenHash,
      now
    );
    return decodeResult(this.statements.findResultByTrace.get(traceId), false);
  }

  createManualTicket({ traceId, resultId }) {
    const existing = this.statements.findTicketByTrace.get(traceId);
    if (existing) return decodeTicket(existing, true);
    const result = this.statements.findResultByTrace.get(traceId);
    if (!result || result.result_id !== resultId) {
      throw failedPrecondition("resultId does not belong to the triage trace", { traceId, resultId });
    }
    const ticketId = this.idFactory();
    const now = this.now().toISOString();
    this.statements.insertTicket.run(ticketId, traceId, resultId, now, now);
    return decodeTicket(this.statements.findTicketByTrace.get(traceId), false);
  }

  queueFeishuNotification({ traceId, ticketId, payload }) {
    const existing = this.statements.findDeliveryByTicket.get(ticketId);
    if (existing) return decodeDelivery(existing, true);
    const ticket = this.statements.findTicketByTrace.get(traceId);
    if (!ticket || ticket.ticket_id !== ticketId) {
      throw failedPrecondition("ticketId does not belong to the triage trace", { traceId, ticketId });
    }
    const deliveryId = this.idFactory();
    const now = this.now().toISOString();
    this.statements.insertDelivery.run(deliveryId, traceId, ticketId, `feishu:${ticketId}`, JSON.stringify(payload), now, now, now);
    return decodeDelivery(this.statements.findDeliveryByTicket.get(ticketId), false);
  }

  finalizeTriage(traceId) {
    const run = this.statements.findRun.get(traceId);
    if (!run) throw notFound("triage run was not found", { traceId });
    if (run.state === "completed") return { traceId, state: "completed", duplicate: true };
    const result = this.statements.findResultByTrace.get(traceId);
    const ticket = this.statements.findTicketByTrace.get(traceId);
    const delivery = ticket ? this.statements.findDeliveryByTicket.get(ticket.ticket_id) : null;
    if (!result || !ticket || !delivery) {
      throw failedPrecondition("result, manual ticket and Feishu delivery are required before finalization", { traceId });
    }
    const now = this.now().toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.statements.finalizeRun.run(now, traceId);
      this.statements.updateIngressStatus.run("completed", now, run.event_id);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return { traceId, state: "completed", duplicate: false, finalizedAt: now };
  }

  getTriageTrace(traceId) {
    const run = this.statements.findRun.get(traceId);
    if (!run) throw notFound("triage run was not found", { traceId });
    const alert = this.statements.findIngressByEvent.get(run.event_id);
    const claim = this.statements.findClaimByEvent.get(run.event_id);
    const policy = this.statements.findPolicyDecision.get(traceId);
    const result = this.statements.findResultByTrace.get(traceId);
    const ticket = this.statements.findTicketByTrace.get(traceId);
    const delivery = ticket ? this.statements.findDeliveryByTicket.get(ticket.ticket_id) : null;
    return {
      traceId,
      eventId: run.event_id,
      wazuhAlertId: alert.wazuh_alert_id,
      correlationId: alert.correlation_id,
      schedulerRunId: claim.scheduler_run_id,
      sandboxId: claim.sandbox_id,
      state: run.state,
      steps: this.statements.listSteps.all(traceId).map(decodeStep),
      policy: policy ? publicPolicyDecision(decodePolicyDecision(policy, false)) : null,
      result: result ? decodeResult(result, false) : null,
      ticket: ticket ? decodeTicket(ticket, false) : null,
      delivery: delivery ? decodeDelivery(delivery, false) : null
    };
  }

  recoverDelivery({ limit = 20, includeManual = false } = {}) {
    const boundedLimit = normalizeLimit(limit);
    const now = this.now().toISOString();
    let recovered = 0;
    if (includeManual) {
      recovered += this.statements.recoverManualTriggers.run(now, now, boundedLimit).changes;
      const remaining = Math.max(0, boundedLimit - recovered);
      if (remaining > 0) recovered += this.statements.recoverManualDeliveries.run(now, now, remaining).changes;
    }
    const triggerCounts = this.statements.triggerCounts.get();
    const deliveryCounts = this.statements.deliveryCounts.get();
    return {
      recovered: Number(recovered),
      pending: Number(triggerCounts.pending ?? 0) + Number(deliveryCounts.pending ?? 0),
      manual: Number(triggerCounts.manual ?? 0) + Number(deliveryCounts.manual ?? 0)
    };
  }

  requeueStalledAlerts() {
    const nowDate = this.now();
    const now = nowDate.toISOString();
    const staleBefore = new Date(nowDate.getTime() - STALE_AFTER_MS).toISOString();
    const rows = this.statements.selectStalledRuns.all(staleBefore, RECOVERY_BATCH_LIMIT);
    const eventIds = [];
    let requeued = 0;
    let manualized = 0;
    for (const selected of rows) {
      this.database.exec("BEGIN IMMEDIATE");
      try {
        const run = this.statements.findRun.get(selected.trace_id);
        const event = this.statements.findIngressByEvent.get(selected.event_id);
        const activity = run?.last_activity_at ?? run?.started_at;
        if (!run || !event || run.state !== "processing" || !activity || activity > staleBefore) {
          this.database.exec("COMMIT");
          continue;
        }
        const recoveryAttempt = Number(event.recovery_count ?? 0) + 1;
        if (recoveryAttempt < MANUALIZE_ON_RECOVERY) {
          const deliveryId = this.idFactory();
          const idempotencyKey = `triage:${event.event_id}:recovery:${recoveryAttempt}`;
          const payload = JSON.stringify({
            eventId: event.event_id,
            correlationId: event.correlation_id,
            recoveryAttempt
          });
          this.statements.prepareRunRecovery.run(Number(run.attempt) + 1, now, run.trace_id);
          this.statements.prepareIngressRecovery.run(recoveryAttempt, now, event.event_id);
          this.statements.insertRecoveryTrigger.run(
            deliveryId,
            event.event_id,
            recoveryAttempt,
            idempotencyKey,
            payload,
            now,
            now,
            now
          );
          requeued += 1;
        } else {
          this.#manualizeExhaustedRecovery({ run, event, recoveryAttempt, now });
          manualized += 1;
        }
        eventIds.push(event.event_id);
        this.database.exec("COMMIT");
      } catch (error) {
        this.database.exec("ROLLBACK");
        throw error;
      }
    }
    return { scanned: rows.length, requeued, manualized, eventIds };
  }

  claimTriggerDeliveries({ limit = 20, leaseMs = 30_000 } = {}) {
    const boundedLimit = normalizeLimit(limit);
    const nowDate = this.now();
    const now = nowDate.toISOString();
    const leaseUntil = new Date(nowDate.getTime() + leaseMs).toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const reserved = Number(this.statements.countReservedIngress.get().count);
      const available = Math.max(0, this.maxActiveTriage - reserved);
      if (available === 0) {
        this.database.exec("COMMIT");
        return [];
      }
      const rows = this.statements.selectDueTriggers.all(now, now, Math.min(boundedLimit, available));
      const claimed = [];
      for (const row of rows) {
        const reservedEvent = this.statements.reserveIngress.run(now, row.event_id);
        if (reservedEvent.changes !== 1) continue;
        const changed = this.statements.claimTrigger.run(leaseUntil, now, row.delivery_id, now, now);
        if (changed.changes !== 1) {
          this.statements.releaseIngressReservation.run(now, row.event_id);
          continue;
        }
        claimed.push(decodeTriggerDelivery({ ...row, status: "processing", lease_until: leaseUntil }, false));
      }
      this.database.exec("COMMIT");
      return claimed;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  claimFeishuDeliveries({ limit = 20, leaseMs = 30_000 } = {}) {
    return this.#claimOutbox({
      select: this.statements.selectDueDeliveries,
      claim: this.statements.claimDelivery,
      decode: decodeDelivery,
      limit,
      leaseMs
    });
  }

  markTriggerDelivered(deliveryId) {
    this.statements.markTriggerDelivered.run(this.now().toISOString(), deliveryId);
  }

  markFeishuDelivered(deliveryId) {
    this.statements.markDeliveryDelivered.run(this.now().toISOString(), deliveryId);
  }

  markTriggerFailed(delivery, { error, retryable, maxAttempts = 9 } = {}) {
    this.#markOutboxFailed({ delivery, error, retryable, maxAttempts, retry: this.statements.markTriggerRetry, manual: this.statements.markTriggerManual });
    this.statements.releaseIngressReservation.run(this.now().toISOString(), delivery.eventId);
  }

  markFeishuFailed(delivery, { error, retryable, maxAttempts = 9 } = {}) {
    this.#markOutboxFailed({ delivery, error, retryable, maxAttempts, retry: this.statements.markDeliveryRetry, manual: this.statements.markDeliveryManual });
  }

  #claimOutbox({ select, claim, decode, limit, leaseMs }) {
    const boundedLimit = normalizeLimit(limit);
    const now = this.now();
    const nowIso = now.toISOString();
    const leaseUntil = new Date(now.getTime() + leaseMs).toISOString();
    const rows = select.all(nowIso, nowIso, boundedLimit);
    const claimed = [];
    for (const row of rows) {
      const changed = claim.run(leaseUntil, nowIso, row.delivery_id, nowIso, nowIso);
      if (changed.changes === 1) claimed.push(decode({ ...row, status: "processing", lease_until: leaseUntil }, false));
    }
    return claimed;
  }

  #markOutboxFailed({ delivery, error, retryable, maxAttempts, retry, manual }) {
    const safeError = String(error ?? "delivery failed").slice(0, 512);
    const attempts = Number(delivery.attempts ?? 0) + 1;
    const now = this.now();
    if (!retryable || attempts >= maxAttempts) {
      manual.run(safeError, now.toISOString(), delivery.deliveryId);
      return;
    }
    const delayMs = Math.min(30_000 * (2 ** Math.max(0, attempts - 1)), 15 * 60_000);
    retry.run(new Date(now.getTime() + delayMs).toISOString(), safeError, now.toISOString(), delivery.deliveryId);
  }

  #manualizeExhaustedRecovery({ run, event, recoveryAttempt, now }) {
    const evidenceRefs = [`event:${event.event_id}`, `trace:${run.trace_id}:recovery-exhausted`];
    const evidenceJson = JSON.stringify(evidenceRefs);
    const internalToken = `internal-recovery:${run.trace_id}:${recoveryAttempt}`;
    const internalTokenHash = createHash("sha256").update(internalToken).digest("hex");
    const resultId = this.idFactory();
    const ticketId = this.idFactory();
    const deliveryId = this.idFactory();
    const stepId = this.idFactory();
    this.statements.upsertManualPolicy.run(
      run.trace_id,
      evidenceJson,
      internalToken,
      internalTokenHash,
      now
    );
    this.statements.upsertManualResult.run(
      resultId,
      run.trace_id,
      evidenceJson,
      "研判运行连续停滞，已安全转入人工复核并请求补充证据。",
      internalTokenHash,
      now
    );
    const result = this.statements.findResultByTrace.get(run.trace_id);
    this.statements.insertTicketIfMissing.run(ticketId, run.trace_id, result.result_id, now, now);
    const ticket = this.statements.findTicketByTrace.get(run.trace_id);
    const payload = JSON.stringify({
      msg_type: "interactive",
      card: {
        header: { title: { tag: "plain_text", content: "安全告警需人工复核" } },
        elements: [{
          tag: "div",
          text: { tag: "lark_md", content: `事件 ${event.event_id}\n工单 ${ticket.ticket_id}\n动作 request_additional_evidence` }
        }]
      }
    });
    this.statements.insertDeliveryIfMissing.run(
      deliveryId,
      run.trace_id,
      ticket.ticket_id,
      `feishu:${ticket.ticket_id}`,
      payload,
      now,
      now,
      now
    );
    const sequence = Number(this.statements.nextStepSequence.get(run.trace_id).sequence);
    this.statements.insertStep.run(stepId, run.trace_id, sequence, "FailSafeManualization", "completed", evidenceJson, now);
    this.statements.manualizeRun.run(now, run.trace_id);
    this.statements.manualizeIngress.run(recoveryAttempt, "recovery attempts exhausted", now, event.event_id);
  }

  getAlertContext(eventId) {
    const row = this.statements.findIngressByEvent.get(eventId);
    if (!row) throw notFound("alert event was not found", { eventId });
    return {
      eventId: row.event_id,
      correlationId: row.correlation_id,
      wazuhAlertId: row.wazuh_alert_id,
      occurredAt: row.occurred_at,
      status: row.status,
      alert: JSON.parse(row.alert_json)
    };
  }

  findClaimForEvent(eventId) {
    const claim = this.statements.findClaimByEvent.get(eventId);
    const run = this.statements.findRunByEvent.get(eventId);
    return claim && run ? decodeClaim(claim, run, { status: run.state, duplicate: false }) : null;
  }

  inspectCounts() {
    return {
      ingressEvents: Number(this.statements.countIngress.get().count),
      triggerOutbox: Number(this.statements.countTrigger.get().count)
    };
  }

  close() {
    this.database.close();
  }
}

function prepareStatements(database) {
  return {
    findIngressByWazuh: database.prepare("SELECT * FROM ingress_events WHERE wazuh_alert_id = ?"),
    findIngressByEvent: database.prepare("SELECT * FROM ingress_events WHERE event_id = ?"),
    insertIngress: database.prepare(`
      INSERT INTO ingress_events
        (event_id, wazuh_alert_id, correlation_id, occurred_at, alert_json, status, received_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
    `),
    insertTrigger: database.prepare(`
      INSERT INTO trigger_outbox
        (delivery_id, event_id, idempotency_key, payload_json, status, attempts, next_attempt_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?)
    `),
    listPending: database.prepare(`
      SELECT event_id, correlation_id, wazuh_alert_id, status, received_at
      FROM ingress_events
      WHERE status = 'pending'
         OR (status = 'processing' AND EXISTS (
           SELECT 1 FROM triage_runs
           WHERE triage_runs.event_id = ingress_events.event_id
             AND triage_runs.state = 'processing'
         ))
      ORDER BY received_at ASC, event_id ASC
      LIMIT ?
    `),
    countIngress: database.prepare("SELECT COUNT(*) AS count FROM ingress_events"),
    countTrigger: database.prepare("SELECT COUNT(*) AS count FROM trigger_outbox"),
    findClaimByEvent: database.prepare("SELECT * FROM alert_claims WHERE event_id = ?"),
    findRunByEvent: database.prepare("SELECT * FROM triage_runs WHERE event_id = ?"),
    countActiveIngressExcluding: database.prepare("SELECT COUNT(*) AS count FROM ingress_events WHERE status IN ('claimed', 'processing') AND event_id <> ?"),
    countReservedIngress: database.prepare("SELECT COUNT(*) AS count FROM ingress_events WHERE status IN ('claimed', 'processing')"),
    insertClaim: database.prepare(`INSERT INTO alert_claims (claim_id, event_id, trace_id, scheduler_run_id, sandbox_id, claimed_at) VALUES (?, ?, ?, ?, ?, ?)`),
    insertRun: database.prepare(`
      INSERT INTO triage_runs
        (trace_id, event_id, scheduler_run_id, sandbox_id, state, claim_token_hash, attempt, lease_until, last_activity_at, started_at)
      VALUES (?, ?, ?, ?, 'processing', ?, 1, ?, ?, ?)
    `),
    findRun: database.prepare("SELECT * FROM triage_runs WHERE trace_id = ?"),
    reacquireRun: database.prepare(`
      UPDATE triage_runs
      SET scheduler_run_id = ?, sandbox_id = ?, state = 'processing', claim_token_hash = ?,
          lease_until = ?, last_activity_at = ?, started_at = ?
      WHERE trace_id = ? AND state = 'requeued'
    `),
    updateClaim: database.prepare("UPDATE alert_claims SET scheduler_run_id = ?, sandbox_id = ?, claimed_at = ? WHERE event_id = ?"),
    refreshRunLease: database.prepare(`
      UPDATE triage_runs SET lease_until = ?, last_activity_at = ?
      WHERE trace_id = ? AND claim_token_hash = ? AND state = 'processing'
    `),
    selectStalledRuns: database.prepare(`
      SELECT trace_id, event_id
      FROM triage_runs
      WHERE state = 'processing' AND COALESCE(last_activity_at, started_at) <= ?
      ORDER BY COALESCE(last_activity_at, started_at), trace_id
      LIMIT ?
    `),
    prepareRunRecovery: database.prepare(`
      UPDATE triage_runs
      SET state = 'requeued', claim_token_hash = NULL, attempt = ?, lease_until = NULL, last_activity_at = ?
      WHERE trace_id = ? AND state = 'processing'
    `),
    prepareIngressRecovery: database.prepare(`
      UPDATE ingress_events
      SET status = 'pending', recovery_count = ?, next_recovery_at = NULL,
          last_recovery_error = 'triage lease expired', updated_at = ?
      WHERE event_id = ?
    `),
    insertRecoveryTrigger: database.prepare(`
      INSERT INTO trigger_outbox
        (delivery_id, event_id, delivery_kind, recovery_attempt, idempotency_key,
         payload_json, status, attempts, next_attempt_at, created_at, updated_at)
      VALUES (?, ?, 'recovery', ?, ?, ?, 'pending', 0, ?, ?, ?)
    `),
    updateIngressStatus: database.prepare("UPDATE ingress_events SET status = ?, updated_at = ? WHERE event_id = ?"),
    nextStepSequence: database.prepare("SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence FROM triage_steps WHERE trace_id = ?"),
    insertStep: database.prepare(`INSERT INTO triage_steps (step_id, trace_id, sequence, method, status, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
    listSteps: database.prepare("SELECT * FROM triage_steps WHERE trace_id = ? ORDER BY sequence"),
    findPolicyDecision: database.prepare("SELECT * FROM policy_decisions WHERE trace_id = ?"),
    insertPolicyDecision: database.prepare(`INSERT INTO policy_decisions (trace_id, decision, action, evidence_json, knowledge_json, policy_status, ticket_required, auto_close_allowed, decision_token, decision_token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)`),
    findResultByTrace: database.prepare("SELECT * FROM triage_results WHERE trace_id = ?"),
    insertResult: database.prepare(`INSERT INTO triage_results (result_id, trace_id, decision, action, evidence_json, knowledge_json, narrative, decision_token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    findTicketByTrace: database.prepare("SELECT * FROM manual_tickets WHERE trace_id = ?"),
    insertTicket: database.prepare(`INSERT INTO manual_tickets (ticket_id, trace_id, result_id, status, created_at, updated_at) VALUES (?, ?, ?, 'open', ?, ?)`),
    findDeliveryByTicket: database.prepare("SELECT * FROM delivery_outbox WHERE ticket_id = ?"),
    insertDelivery: database.prepare(`INSERT INTO delivery_outbox (delivery_id, trace_id, ticket_id, idempotency_key, payload_json, status, attempts, next_attempt_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)`),
    upsertManualPolicy: database.prepare(`
      INSERT INTO policy_decisions
        (trace_id, decision, action, evidence_json, knowledge_json, policy_status,
         ticket_required, auto_close_allowed, decision_token, decision_token_hash, created_at)
      VALUES (?, 'manual_review', 'request_additional_evidence', ?, '[]', 'recovery_fallback', 1, 0, ?, ?, ?)
      ON CONFLICT(trace_id) DO UPDATE SET
        decision = 'manual_review', action = 'request_additional_evidence', evidence_json = excluded.evidence_json,
        knowledge_json = '[]', policy_status = 'recovery_fallback', ticket_required = 1,
        auto_close_allowed = 0, decision_token = excluded.decision_token,
        decision_token_hash = excluded.decision_token_hash
    `),
    upsertManualResult: database.prepare(`
      INSERT INTO triage_results
        (result_id, trace_id, decision, action, evidence_json, knowledge_json, narrative, decision_token_hash, created_at)
      VALUES (?, ?, 'manual_review', 'request_additional_evidence', ?, '[]', ?, ?, ?)
      ON CONFLICT(trace_id) DO UPDATE SET
        decision = 'manual_review', action = 'request_additional_evidence', evidence_json = excluded.evidence_json,
        knowledge_json = '[]', narrative = excluded.narrative, decision_token_hash = excluded.decision_token_hash
    `),
    insertTicketIfMissing: database.prepare(`
      INSERT OR IGNORE INTO manual_tickets
        (ticket_id, trace_id, result_id, status, created_at, updated_at)
      VALUES (?, ?, ?, 'open', ?, ?)
    `),
    insertDeliveryIfMissing: database.prepare(`
      INSERT OR IGNORE INTO delivery_outbox
        (delivery_id, trace_id, ticket_id, idempotency_key, payload_json, status, attempts, next_attempt_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
    `),
    finalizeRun: database.prepare("UPDATE triage_runs SET state = 'completed', finalized_at = ? WHERE trace_id = ?"),
    manualizeRun: database.prepare("UPDATE triage_runs SET state = 'manual', claim_token_hash = NULL, lease_until = NULL, finalized_at = ? WHERE trace_id = ?"),
    manualizeIngress: database.prepare(`
      UPDATE ingress_events
      SET status = 'manual', recovery_count = ?, next_recovery_at = NULL, last_recovery_error = ?, updated_at = ?
      WHERE event_id = ?
    `),
    recoverManualTriggers: database.prepare(`
      UPDATE trigger_outbox
      SET status = 'pending', next_attempt_at = ?, updated_at = ?, lease_until = NULL
      WHERE delivery_id IN (
        SELECT delivery_id FROM trigger_outbox WHERE status = 'manual' ORDER BY created_at LIMIT ?
      )
    `),
    recoverManualDeliveries: database.prepare(`
      UPDATE delivery_outbox
      SET status = 'pending', next_attempt_at = ?, updated_at = ?, lease_until = NULL
      WHERE delivery_id IN (
        SELECT delivery_id FROM delivery_outbox WHERE status = 'manual' ORDER BY created_at LIMIT ?
      )
    `),
    triggerCounts: database.prepare(`
      SELECT
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'manual' THEN 1 ELSE 0 END) AS manual
      FROM trigger_outbox
    `),
    deliveryCounts: database.prepare(`
      SELECT
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'manual' THEN 1 ELSE 0 END) AS manual
      FROM delivery_outbox
    `),
    selectDueTriggers: database.prepare(`
      SELECT * FROM trigger_outbox
      WHERE (status = 'pending' AND next_attempt_at <= ?)
         OR (status = 'processing' AND lease_until <= ?)
      ORDER BY created_at LIMIT ?
    `),
    claimTrigger: database.prepare(`
      UPDATE trigger_outbox SET status = 'processing', lease_until = ?, updated_at = ?
      WHERE delivery_id = ? AND ((status = 'pending' AND next_attempt_at <= ?) OR (status = 'processing' AND lease_until <= ?))
    `),
    reserveIngress: database.prepare("UPDATE ingress_events SET status = 'claimed', updated_at = ? WHERE event_id = ? AND status = 'pending'"),
    releaseIngressReservation: database.prepare("UPDATE ingress_events SET status = 'pending', updated_at = ? WHERE event_id = ? AND status = 'claimed'"),
    markTriggerDelivered: database.prepare("UPDATE trigger_outbox SET status = 'delivered', lease_until = NULL, last_error = NULL, updated_at = ? WHERE delivery_id = ?"),
    markTriggerRetry: database.prepare("UPDATE trigger_outbox SET status = 'pending', attempts = attempts + 1, next_attempt_at = ?, lease_until = NULL, last_error = ?, updated_at = ? WHERE delivery_id = ?"),
    markTriggerManual: database.prepare("UPDATE trigger_outbox SET status = 'manual', attempts = attempts + 1, lease_until = NULL, last_error = ?, updated_at = ? WHERE delivery_id = ?"),
    selectDueDeliveries: database.prepare(`
      SELECT * FROM delivery_outbox
      WHERE (status = 'pending' AND next_attempt_at <= ?)
         OR (status = 'processing' AND lease_until <= ?)
      ORDER BY created_at LIMIT ?
    `),
    claimDelivery: database.prepare(`
      UPDATE delivery_outbox SET status = 'processing', lease_until = ?, updated_at = ?
      WHERE delivery_id = ? AND ((status = 'pending' AND next_attempt_at <= ?) OR (status = 'processing' AND lease_until <= ?))
    `),
    markDeliveryDelivered: database.prepare("UPDATE delivery_outbox SET status = 'delivered', lease_until = NULL, last_error = NULL, updated_at = ? WHERE delivery_id = ?"),
    markDeliveryRetry: database.prepare("UPDATE delivery_outbox SET status = 'pending', attempts = attempts + 1, next_attempt_at = ?, lease_until = NULL, last_error = ?, updated_at = ? WHERE delivery_id = ?"),
    markDeliveryManual: database.prepare("UPDATE delivery_outbox SET status = 'manual', attempts = attempts + 1, lease_until = NULL, last_error = ?, updated_at = ? WHERE delivery_id = ?")
  };
}

function decodeIngress(row, duplicate) {
  return {
    eventId: row.event_id,
    correlationId: row.correlation_id,
    wazuhAlertId: row.wazuh_alert_id,
    status: row.status,
    duplicate,
    receivedAt: row.received_at
  };
}

function decodeClaim(claim, run, { status, duplicate }) {
  return {
    claimId: claim.claim_id,
    eventId: claim.event_id,
    traceId: claim.trace_id,
    schedulerRunId: claim.scheduler_run_id,
    sandboxId: claim.sandbox_id,
    status,
    duplicate,
    attempt: Number(run.attempt),
    leaseUntil: run.lease_until,
    claimedAt: claim.claimed_at
  };
}

function hashClaimToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function secureHashEquals(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  return timingSafeEqual(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function decodePolicyDecision(row, duplicate) {
  return { traceId: row.trace_id, decision: row.decision, action: row.action, evidenceRefs: JSON.parse(row.evidence_json), knowledgeRefs: JSON.parse(row.knowledge_json), policyStatus: row.policy_status, ticketRequired: true, autoCloseAllowed: false, decisionToken: row.decision_token, decisionTokenHash: row.decision_token_hash, duplicate, createdAt: row.created_at };
}

function publicPolicyDecision(decision) {
  const { decisionToken: _decisionToken, decisionTokenHash: _decisionTokenHash, ...publicDecision } = decision;
  return publicDecision;
}

function decodeResult(row, duplicate) {
  return { resultId: row.result_id, traceId: row.trace_id, decision: row.decision, action: row.action, evidenceRefs: JSON.parse(row.evidence_json), knowledgeRefs: JSON.parse(row.knowledge_json), narrative: row.narrative, duplicate, createdAt: row.created_at };
}

function decodeTicket(row, duplicate) {
  return { ticketId: row.ticket_id, traceId: row.trace_id, resultId: row.result_id, status: row.status, duplicate, createdAt: row.created_at, updatedAt: row.updated_at };
}

function decodeDelivery(row, duplicate) {
  return { deliveryId: row.delivery_id, traceId: row.trace_id, ticketId: row.ticket_id, idempotencyKey: row.idempotency_key, payload: JSON.parse(row.payload_json), status: row.status, attempts: row.attempts, nextAttemptAt: row.next_attempt_at, lastError: row.last_error, duplicate, createdAt: row.created_at, updatedAt: row.updated_at };
}

function decodeTriggerDelivery(row, duplicate) {
  return { deliveryId: row.delivery_id, eventId: row.event_id, idempotencyKey: row.idempotency_key, payload: JSON.parse(row.payload_json), status: row.status, attempts: row.attempts, nextAttemptAt: row.next_attempt_at, leaseUntil: row.lease_until, lastError: row.last_error, duplicate, createdAt: row.created_at, updatedAt: row.updated_at };
}

function decodeStep(row) {
  return { stepId: row.step_id, traceId: row.trace_id, sequence: row.sequence, method: row.method, status: row.status, evidenceRefs: JSON.parse(row.evidence_json), createdAt: row.created_at };
}
