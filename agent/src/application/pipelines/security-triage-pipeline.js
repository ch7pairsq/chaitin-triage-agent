/**
 * 应用层：安全告警研判流水线（规范 §4 八层中的「编排/判定」用例流水线）。
 *
 * 业务闭环五阶段（规范红线 1）：
 *   触发（CLI/scheduler → TaskContext）→ 取数（OctoBus GetAlertContext）
 *   → 判定（capabilities 规则引擎 + 私有证据关联，模型仅解释）
 *   → 处置（RecordTriageResult / 企业微信脱敏通知 / 高危升级人工）
 *   → 留痕（SQLite 状态快照 + outbox + trace_id 贯穿）
 * 状态机以代码固化：每次状态迁移先落库再执行下一个副作用，
 * 运维可据此完整重建一次失败的运行。
 */
import { createTraceId as defaultTraceId } from "../../shared/trace.js";

import { DeterministicNarrator } from "../../infrastructure/model-gateway/security-narrator.js";
import { evaluateRules } from "../../capabilities/security/rule-engine.js";
import { NoopStateStore } from "../../infrastructure/db/security-state-store.js";
import { correlateThreatEvidence, decisionFromThreatCorrelation } from "../../capabilities/security/threat-evidence.js";
import { ResilientExecutor, isTransientError } from "../../shared/resilience.js";
import { createTaskContext, isValidState } from "../../domains/task/task-context.js";
import { finalizeJudgment } from "../../domains/judgment/judgment.js";
export class SecurityTriageAgent {
  /**
   * @param {object} deps 依赖注入（Port 实现，见 application/ports.js）
   * @param {object} deps.octobus 能力总线口（取数 / 结论上报）
   * @param {object} deps.rules 降噪规则知识资产（corpus 加载后注入）
   * @param {Array} [deps.threatEvidence] 私有威胁证据包（仅标识符关联）
   * @param {object} [deps.narrator] 模型解释口（只解释，不改决策）
   * @param {object} [deps.stateStore] 留痕口（SQLite 快照 + outbox）
   * @param {() => string} [deps.createTraceId] trace 工厂（测试注入）
   * @param {object} [deps.notifier] 处置通知口（企业微信脱敏通知）
   * @param {object} [deps.executor] 弹性执行器（有界重试 + 熔断）
   */
  constructor({
    octobus,
    rules,
    threatEvidence = [],
    narrator = new DeterministicNarrator(),
    stateStore = new NoopStateStore(),
    createTraceId = defaultTraceId,
    notifier = null,
    executor = new ResilientExecutor()
  }) {
    this.octobus = octobus;
    this.rules = rules;
    this.threatEvidence = threatEvidence;
    this.narrator = narrator;
    this.stateStore = stateStore;
    this.createTraceId = createTraceId;
    this.notifier = notifier;
    this.executor = executor;
  }

  async triage({ alertId }) {
    // 触发层标准化：TaskContext 统一生成 traceId / taskId 并贯穿全链路。
    const taskContext = createTaskContext({
      workflow: "security",
      trigger: "cli",
      subject: { alertId },
      createId: this.createTraceId
    });
    const traceId = taskContext.traceId;
    const states = [];
    let context;

    try {
      await this.#transition({ states, traceId, alertId, state: "RECEIVED" });
      await this.#transition({ states, traceId, alertId, state: "ACQUIRE_CONTEXT" });
      context = await this.executor.run("GetAlertContext", () => this.octobus.getAlertContext(alertId, traceId));
      if (!context.found) {
        return this.#failureResult({ alertId, traceId, states, message: "能力服务未返回该告警。" });
      }

      await this.#transition({ states, traceId, alertId, state: "EXTRACT_SIGNALS", context });
      const correlation = correlateThreatEvidence(context, this.threatEvidence);
      await this.#transition({ states, traceId, alertId, state: "CORRELATE_THREAT_EVIDENCE", context, correlation });
      await this.#transition({ states, traceId, alertId, state: "APPLY_RULES", context, correlation });
      // 判定只能来自确定性规则 / 私有证据关联；finalizeJudgment 补齐 evidenceRefs，
      // 无证据引用的结论按规范无效（模型仅做解释，见下方 narrator）。
      const rawDecision = correlation.matchedCount
        ? decisionFromThreatCorrelation(correlation)
        : evaluateRules(context, this.rules);
      const decision = finalizeJudgment(rawDecision);
      await this.#transition({ states, traceId, alertId, state: "LLM_SUMMARIZE", context, decision });
      let narrative;
      let narrativeSource = this.narrator.kind ?? "llm";
      try {
        narrative = await this.narrator.summarize(context, decision);
      } catch (error) {
        // 模型不可用时降级为确定性叙述并显式标记，禁止静默失败（规范 §11.3）。
        narrative = await new DeterministicNarrator().summarize(context, decision);
        narrativeSource = "fallback";
      }
      const result = {
        alertId,
        traceId,
        status: decision.status,
        action: decision.action,
        matchedRuleId: decision.matchedRuleId,
        falsePositiveScore: decision.falsePositiveScore,
        evidence: decision.evidence,
        evidenceRefs: decision.evidenceRefs,
        threatEvidenceMatched: correlation.matchedCount,
        narrative,
        narrativeSource,
        states: [],
        recorded: false
      };

      await this.#transition({ states, traceId, alertId, state: "DECIDE_ACTION", context, decision, result });
      result.states = [...states];
      await this.#transition({ states, traceId, alertId, state: "PERSIST_RESULT", context, decision, result });
      const recordDelivery = this.stateStore.enqueueDelivery({
        kind: "record_triage_result",
        traceId,
        alertId,
        idempotencyKey: `record:${traceId}`,
        payload: { result }
      });
      const recordOutcome = await this.#deliverEntry(recordDelivery);
      if (recordOutcome.delivered) {
        result.recorded = Boolean(recordOutcome.response.accepted);
        result.recordId = recordOutcome.response.recordId ?? null;
        await this.#transition({ states, traceId, alertId, state: "COMPLETED", context, decision, result });
        result.states = [...states];
      } else {
        result.status = "manual_review";
        result.action = "manual_record_required";
        result.recordingError = recordOutcome.error;
        result.recoveryPending = recordOutcome.recoveryPending;
        await this.#transition({ states, traceId, alertId, state: "NEED_HUMAN", context, decision, result, error: new Error(recordOutcome.error) });
        result.states = [...states];
      }
      await this.#notifyTerminalResult(result);
      return result;
    } catch (error) {
      const result = await this.#failureResult({ alertId, traceId, states, message: error.message });
      try {
        await this.#notifyTerminalResult(result);
      } catch (notificationError) {
        result.notification = { status: "manual_recovery_required", error: notificationError.message };
      }
      return result;
    }
  }

  async #failureResult({ alertId, traceId, states, message }) {
    const result = {
      alertId,
      traceId,
      status: "manual_review",
      action: "manual_investigation_required",
      matchedRuleId: null,
      falsePositiveScore: null,
      evidence: [],
      narrative: `告警 ${alertId} 未完成自动研判：${message}`,
      states: [],
      recorded: false
    };
    try {
      await this.#transition({
        states,
        traceId,
        alertId,
        state: "NEED_HUMAN",
        result,
        error: new Error(message)
      });
      result.states = [...states];
    } catch (snapshotError) {
      // A persistence failure must be visible to operators, but cannot mask the
      // original reason that this run was transferred to manual investigation.
      result.snapshotError = snapshotError.message;
      result.states = [...states, "NEED_HUMAN"];
    }
    return result;
  }

  async #transition({ states, traceId, alertId, state, context, decision, correlation, result, error }) {
    // 状态机合法性由领域层统一校验，禁止快照写入未知状态。
    if (!isValidState("security", state)) {
      throw new Error(`非法状态迁移：${state}`);
    }
    states.push(state);
    try {
      await this.stateStore.save({
        traceId,
        alertId,
        sequence: states.length,
        state,
        payload: snapshotPayload({ context, decision, correlation, result, error })
      });
    } catch (snapshotError) {
      states.pop();
      throw new Error(`State snapshot failed at ${state}: ${snapshotError.message}`);
    }
  }

  async #notifyTerminalResult(result) {
    if (!this.notifier) return;
    const entry = this.stateStore.enqueueDelivery({
      kind: "wecom_result_notification",
      traceId: result.traceId,
      alertId: result.alertId,
      idempotencyKey: `wecom:${result.traceId}:result`,
      payload: { result: notificationPayload(result) }
    });
    const outcome = await this.#deliverEntry(entry);
    result.notification = outcome.delivered
      ? { status: "delivered" }
      : { status: outcome.recoveryPending ? "pending_recovery" : "manual_recovery_required" };
  }

  async recoverOutbox({ limit = 20, now } = {}) {
    const entries = this.stateStore.claimDueDeliveries({ limit, now });
    const outcomes = [];
    for (const entry of entries) outcomes.push({ idempotencyKey: entry.idempotencyKey, ...(await this.#deliverEntry(entry)) });
    return outcomes;
  }

  async #deliverEntry(entry) {
    try {
      let response;
      if (entry.kind === "record_triage_result") {
        response = await this.executor.run("RecordTriageResult", () => this.octobus.recordTriageResult(entry.payload.result, entry.traceId, entry.idempotencyKey));
      } else if (entry.kind === "wecom_result_notification") {
        if (!this.notifier) throw new Error("Enterprise WeChat notifier is not configured");
        response = await this.executor.run("WeComResultNotification", () => this.notifier.sendResult(entry.payload.result));
      } else {
        throw new Error(`unsupported outbox delivery type: ${entry.kind}`);
      }
      this.stateStore.markDeliveryDelivered(entry.id);
      return { delivered: true, response };
    } catch (error) {
      const tooManyAttempts = (entry.attempts ?? 0) >= 9;
      const retryable = isTransientError(error) && !tooManyAttempts;
      if (retryable) {
        const delayMs = Math.min(15 * 60_000, 30_000 * (2 ** Math.min(entry.attempts ?? 0, 4)));
        this.stateStore.markDeliveryRetry(entry.id, { error: error.message, delayMs });
      } else {
        this.stateStore.markDeliveryManual(entry.id, { error: error.message });
      }
      return { delivered: false, recoveryPending: retryable, error: error.message };
    }
  }
}

function notificationPayload(result) {
  return {
    alertId: result.alertId,
    traceId: result.traceId,
    status: result.status,
    action: result.action,
    recorded: Boolean(result.recorded)
  };
}

/** 快照只保留恢复 / 复核所必需的证据字段；绝不快照密钥、原始日志或未脱敏 IOC。 */
function snapshotPayload({ context, decision, correlation, result, error }) {
  return {
    context: context
      ? {
          alertId: context.alertId,
          title: context.title,
          severity: context.severity,
          sourceAssetTag: context.sourceAssetTag,
          eventTime: context.eventTime,
          approvedScanWindow: context.approvedScanWindow,
          destinationPort: context.destinationPort,
          assetCriticality: context.assetCriticality
        }
      : undefined,
    correlation: correlation
      ? {
          matchedCount: correlation.matchedCount,
          matchedEvidence: correlation.matched
        }
      : undefined,
    decision: decision
      ? {
          status: decision.status,
          action: decision.action,
          matchedRuleId: decision.matchedRuleId,
          falsePositiveScore: decision.falsePositiveScore,
          evidence: decision.evidence,
          evidenceRefs: decision.evidenceRefs ?? []
        }
      : undefined,
    result: result
      ? {
          status: result.status,
          action: result.action,
          recordId: result.recordId ?? null,
          recorded: result.recorded
        }
      : undefined,
    error: error ? error.message : undefined
  };
}
