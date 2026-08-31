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
import { createMetricsCollector } from "../../shared/run-metrics.js";

import { DeterministicNarrator } from "../../infrastructure/model-gateway/security-narrator.js";
import { evaluateRules } from "../../capabilities/security/rule-engine.js";
import { NoopStateStore } from "../../infrastructure/db/security-state-store.js";
import { correlateThreatEvidence, decisionFromThreatCorrelation } from "../../capabilities/security/threat-evidence.js";
import {
  SEVERITY_GATING_KNOWLEDGE,
  ASSET_CRITICALITY_KNOWLEDGE,
  applySeverityGating,
  applyAssetCriticalityGate
} from "../../capabilities/security/escalation-gates.js";
import { ResilientExecutor, isTransientError } from "../../shared/resilience.js";
import { createTaskContext, isValidState } from "../../domains/task/task-context.js";
import { finalizeJudgment, assertJudgmentGrounded } from "../../domains/judgment/judgment.js";

/**
 * IOC 升级判据知识资产（knowledge/corpus/security/threat-evidence-judgment.json）
 * 的代码侧绑定常量（规范 §9.5 知识-代码绑定）：knowledge_id 与 consumed_by
 * 与资产文件保持一致，供流水线命中留痕与 CLI 反向审计共用。
 */
export const IOC_ESCALATION_KNOWLEDGE = {
  knowledge_id: "kb-security-ioc-escalation",
  consumed_by: [
    { type: "capability", ref: "security.correlate_threat_evidence" },
    { type: "prompt", ref: "security-triage-pipeline#CORRELATE_THREAT_EVIDENCE" }
  ]
};
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
   * @param {Iterable<string>} [deps.knowledgeAblation] 知识消融集合（规范 §9.4，
   *   KNOWLEDGE_ABLATION 逗号分隔 knowledge_id；未配置为空集，行为与现状一致）
   */
  constructor({
    octobus,
    rules,
    threatEvidence = [],
    narrator = new DeterministicNarrator(),
    stateStore = new NoopStateStore(),
    createTraceId = defaultTraceId,
    notifier = null,
    executor = new ResilientExecutor(),
    knowledgeAblation = []
  }) {
    this.octobus = octobus;
    this.rules = rules;
    this.threatEvidence = threatEvidence;
    this.narrator = narrator;
    this.stateStore = stateStore;
    this.createTraceId = createTraceId;
    this.notifier = notifier;
    this.executor = executor;
    this.knowledgeAblation = new Set(knowledgeAblation);
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
    // 终态指标（规范 §11.1）：随状态迁移与能力调用累计，任务终态挂到 result.metrics。
    const collector = createMetricsCollector();

    try {
      await this.#transition({ states, traceId, alertId, state: "RECEIVED", collector });
      await this.#transition({ states, traceId, alertId, state: "ACQUIRE_CONTEXT", collector });
      context = await this.#executorRun(collector, "GetAlertContext", () => this.octobus.getAlertContext(alertId, traceId));
      if (!context.found) {
        const result = await this.#failureResult({ alertId, traceId, states, message: "能力服务未返回该告警。", collector });
        collector.finalize({ manualEscalation: true });
        return result;
      }

      await this.#transition({ states, traceId, alertId, state: "EXTRACT_SIGNALS", context, collector });
      let correlation = correlateThreatEvidence(context, this.threatEvidence);
      // 知识消融（规范 §9.4）：IOC 升级判据被消融时跳过威胁证据关联判定，
      // correlation 置为 matchedCount=0 并打 ablated 标记，判定回退规则引擎。
      const knowledgeAblated = [];
      if (
        this.knowledgeAblation.size > 0 &&
        correlation.matchedCount >= 1 &&
        this.knowledgeAblation.has(IOC_ESCALATION_KNOWLEDGE.knowledge_id)
      ) {
        knowledgeAblated.push(IOC_ESCALATION_KNOWLEDGE.knowledge_id);
        correlation = { matched: [], matchedCount: 0, action: null, ablated: true };
      }
      await this.#transition({ states, traceId, alertId, state: "CORRELATE_THREAT_EVIDENCE", context, correlation, collector });
      await this.#transition({ states, traceId, alertId, state: "APPLY_RULES", context, correlation, collector });
      // 知识消融（规范 §9.4）：被消融的降噪规则不参与判定；若其本会成为命中
      // 判据（含缺证据分支），逐个剔除并留痕，直至命中的是未被消融的规则。
      let activeRules = this.rules;
      if (this.knowledgeAblation.size > 0 && !correlation.matchedCount) {
        for (;;) {
          const candidate = evaluateRules(context, activeRules);
          const matchedRule = (activeRules.rules ?? []).find((rule) => rule.ruleId === candidate.matchedRuleId);
          if (!matchedRule?.knowledge_id || !this.knowledgeAblation.has(matchedRule.knowledge_id)) break;
          knowledgeAblated.push(matchedRule.knowledge_id);
          activeRules = { ...activeRules, rules: (activeRules.rules ?? []).filter((rule) => rule !== matchedRule) };
        }
      }
      // 判定只能来自确定性规则 / 私有证据关联；finalizeJudgment 补齐 evidenceRefs，
      // 无证据引用的结论按规范无效（模型仅做解释，见下方 narrator）。
      const rawDecision = correlation.matchedCount
        ? decisionFromThreatCorrelation(correlation)
        : evaluateRules(context, activeRules);
      // 降噪门控判据（kb-security-severity-gating / kb-security-asset-criticality-escalation）：
      // 仅作用于降噪复核类结论；信号字段未提供视为判据不适用（skipped，不凭空推断）。
      // 门控放行 / 拦截都把信号字段写入证据链；被消融时跳过门控并留痕（规范 §9.4）。
      let gatedDecision = rawDecision;
      const knowledgeHits = [];
      for (const { knowledge, apply } of [
        { knowledge: SEVERITY_GATING_KNOWLEDGE, apply: applySeverityGating },
        { knowledge: ASSET_CRITICALITY_KNOWLEDGE, apply: applyAssetCriticalityGate }
      ]) {
        const { decision: candidate, gate } = apply(gatedDecision, context);
        if (gate.outcome === "skipped") continue;
        if (this.knowledgeAblation.has(knowledge.knowledge_id)) {
          knowledgeAblated.push(knowledge.knowledge_id);
          continue;
        }
        gatedDecision = candidate;
        knowledgeHits.push(knowledge.knowledge_id);
      }
      const decision = assertJudgmentGrounded(finalizeJudgment(gatedDecision));
      // 知识-代码绑定反向留痕（规范 §9.5）：判定阶段命中的知识资产去重挂到结果，
      // 并填入终态指标 knowledge_hits（此前为占位 0）。
      if (correlation.matchedCount >= 1) knowledgeHits.push(IOC_ESCALATION_KNOWLEDGE.knowledge_id);
      if (decision.matchedRuleId) {
        const decisionRule = (this.rules?.rules ?? []).find((rule) => rule.ruleId === decision.matchedRuleId);
        if (decisionRule?.knowledge_id) knowledgeHits.push(decisionRule.knowledge_id);
      }
      collector.metrics.knowledge_hits = new Set(knowledgeHits).size;
      await this.#transition({ states, traceId, alertId, state: "LLM_SUMMARIZE", context, decision, collector });
      let narrative;
      let narrativeSource = this.narrator.kind ?? "llm";
      try {
        narrative = await this.narrator.summarize(context, decision);
      } catch (error) {
        // 模型不可用时降级为确定性叙述并显式标记，禁止静默失败（规范 §11.3）。
        narrative = await new DeterministicNarrator().summarize(context, decision);
        narrativeSource = "fallback";
      }
      collector.metrics.narrative_source = narrativeSource;
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
        knowledgeHits: [...new Set(knowledgeHits)],
        narrative,
        narrativeSource,
        metrics: collector.metrics,
        states: [],
        recorded: false
      };
      // 消融显式标记（规范 §9.4）：仅在本会影响判定的知识被消融时挂载，
      // 未配置消融时不加该字段，行为与现状完全一致。
      if (knowledgeAblated.length > 0) {
        result.knowledgeAblated = [...new Set(knowledgeAblated)];
      }

      await this.#transition({ states, traceId, alertId, state: "DECIDE_ACTION", context, decision, result, collector });
      result.states = [...states];
      await this.#transition({ states, traceId, alertId, state: "PERSIST_RESULT", context, decision, result, collector });
      const recordDelivery = this.stateStore.enqueueDelivery({
        kind: "record_triage_result",
        traceId,
        alertId,
        idempotencyKey: `record:${traceId}`,
        payload: { result }
      });
      const recordOutcome = await this.#deliverEntry(recordDelivery, collector);
      if (recordOutcome.delivered) {
        result.recorded = Boolean(recordOutcome.response.accepted);
        result.recordId = recordOutcome.response.recordId ?? null;
        await this.#transition({ states, traceId, alertId, state: "COMPLETED", context, decision, result, collector });
        result.states = [...states];
      } else {
        result.status = "manual_review";
        result.action = "manual_record_required";
        result.recordingError = recordOutcome.error;
        result.recoveryPending = recordOutcome.recoveryPending;
        await this.#transition({ states, traceId, alertId, state: "NEED_HUMAN", context, decision, result, collector, error: new Error(recordOutcome.error) });
        result.states = [...states];
      }
      await this.#notifyTerminalResult(result, collector);
      collector.finalize({
        manualEscalation: result.status === "manual_review" || result.notification?.status === "manual_recovery_required"
      });
      return result;
    } catch (error) {
      const result = await this.#failureResult({ alertId, traceId, states, message: error.message, collector });
      collector.finalize({ manualEscalation: true });
      try {
        await this.#notifyTerminalResult(result, collector);
      } catch (notificationError) {
        result.notification = { status: "manual_recovery_required", error: notificationError.message };
      }
      return result;
    }
  }

  async #failureResult({ alertId, traceId, states, message, collector }) {
    const result = {
      alertId,
      traceId,
      status: "manual_review",
      action: "manual_investigation_required",
      matchedRuleId: null,
      falsePositiveScore: null,
      evidence: [],
      narrative: `告警 ${alertId} 未完成自动研判：${message}`,
      // 失败路径同样携带已收集到哪算哪的终态指标（规范 §11.1）。
      metrics: collector.metrics,
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
        error: new Error(message),
        collector
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

  async #transition({ states, traceId, alertId, state, context, decision, correlation, result, error, collector }) {
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
    // 快照落库成功即视为该阶段起点（下一次状态迁移时间戳即其终点）。
    collector?.markStage(state);
  }

  /** 经弹性执行器发起的能力调用统一计数（collector 缺省时不计数，如 outbox 恢复）。 */
  #executorRun(collector, operation, action) {
    return collector
      ? collector.runCapability(() => this.executor.run(operation, action))
      : this.executor.run(operation, action);
  }

  async #notifyTerminalResult(result, collector) {
    if (!this.notifier) return;
    const entry = this.stateStore.enqueueDelivery({
      kind: "wecom_result_notification",
      traceId: result.traceId,
      alertId: result.alertId,
      idempotencyKey: `wecom:${result.traceId}:result`,
      payload: { result: notificationPayload(result) }
    });
    const outcome = await this.#deliverEntry(entry, collector);
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

  async #deliverEntry(entry, collector) {
    try {
      let response;
      if (entry.kind === "record_triage_result") {
        response = await this.#executorRun(collector, "RecordTriageResult", () => this.octobus.recordTriageResult(entry.payload.result, entry.traceId, entry.idempotencyKey));
      } else if (entry.kind === "wecom_result_notification") {
        if (!this.notifier) throw new Error("Enterprise WeChat notifier is not configured");
        response = await this.#executorRun(collector, "WeComResultNotification", () => this.notifier.sendResult(entry.payload.result));
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
          matchedEvidence: correlation.matched,
          // 消融留痕：IOC 判据被消融跳过关联判定时显式可见（正常路径不带该字段）。
          ...(correlation.ablated ? { ablated: true } : {})
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
