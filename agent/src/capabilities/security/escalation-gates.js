/**
 * 领域层：降噪门控判据（纯函数，零 IO，规范 §5.2 capabilities/security/）。
 *
 * 知识资产（规范 §8/§9.5 知识-代码绑定）：
 * - knowledge/corpus/security/severity-gating.json（kb-security-severity-gating）
 * - knowledge/corpus/security/asset-criticality-escalation.json（kb-security-asset-criticality-escalation）
 *
 * 门控只作用于降噪复核类结论（action = suppress_with_review）：
 * - severity ∈ {high, critical} → 降级人工确认（高危告警禁止自动降噪）；
 * - assetCriticality = critical，或 high 且 falsePositiveScore < 0.9 → 降级人工确认；
 * - 信号字段未提供视为该判据不适用（skipped）：不凭空推断等级、不阻断既有降噪路径；
 * - 门控放行（passed）与拦截（blocked）都把信号字段写入证据链，供 evidenceRefs 留痕。
 */

/** 严重度门控知识资产绑定常量（与提交入库的 JSON 资产保持一致）。 */
export const SEVERITY_GATING_KNOWLEDGE = {
  knowledge_id: "kb-security-severity-gating",
  consumed_by: [
    { type: "capability", ref: "security.gates.apply_severity" },
    { type: "prompt", ref: "security-triage-pipeline#APPLY_RULES" }
  ]
};

/** 关键资产提级知识资产绑定常量（与提交入库的 JSON 资产保持一致）。 */
export const ASSET_CRITICALITY_KNOWLEDGE = {
  knowledge_id: "kb-security-asset-criticality-escalation",
  consumed_by: [
    { type: "capability", ref: "security.gates.apply_asset_criticality" },
    { type: "prompt", ref: "security-triage-pipeline#APPLY_RULES" }
  ]
};

const SUPPRESS_ACTION = "suppress_with_review";
const HIGH_SEVERITIES = new Set(["high", "critical"]);
const HIGH_CRITICALITY_SCORE_FLOOR = 0.9;

function isSuppression(decision) {
  return decision?.action === SUPPRESS_ACTION;
}

function hasValue(value) {
  return value !== undefined && value !== null && value !== "";
}

function gateEvidence(field, label, value) {
  return { field, label, value, present: true };
}

function skipped(knowledge, reason) {
  return { outcome: "skipped", knowledgeId: knowledge.knowledge_id, reason };
}

function withGateEvidence(decision, evidence, extra = {}) {
  return { ...decision, evidence: [...(decision.evidence ?? []), evidence], ...extra };
}

/**
 * 严重度门控：高危告警（severity ∈ {high, critical}）的降噪复核结论降级人工确认。
 * @returns {{decision: object, gate: {outcome: "passed"|"blocked"|"skipped", knowledgeId: string}}}
 */
export function applySeverityGating(decision, context) {
  if (!isSuppression(decision)) {
    return { decision, gate: skipped(SEVERITY_GATING_KNOWLEDGE, "结论非降噪复核类，门控不适用") };
  }
  const severity = context?.severity;
  if (!hasValue(severity)) {
    return { decision, gate: skipped(SEVERITY_GATING_KNOWLEDGE, "上下文未提供 severity，判据不适用") };
  }
  const evidence = gateEvidence("severityGate", "严重度门控", severity);
  if (HIGH_SEVERITIES.has(String(severity).toLowerCase())) {
    return {
      decision: withGateEvidence(decision, evidence, {
        status: "manual_review",
        action: "manual_confirm_required",
        reason: `${decision.reason}；severity=${severity} 命中降噪门控判据，降噪复核让位人工确认。`
      }),
      gate: { outcome: "blocked", knowledgeId: SEVERITY_GATING_KNOWLEDGE.knowledge_id }
    };
  }
  return {
    decision: withGateEvidence(decision, evidence),
    gate: { outcome: "passed", knowledgeId: SEVERITY_GATING_KNOWLEDGE.knowledge_id }
  };
}

/**
 * 关键资产提级：critical 资产（或 high 且降噪置信度 < 0.9）上的降噪复核结论降级人工确认。
 * @returns {{decision: object, gate: {outcome: "passed"|"blocked"|"skipped", knowledgeId: string}}}
 */
export function applyAssetCriticalityGate(decision, context) {
  if (!isSuppression(decision)) {
    return { decision, gate: skipped(ASSET_CRITICALITY_KNOWLEDGE, "结论非降噪复核类，门控不适用") };
  }
  const criticality = context?.assetCriticality;
  if (!hasValue(criticality)) {
    return { decision, gate: skipped(ASSET_CRITICALITY_KNOWLEDGE, "上下文未提供 assetCriticality，判据不适用") };
  }
  const evidence = gateEvidence("assetCriticalityGate", "关键资产门控", criticality);
  const normalized = String(criticality).toLowerCase();
  const score = decision.falsePositiveScore;
  const mustEscalate = normalized === "critical"
    || (normalized === "high" && typeof score === "number" && score < HIGH_CRITICALITY_SCORE_FLOOR);
  if (mustEscalate) {
    return {
      decision: withGateEvidence(decision, evidence, {
        status: "manual_review",
        action: "manual_confirm_required",
        reason: `${decision.reason}；assetCriticality=${criticality} 命中关键资产提级判据，降噪复核让位人工确认。`
      }),
      gate: { outcome: "blocked", knowledgeId: ASSET_CRITICALITY_KNOWLEDGE.knowledge_id }
    };
  }
  return {
    decision: withGateEvidence(decision, evidence),
    gate: { outcome: "passed", knowledgeId: ASSET_CRITICALITY_KNOWLEDGE.knowledge_id }
  };
}
