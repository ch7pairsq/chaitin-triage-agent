/**
 * 领域层：判定结论模型与定级枚举（规范 §5.2 domains/judgment/）。
 *
 * 约束（规范 §6 能力分工 / §10.2 硬性规则）：
 * - 结论只能由确定性规则（capabilities/）产出，模型仅解释；
 * - 任何结论必须携带 evidenceRefs（证据引用），否则结论无效；
 * - 证据不足走显式分支（manual_review / REFUSE），禁止模型"补全"数据。
 */

/** 安全告警研判结论状态枚举。 */
export const TRIAGE_STATUS = Object.freeze({
  /** 命中降噪规则，建议进入降噪复核。 */
  NEEDS_REVIEW: "needs_review",
  /** 证据不足或流程失败，转人工。 */
  MANUAL_REVIEW: "manual_review",
  /** 未命中降噪规则或命中私有威胁证据，升级开案。 */
  ESCALATE: "escalate"
});

/** 恶意样本处置动作枚举（结论动作只能取这些显式值）。 */
export const MALWARE_ACTIONS = Object.freeze({
  /** 高危或不确定，必须人工复核（YARA 不自动发布）。 */
  HUMAN_REVIEW_REQUIRED: "HUMAN_REVIEW_REQUIRED",
  /** 确定性证据与 RAG 来源均不足，拒绝生成结论。 */
  REFUSE_INSUFFICIENT_EVIDENCE: "REFUSE_INSUFFICIENT_EVIDENCE"
});

/**
 * 为判定结论补充标准化的证据引用（evidenceRefs）。
 * 规范 §10.2：模型 / 流程产出的每条结论必须携带 evidence_refs，否则结论无效。
 * @param {object} decision 规则引擎产出的判定结论
 * @returns {object} 原结论（浅拷贝）+ evidenceRefs 字符串数组
 */
export function finalizeJudgment(decision) {
  const evidence = Array.isArray(decision?.evidence) ? decision.evidence : [];
  return {
    ...decision,
    evidenceRefs: evidence
      .map((item) => item.field ?? item.evidenceId ?? item.tag ?? null)
      .filter(Boolean)
  };
}

/** 断言结论携带证据引用（供留痕层 / 输出过滤做最后一道校验）。 */
export function assertJudgmentGrounded(judgment) {
  if (!Array.isArray(judgment?.evidenceRefs)) {
    throw new Error("结论缺少 evidenceRefs：无证据引用的结论按规范无效");
  }
  return judgment;
}
