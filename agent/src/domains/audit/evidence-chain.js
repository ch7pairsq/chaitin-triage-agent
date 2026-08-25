/**
 * 领域层：证据链记录模型（规范 §10.1 / §5.2 domains/audit/）。
 *
 * 证据链是结论可回放、可审计的核心结构：每条证据记录"由哪个能力产出、
 * 确定性取值是什么、何时取到、来源是什么"。留痕层（audit/audit-log.js
 * 与 SQLite 快照）消费这些纯构造函数，本模块自身零 IO。
 */

let evidenceSequence = 0;

/**
 * 构造一条证据链记录（规范 §10.1 数据结构）。
 * @param {object} input
 * @param {string} input.taskId 任务标识
 * @param {string} input.producedBy 产出能力（capability_id，如 security.rules.evaluate_false_positive）
 * @param {object} input.value 确定性取值（必须可 JSON 序列化）
 * @param {string} [input.source] 来源（case / 报告 source / 登记册引用）
 * @param {string} [input.fetchedAt] 取数时间（缺省为当前时间）
 */
export function createEvidenceChainRecord({ taskId, producedBy, value, source, fetchedAt }) {
  if (!taskId) throw new Error("证据链记录缺少 taskId");
  if (!producedBy) throw new Error("证据链记录缺少 producedBy（产出能力 capability_id）");
  evidenceSequence += 1;
  return {
    evidenceId: `evt_${String(evidenceSequence).padStart(4, "0")}`,
    taskId,
    producedBy,
    value,
    fetchedAt: fetchedAt ?? new Date().toISOString(),
    source: source ?? null
  };
}

/**
 * 从研判结论提取证据引用列表（规范 §10.2：结论必须携带 evidence_refs）。
 * @param {object} judgment 已 finalizeJudgment 的结论
 * @returns {string[]} 证据引用（字段名 / 证据 ID / 证据标签）
 */
export function evidenceRefsFromJudgment(judgment) {
  if (Array.isArray(judgment?.evidenceRefs)) return judgment.evidenceRefs;
  return (judgment?.evidence ?? [])
    .map((item) => item.field ?? item.evidenceId ?? item.tag ?? null)
    .filter(Boolean);
}

/**
 * 构造一次留痕快照的最小化审计负载：只保留回放与复核所需字段，
 * 永不包含原始样本、路径、密钥或未脱敏 IOC。
 */
export function minimalAuditPayload({ taskContext, state, judgment, error }) {
  return {
    workflow: taskContext?.workflow,
    trigger: taskContext?.trigger,
    state,
    decision: judgment
      ? {
          status: judgment.status ?? judgment.action ?? null,
          action: judgment.action ?? null,
          evidenceRefs: evidenceRefsFromJudgment(judgment)
        }
      : undefined,
    error: error ? String(error.message ?? error) : undefined
  };
}
