/**
 * 领域层：TaskContext 标准化与任务状态机（规范 §5.2 domains/task/）。
 *
 * 触发层（scheduler / webhook / CLI）解析入参后，必须先构造标准化
 * TaskContext 再进入编排层；traceId / taskId 在此统一生成并贯穿
 * 「触发 → 取数 → 判定 → 处置 → 留痕」全链路。
 * 本模块为纯函数：零 IO 依赖，可 100% 单测。
 */

/** 安全告警研判状态机（有序，快照按序落库）。 */
export const SECURITY_TRIAGE_STATES = Object.freeze([
  "RECEIVED",
  "ACQUIRE_CONTEXT",
  "EXTRACT_SIGNALS",
  "CORRELATE_THREAT_EVIDENCE",
  "APPLY_RULES",
  "LLM_SUMMARIZE",
  "DECIDE_ACTION",
  "PERSIST_RESULT",
  "COMPLETED",
  "NEED_HUMAN"
]);

/** 恶意样本研判状态机（键值形式，含工具重试与熔断观察态）。 */
export const MALWARE_TRIAGE_STATES = Object.freeze({
  RECEIVED: "RECEIVED",
  RETRIEVE_REPORT: "RETRIEVE_REPORT",
  TOOL_RETRY: "TOOL_RETRY",
  TOOL_CIRCUIT_OPEN: "TOOL_CIRCUIT_OPEN",
  NORMALIZE_FEATURES: "NORMALIZE_FEATURES",
  APPLY_RULES: "APPLY_RULES",
  RETRIEVE_KNOWLEDGE: "RETRIEVE_KNOWLEDGE",
  REFUSE_INSUFFICIENT_EVIDENCE: "REFUSE_INSUFFICIENT_EVIDENCE",
  LLM_ANALYZE: "LLM_ANALYZE",
  DRAFT_YARA: "DRAFT_YARA",
  VALIDATE_CANDIDATE: "VALIDATE_CANDIDATE",
  CREATE_REVIEW_TASK: "CREATE_REVIEW_TASK",
  PERSIST_RESULT: "PERSIST_RESULT",
  COMPLETED: "COMPLETED",
  NEED_HUMAN: "NEED_HUMAN",
  NOTIFY_RESULT: "NOTIFY_RESULT"
});

/** 校验状态是否属于指定工作流的状态机（防止快照写入非法状态）。 */
export function isValidState(workflow, state) {
  if (workflow === "security") return SECURITY_TRIAGE_STATES.includes(state);
  if (workflow === "malware") return Object.values(MALWARE_TRIAGE_STATES).includes(state);
  return false;
}

/**
 * 构造标准化任务上下文。
 * @param {object} input
 * @param {"security"|"malware"} input.workflow 工作流（由 CLI flag 决定，不受 prompt 影响）
 * @param {string} input.trigger 触发来源（cli / scheduler / event / conversation）
 * @param {object} input.subject 最小化任务主体（alertId 或 sampleId+sha256）
 * @param {() => string} [input.createId] 标识生成工厂（测试注入固定值）
 * @returns {{taskId: string, traceId: string, workflow: string, trigger: string, subject: object, createdAt: string}}
 */
export function createTaskContext({ workflow, trigger, subject, createId }) {
  if (workflow !== "security" && workflow !== "malware") {
    throw new Error(`未知工作流：${workflow}（仅支持 security / malware）`);
  }
  if (!trigger || typeof trigger !== "string") {
    throw new Error("TaskContext 缺少 trigger（cli / scheduler / event / conversation）");
  }
  if (!subject || typeof subject !== "object") {
    throw new Error("TaskContext 缺少 subject（最小化任务主体）");
  }
  const id = createId ? createId() : undefined;
  return {
    taskId: id,
    traceId: id,
    workflow,
    trigger,
    subject,
    createdAt: new Date().toISOString()
  };
}
