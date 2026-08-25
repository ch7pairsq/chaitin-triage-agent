/**
 * 共享层：结构化 JSON 日志（规范 §11.1 可观测性三件套之「日志」）。
 *
 * 每行一个 JSON 对象，标准字段：
 *   ts / level / event / trace_id / task_id / capability_id / capset_id / model / prompt_version
 * 可观测字段按需附加（fields 透传）。输出到 stderr，避免污染 CLI 的 stdout
 * JSON 结果（stdout 只用于机器可读的工作流产物）。
 */

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });

let minLevel = LEVELS[process.env.LOG_LEVEL ?? "info"] ?? LEVELS.info;

/** 运行时调整最低日志级别（测试注入用）。 */
export function setLogLevel(level) {
  minLevel = LEVELS[level] ?? minLevel;
}

/**
 * 输出一条结构化日志。
 * @param {"debug"|"info"|"warn"|"error"} level 级别
 * @param {string} event 事件名（如 workflow.completed、octobus.call_failed）
 * @param {Record<string, unknown>} fields 附加字段（trace_id 等标准字段优先从这里取）
 */
export function structuredLog(level, event, fields = {}) {
  if ((LEVELS[level] ?? LEVELS.info) < minLevel) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...fields
  });
  process.stderr.write(`${line}\n`);
}

/** 便捷封装。 */
export const logger = {
  debug: (event, fields) => structuredLog("debug", event, fields),
  info: (event, fields) => structuredLog("info", event, fields),
  warn: (event, fields) => structuredLog("warn", event, fields),
  error: (event, fields) => structuredLog("error", event, fields)
};
