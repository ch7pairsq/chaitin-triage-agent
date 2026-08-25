/**
 * 共享层：统一错误码（规范 §5.2 shared/）。
 *
 * 所有基础设施实现抛出的错误都携带稳定 code，便于：
 * - 编排层按 code 决定重试 / 熔断 / 升级人工（配合 shared/resilience.js）；
 * - 留痕层按 code 归类失败原因，禁止静默吞错。
 */

/** 全局错误码枚举（追加不改名，保持审计日志可回放）。 */
export const ERROR_CODES = Object.freeze({
  /** OctoBus 能力调用失败（网关 / 超时 / 非 2xx / 非法响应）。 */
  OCTOBUS_CALL_FAILED: "OCTOBUS_CALL_FAILED",
  /** 企业微信通知失败（限流 / 非 0 errcode / 超时）。 */
  WECOM_NOTIFY_FAILED: "WECOM_NOTIFY_FAILED",
  /** 配置缺失或非法（环境变量、组合根装配）。 */
  CONFIG_INVALID: "CONFIG_INVALID",
  /** 留痕写入失败（SQLite 快照 / 审计日志）。 */
  AUDIT_WRITE_FAILED: "AUDIT_WRITE_FAILED"
});

/**
 * 应用统一错误基类：message 面向运维，code 面向程序分支。
 * retryable 语义与 shared/resilience.js 的 isTransientError 对齐。
 */
export class AppError extends Error {
  /**
   * @param {string} message 人读错误信息
   * @param {{code?: string, retryable?: boolean, status?: number}} [options]
   */
  constructor(message, { code = ERROR_CODES.CONFIG_INVALID, retryable = false, status } = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}
