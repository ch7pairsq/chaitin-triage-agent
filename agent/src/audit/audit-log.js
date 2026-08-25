/**
 * 留痕层：追加写 NDJSON 审计日志（规范 §10.2、§5.2 audit/）。
 *
 * 与 SQLite 业务留痕（workflow_snapshots / delivery_outbox）分离：
 * - 审计日志只追加（append-only），一行一条 JSON，不更新、不删除；
 * - 每次运行至少一条终态记录：结论 + 证据引用 + 原始入参 + 模型来源
 *   + prompt 版本，支持任意时刻回放；
 * - OctoBus 侧 access.log（网关 NDJSON）是能力调用留痕的权威输入，
 *   部署时与本日志统一归档（见 README 可观测性一节）。
 * 写入失败不静默：抛出错误由调用方（CLI）显式呈现给运维。
 */
import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";

import { ERROR_CODES } from "../shared/errors.js";

/** 审计日志写入器（进程内复用一个文件句柄语义，逐条 append）。 */
export class AuditLog {
  /**
   * @param {object} options
   * @param {string} options.logPath 审计日志文件路径（自动创建父目录）
   */
  constructor({ logPath }) {
    if (!logPath) throw new Error("AuditLog 需要 logPath");
    this.logPath = path.resolve(logPath);
    mkdirSync(path.dirname(this.logPath), { recursive: true });
  }

  /**
   * 追加一条审计记录。
   * @param {object} record 任意可序列化对象；建议字段见模块头注释。
   */
  append(record) {
    try {
      appendFileSync(this.logPath, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
      return true;
    } catch (error) {
      const wrapped = new Error(`审计日志写入失败（${this.logPath}）：${error.message}`);
      wrapped.code = ERROR_CODES.AUDIT_WRITE_FAILED;
      throw wrapped;
    }
  }
}

/** 从环境变量装配审计日志（未配置路径时使用 runtime/audit.log，已被 .gitignore 覆盖）。 */
export function auditLogFromEnvironment(environment = process.env) {
  const logPath = environment.TRIAGE_AUDIT_LOG_PATH
    ? path.resolve(environment.TRIAGE_AUDIT_LOG_PATH)
    : path.resolve(process.cwd(), "runtime", "audit.log");
  return new AuditLog({ logPath });
}
