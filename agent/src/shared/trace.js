/**
 * 共享层：trace_id / task_id 生成（规范 §11.1 追踪三件套的基础）。
 *
 * trace_id 贯穿「触发 → 取数 → 判定 → 处置 → 留痕」全链路：
 * - 写入 OctoBus 请求头 x-octobus-ext-business-request-id；
 * - 写入 SQLite 状态快照与审计日志；
 * - 测试可通过注入固定工厂实现确定性断言。
 */
import { randomUUID } from "node:crypto";

/** 生成一个新的追踪标识（UUID v4）。 */
export function createTraceId() {
  return randomUUID();
}

/** 生成任务标识；当前实现与 trace 同源，保持一对一便于回放。 */
export function createTaskId() {
  return randomUUID();
}

/** 校验外部传入的 trace_id 是否为合法 UUID（用于状态查询入参）。 */
export function isValidTraceId(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value ?? ""));
}
