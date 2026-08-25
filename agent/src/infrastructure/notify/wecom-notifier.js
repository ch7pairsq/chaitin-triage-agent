/**
 * 基础设施层：企业微信出站通知（规范 §4 处置层通知通道）。
 *
 * 合并原 security / malware 两份重复实现，统一约定：
 * - 出站单向：只向官方群机器人 webhook 发送，无任何回读 / 指令通道；
 * - 脱敏：格式化函数只保留结论级字段，绝不包含 narrative、证据、原始
 *   IOC、样本哈希、YARA 文本等敏感内容；
 * - 限流：串行发送并保持群机器人最小间隔，低于企业微信频控阈值；
 * - 失败可见：抛 WeComNotificationError（retryable 语义），交由 outbox
 *   重试或升级人工，禁止静默失败。
 */
import { ERROR_CODES } from "../../shared/errors.js";

function truncateUtf8(value, maxBytes) {
  const bytes = Buffer.from(String(value ?? ""), "utf8");
  return bytes.length <= maxBytes ? bytes.toString("utf8") : `${bytes.subarray(0, Math.max(0, maxBytes - 3)).toString("utf8")}...`;
}

function cleanField(value, fallback = "-") {
  const text = String(value ?? fallback).replace(/[\r\n\t]/g, " ").trim();
  return truncateUtf8(text || fallback, 256);
}

/** 企业微信通知失败：status 供频控判断，retryable 供 outbox 重试决策。 */
export class WeComNotificationError extends Error {
  constructor(message, { status, retryable = false } = {}) {
    super(message);
    this.name = "WeComNotificationError";
    this.code = ERROR_CODES.WECOM_NOTIFY_FAILED;
    this.status = status;
    this.retryable = retryable;
  }
}

/** 校验必须是企业微信官方群机器人 webhook，拒绝任意 URL 注入。 */
export function validateWeComWebhookUrl(webhookUrl) {
  let url;
  try {
    url = new URL(webhookUrl);
  } catch {
    throw new Error("WECOM_WEBHOOK_URL must be a valid URL");
  }
  if (url.protocol !== "https:" || url.hostname !== "qyapi.weixin.qq.com" || url.pathname !== "/cgi-bin/webhook/send" || !url.searchParams.get("key")) {
    throw new Error("WECOM_WEBHOOK_URL must be an official Enterprise WeChat group robot webhook");
  }
  return url.toString();
}

/** security 域通知内容：只保留结论级字段，排除 narrative / 证据 / 私有 IOC。 */
export function formatWeComResult(result) {
  return truncateUtf8([
    "【安全运营研判结果】",
    `告警：${cleanField(result.alertId)}`,
    `状态：${cleanField(result.status)}`,
    `建议动作：${cleanField(result.action)}`,
    `追踪号：${cleanField(result.traceId)}`,
    `结果留存：${result.recorded ? "已完成" : "待恢复"}`
  ].join("\n"), 1800);
}

/** malware 域通知内容：排除样本哈希、报告内容、YARA 文本与原始指标。 */
export function formatMalwareTriageResult(result) {
  return truncateUtf8([
    "【恶意样本研判结果】",
    `样本引用：${cleanField(result.sampleId)}`,
    `风险：${cleanField(result.assessment?.severity, "未完成")}`,
    `处理：${cleanField(result.action)}`,
    `规则候选：${cleanField(result.candidate?.status, "未生成")}`,
    `追踪号：${cleanField(result.traceId)}`
  ].join("\n"), 1800);
}

/**
 * 企业微信 webhook 通知器。
 * 构造时注入 format 决定脱敏模板（security / malware 各自的格式化函数），
 * 发送骨架（限流串行、超时、错误分类）完全复用。
 */
export class WeComWebhookNotifier {
  /**
   * @param {object} options
   * @param {string} options.webhookUrl 官方群机器人 webhook
   * @param {Function} [options.format] 结果脱敏格式化函数（默认 security 模板）
   * @param {number} [options.timeoutMs] 单次请求超时（默认 5000）
   * @param {number} [options.minIntervalMs] 相邻两次发送的最小间隔（默认 3000）
   */
  constructor({ webhookUrl, format = formatWeComResult, timeoutMs = 5000, minIntervalMs = 3000, fetchImpl = fetch, now = () => Date.now(), sleep = delay => new Promise(resolve => setTimeout(resolve, delay)) }) {
    this.webhookUrl = validateWeComWebhookUrl(webhookUrl);
    this.format = format;
    this.timeoutMs = Math.max(500, Math.min(Number(timeoutMs) || 5000, 30_000));
    this.minIntervalMs = Math.max(0, Number(minIntervalMs) || 3000);
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.sleep = sleep;
    this.nextSendAt = 0;
    this.reservation = Promise.resolve();
  }

  /** security 域发送入口：sendResult(研判结果)。 */
  async sendResult(result) {
    await this.reserveSendSlot();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.webhookUrl, {
        method: "POST",
        signal: controller.signal,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ msgtype: "text", text: { content: this.format(result) } })
      });
      const body = await response.text();
      if (!response.ok) {
        throw new WeComNotificationError(`Enterprise WeChat webhook failed with HTTP ${response.status}`, { status: response.status, retryable: response.status === 429 || response.status >= 500 });
      }
      let payload;
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        throw new WeComNotificationError("Enterprise WeChat webhook returned invalid JSON", { retryable: true });
      }
      if (Number(payload.errcode ?? 0) !== 0) {
        // 93000 为企业微信频控错误码，可退避后重试。
        throw new WeComNotificationError(`Enterprise WeChat webhook rejected message: ${payload.errcode}`, { retryable: Number(payload.errcode) === 93000 });
      }
      return { delivered: true };
    } catch (error) {
      if (error?.name === "AbortError") throw new WeComNotificationError("Enterprise WeChat webhook timed out", { retryable: true });
      if (error instanceof WeComNotificationError) throw error;
      throw new WeComNotificationError(`Enterprise WeChat webhook request failed: ${error.message}`, { retryable: true });
    } finally {
      clearTimeout(timer);
    }
  }

  /** malware 域发送入口：与 sendResult 同骨架，仅保留命名一致性。 */
  async sendTriageResult(result) {
    return this.sendResult(result);
  }

  /** 预约发送时隙：串行 + 最小间隔，保证低于群机器人频控。 */
  async reserveSendSlot() {
    const previous = this.reservation;
    let release;
    this.reservation = new Promise(resolve => { release = resolve; });
    await previous;
    try {
      const delay = Math.max(0, this.nextSendAt - this.now());
      if (delay) await this.sleep(delay);
      this.nextSendAt = this.now() + this.minIntervalMs;
    } finally {
      release();
    }
  }
}

/** security 域工厂：从环境变量装配（未配置 webhook 时返回 null，禁用通知）。 */
export function weComNotifierFromEnvironment(environment = process.env) {
  return environment.WECOM_WEBHOOK_URL ? new WeComWebhookNotifier({
    webhookUrl: environment.WECOM_WEBHOOK_URL,
    format: formatWeComResult,
    timeoutMs: environment.WECOM_TIMEOUT_MS
  }) : null;
}

/** malware 域工厂：使用恶意样本脱敏模板。 */
export function malwareWeComNotifierFromEnvironment(environment = process.env) {
  return environment.WECOM_WEBHOOK_URL ? new WeComWebhookNotifier({
    webhookUrl: environment.WECOM_WEBHOOK_URL,
    format: formatMalwareTriageResult,
    timeoutMs: environment.WECOM_TIMEOUT_MS
  }) : null;
}
