/**
 * 基础设施层：OctoBus 能力总线 Connect RPC 客户端（规范 §7.3 调用通道）。
 *
 * 合并原 security / malware 两份重复实现，统一约定：
 * - 只允许访问 OctoBus 公共网关的 Connect 路由，后端沙箱 / 校验器地址对
 *   Agent 不可见（baseUrl 只能是网关根地址，禁止携带路径与凭证）；
 * - 每次调用必须携带 traceId，写入 x-octobus-ext-business-request-id 请求头，
 *   形成 Agent、网关、能力服务三方一致的审计键；
 * - 超时使用 AbortController 有界控制（250ms ~ 30s），网关挂起不会让任务无限等待；
 * - 失败统一抛 OctoBusError（携带 code / status / retryable），供弹性执行器
 *   与 outbox 决定重试或升级人工，禁止静默失败。
 */
import { ERROR_CODES } from "../../shared/errors.js";
import { structuredLog } from "../../shared/logger.js";

/** OctoBus 能力调用失败：message 面向运维，code/status/retryable 面向程序分支。 */
export class OctoBusError extends Error {
  constructor(message, { status, body, retryable = false } = {}) {
    super(message);
    this.name = "OctoBusError";
    this.code = ERROR_CODES.OCTOBUS_CALL_FAILED;
    this.status = status;
    this.body = body;
    this.retryable = retryable;
  }
}

/**
 * OctoBus Connect RPC 适配器（unary 调用）。
 * Agent 永远不直接调用业务后端，所有确定性能力都经此网关路由。
 */
export class OctoBusConnectClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl OctoBus 网关根地址（如 http://127.0.0.1:8080）
   * @param {string} options.capsetId 最小权限能力集标识
   * @param {string} options.instanceId 能力实例标识
   * @param {string} [options.fullService] 完整 gRPC 服务名（security 域在构造时固定；
   *        malware 域按调用传入 service）
   * @param {string} [options.token] capset 作用域 token（Bearer）
   * @param {Function} [options.fetchImpl] 可注入的 fetch 实现（测试用）
   */
  constructor({ baseUrl, capsetId, instanceId, fullService, token, fetchImpl = fetch }) {
    if (!baseUrl || !capsetId || !instanceId) {
      throw new Error("OctoBus 配置不完整：需要 baseUrl、capsetId、instanceId");
    }
    this.baseUrl = normalizeGatewayBaseUrl(baseUrl);
    assertPathSegment(capsetId, "capsetId");
    assertPathSegment(instanceId, "instanceId");
    if (fullService) assertRpcName(fullService, "fullService");
    this.capsetId = capsetId;
    this.instanceId = instanceId;
    this.fullService = fullService;
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  /** 构造唯一允许的下游路径：capsets/{capset}/connect/{instance}/{service}/{method}。 */
  endpoint(service, method) {
    const resolvedService = service ?? this.fullService;
    if (!resolvedService) throw new Error("OctoBus 调用缺少 service（构造时未固定 fullService 且调用未传入）");
    assertRpcName(resolvedService, "service");
    assertRpcName(method, "method");
    // 完整服务名保留在 URL 中，便于将 Agent 动作与 OctoBus 暴露的能力目录精确关联。
    return `${this.baseUrl}/capsets/${encodeURIComponent(this.capsetId)}/connect/${encodeURIComponent(this.instanceId)}/${resolvedService}/${method}`;
  }

  /**
   * 发起一次 unary Connect RPC 调用。
   * @param {object} input
   * @param {string} [input.service] 完整 gRPC 服务名（缺省用构造时的 fullService）
   * @param {string} input.method RPC 方法名
   * @param {object} input.body 请求体（JSON 序列化）
   * @param {string} input.traceId 追踪标识（必填，贯穿全链路留痕）
   * @param {number} [input.timeoutMs] 超时毫秒（默认 8000，钳制到 250~30000）
   * @param {string} [input.idempotencyKey] 幂等键（写入 x-idempotency-key 请求头）
   */
  async call({ service, method, body, traceId, timeoutMs = 8000, idempotencyKey } = {}) {
    if (!method) throw new Error("OctoBus 调用缺少 method");
    if (!traceId || typeof traceId !== "string") throw new Error("OctoBus 调用必须携带 traceId");

    const url = this.endpoint(service, method);
    // traceId 经网关转发给能力服务，是 Agent / 网关 / 服务端记录的共同审计键。
    const headers = {
      "content-type": "application/json",
      "x-octobus-ext-business-request-id": traceId
    };
    if (this.token) {
      headers.authorization = `Bearer ${this.token}`;
    }
    if (idempotencyKey) headers["x-idempotency-key"] = idempotencyKey;

    const controller = new AbortController();
    const boundedTimeoutMs = Math.max(250, Math.min(Number(timeoutMs) || 8000, 30_000));
    const timer = setTimeout(() => controller.abort(), boundedTimeoutMs);
    let response;
    let text;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers,
        signal: controller.signal,
        body: JSON.stringify(body ?? {})
      });
      text = await response.text();
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new OctoBusError(`OctoBus ${method} 超时`, { status: 408, body: "timeout" });
      }
      const transportError = new OctoBusError(`OctoBus ${method} 传输失败：${error.message}`, {
        body: "transport_error",
        retryable: true
      });
      structuredLog("debug", "octobus.transport_failed", { method, capsetId: this.capsetId });
      throw transportError;
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      structuredLog("debug", "octobus.http_failed", { method, status: response.status, capsetId: this.capsetId });
      throw new OctoBusError(`OctoBus ${method} 失败：HTTP ${response.status}`, {
        status: response.status,
        body: text
      });
    }

    try {
      return text ? JSON.parse(text) : {};
    } catch {
      throw new OctoBusError(`OctoBus ${method} 返回了无效 JSON`, {
        status: response.status,
        body: text
      });
    }
  }

  // ---- security 域便捷方法（幂等读上下文 / 幂等写结论）----

  /** 获取告警上下文（幂等读，按 traceId 生成幂等键）。 */
  getAlertContext(alertId, traceId) {
    return this.call({
      method: "GetAlertContext",
      // proto JSON 会合并 snake_case / camelCase 别名，同时出现会被解析器视为 duplicate field。
      // 这里统一只发送 snake_case，服务端 protobuf-json 同样接受，避免 400。
      body: { alert_id: alertId },
      traceId,
      idempotencyKey: `context:${traceId}`
    });
  }

  /** 上报研判结论（幂等写）。 */
  recordTriageResult(result, traceId, idempotencyKey = `record:${traceId}`) {
    return this.call({
      method: "RecordTriageResult",
      // body 只放 proto 定义字段；trace_id / idempotency_key 是网关/HTTP 级别
      // 元数据，由 call() 通过 x-octobus-ext-business-request-id / x-idempotency-key
      // 两个请求头传递，放入 body 会被 proto JSON 当作 unknown field 拒收。
      body: {
        alert_id: result.alertId,
        decision: result.status,
        action: result.action,
        matched_rule_id: result.matchedRuleId ?? "",
        false_positive_score: result.falsePositiveScore ?? 0,
        evidence_json: JSON.stringify(result.evidence),
        narrative: result.narrative
      },
      traceId,
      idempotencyKey
    });
  }
}

/** 网关根地址严格校验：只允许不含凭证、不含路径/查询/锚点的 http(s) origin。 */
function normalizeGatewayBaseUrl(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error("OCTOBUS_BASE_URL 必须是 http(s) 网关根地址");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error("OCTOBUS_BASE_URL 必须是不含凭证的 http(s) 网关根地址");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("OCTOBUS_BASE_URL 只能是 OctoBus 网关根地址，不能包含后端路径");
  }
  return parsed.origin;
}

/** 路径段安全校验：防止注入额外的路由片段（如绕过 capset 直连后端）。 */
function assertPathSegment(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    throw new Error(`${name} 不是安全的 OctoBus 路径标识`);
  }
}

/** RPC 名称安全校验：防止 ../ 等路径穿越进入网关路由。 */
function assertRpcName(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(value)) {
    throw new Error(`${name} 不是安全的 Connect RPC 名称`);
  }
}
