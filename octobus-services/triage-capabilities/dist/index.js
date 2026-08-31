#!/usr/bin/env node
/**
 * OctoBus service package 实现（规范 §7.1）：triage.capabilities.v1.CapabilityService。
 *
 * 职责与边界：
 * - 每个方法都是确定性纯函数（复用 agent/src/capabilities 注册表实现，零 IO、可 100% 单测）；
 * - 服务本体不调用模型、不访问样本原文、不落任何敏感数据（规范红线 2/3）；
 * - 以 Connect RPC JSON 约定对外暴露：
 *     POST /capsets/{capset_id}/connect/{instance_id}/{full_service}/{method}
 *   与 agent 侧 OctoBusConnectClient 的调用地址完全一致，可本地端到端联调；
 * - 访问治理：设置 TRIAGE_CAPABILITIES_TOKEN 后强制 Bearer 鉴权（生产经 OctoBus 网关 token 代理）；
 * - 留痕：每次调用追加一行 NDJSON access.log（含 trace_id / capability / 状态码），
 *   作为规范 §11 留痕层在能力总线侧的权威输入；
 * - 网络仅监听 127.0.0.1（默认），需要外部访问时由 OctoBus 网关代理，本服务不直接暴露。
 */
import { createServer } from "node:http";
import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { evaluateRules } from "../../../agent/src/capabilities/security/rule-engine.js";
import {
  correlateThreatEvidence,
  decisionFromThreatCorrelation
} from "../../../agent/src/capabilities/security/threat-evidence.js";
import {
  applySeverityGating,
  applyAssetCriticalityGate
} from "../../../agent/src/capabilities/security/escalation-gates.js";
import { normalizeSanitizedReport } from "../../../agent/src/capabilities/malware/report-contract.js";
import { assessRisk } from "../../../agent/src/capabilities/malware/risk-engine.js";
import { draftYaraCandidate } from "../../../agent/src/capabilities/malware/yara-drafter.js";
import { getCapability, listCapabilityIds } from "../../../agent/src/capabilities/index.js";

const SERVICE_NAME = "triage.capabilities.v1.CapabilityService";

/**
 * 预置脱敏回放数据集（dataSource: "replay"）：
 * 本服务是「唯一数据来源模拟」（README 5.6 模拟边界），
 * 真实后端沙箱接入后替换实例，Agent 代码零改动；
 * 预置数据只覆盖已在 README 案例中登记的 alertId，未登记告警按 found:false 处理。
 */
const REPLAY_ALERTS = {
  "A-1001": {
    found: true,
    alertId: "A-1001",
    title: "Outbound DNS query to rare domain",
    severity: "medium",
    assetCriticality: "medium",
    sourceAssetTag: "vulnerability_scanner",
    sourceAddress: "10.0.8.15",
    eventTime: "2026-08-25T10:00:00Z",
    approvedScanWindow: true,
    destinationPort: 53,
    rawSignalCount: 4,
    networkIndicatorCount: 1,
    matchedSnortSidCount: 0,
    replayNotice: "Replay data: authorized vulnerability scanner DNS activity within approved window; suppress with review."
  },
  "A-1002": {
    found: true,
    alertId: "A-1002",
    title: "Internal host connecting to known APT IP",
    severity: "high",
    assetCriticality: "critical",
    sourceAssetTag: "workstation",
    sourceAddress: "10.0.3.22",
    eventTime: "2026-08-25T11:30:00Z",
    approvedScanWindow: false,
    destinationPort: 443,
    rawSignalCount: 12,
    networkIndicatorCount: 3,
    networkIndicators: ["91.121.84.115", "aptcmd.example.org", "drop.example.net"],
    matchedSnortSidCount: 1,
    matchedSnortSids: ["9999999"],
    replayNotice: "Replay data: high-severity network egress on critical asset; requires escalation."
  }
};
/** 幂等写登记：RecordTriageResult 的幂等键 → 已写入记录。 */
const replayRecordStore = new Map();

/**
 * 方法路由表：gRPC method → 确定性能力实现。
 * 每个实现只做「解析 JSON 入参 → 调用纯函数 → 返回 JSON」，不掺入任何判定外逻辑。
 * 能力分为两组：
 *   A) 业务端点（沙箱 ↔ 后端沙箱实例）：GetAlertContext / RecordTriageResult
 *      （README 3.3.2 capset 4 个已启用方法中的 2 个数据通路端点）
 *   B) 纯函数确定性能力（规则引擎 / 关联引擎 / 门控 / 样本域能力）：
 *      沙箱 guest 内本地直接 import 调用（零 IO）；本服务同步暴露以支持
 *      其他消费者（如审计查询、可视化）经网关统一路由。
 */
const HANDLERS = {
  // ----- A) 业务数据端点（capset security-triage 必选）-----
  GetAlertContext: ({ alertId }) => {
    const hit = REPLAY_ALERTS[String(alertId ?? "")];
    if (hit) return { ...hit, dataSource: "replay" };
    return { found: false, alertId: String(alertId ?? ""), dataSource: "replay", replayNotice: "Replay data: alert id not registered in local replay set." };
  },
  RecordTriageResult: ({ alertId, decision, action, matchedRuleId = "", falsePositiveScore = 0, evidenceJson = "[]", narrative = "", traceId = "", idempotencyKey = "" }) => {
    const key = String(idempotencyKey || `record:${traceId}:${alertId}`);
    const existing = replayRecordStore.get(key);
    if (existing) return { accepted: true, recordId: existing.recordId, duplicate: true };
    const recordId = `TR-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    replayRecordStore.set(key, { recordId, alertId, decision, action, matchedRuleId, falsePositiveScore, evidenceJson, narrative, traceId, idempotencyKey: key, writtenAt: new Date().toISOString() });
    return { accepted: true, recordId, dataSource: "replay" };
  },
  // ----- B) 纯函数确定性能力（与 capabilities/index.js 一一对应）-----
  EvaluateFalsePositiveRules: ({ context, rules }) => evaluateRules(context, rules),
  MatchThreatIndicators: ({ context, evidenceRecords = [] }) => correlateThreatEvidence(context, evidenceRecords),
  DecisionFromThreatCorrelation: ({ correlation }) => decisionFromThreatCorrelation(correlation),
  ApplySeverityGating: ({ decision, context }) => applySeverityGating(decision, context),
  ApplyAssetCriticalityGate: ({ decision, context }) => applyAssetCriticalityGate(decision, context),
  ValidateSanitizedReport: ({ report }) => normalizeSanitizedReport(report),
  AssessRisk: ({ report }) => assessRisk(report),
  DraftYaraCandidate: ({ report, assessment }) => draftYaraCandidate(report, assessment)
};

/** 解析 Connect RPC 路由，返回 { service, method }；不匹配返回 null。 */
export function parseConnectRoute(pathname) {
  const segments = pathname.split("/").filter(Boolean);
  // 期望形态：capsets/{capset}/connect/{instance}/{service}/{method}
  if (segments.length !== 6 || segments[0] !== "capsets" || segments[2] !== "connect") {
    return null;
  }
  return { service: segments[4], method: segments[5] };
}

/**
 * 处理一次 Connect RPC JSON 调用（纯逻辑，便于单测）。
 * @param {{service: string, method: string, body: object, token?: string, expectedToken?: string}} request
 * @returns {{status: number, body: object}}
 */
export function handleConnectCall({ service, method, body, token, expectedToken }) {
  // 能力治理：token 鉴权（配置了 expectedToken 才启用）。
  if (expectedToken && token !== expectedToken) {
    return { status: 401, body: { code: "unauthenticated", message: "缺少或错误的 capset token" } };
  }
  // 能力治理：未注册的能力禁止调用（规范 §7.4）。
  if (service !== SERVICE_NAME) {
    return { status: 404, body: { code: "not_found", message: `未知服务：${service}` } };
  }
  const handler = HANDLERS[method];
  if (!handler) {
    return { status: 404, body: { code: "not_found", message: `未注册的能力：${method}（可用：${Object.keys(HANDLERS).join(", ")}）` } };
  }
  try {
    return { status: 200, body: handler(body ?? {}) };
  } catch (error) {
    // 能力失败按契约显式返回，禁止静默（规范红线 5）。
    return { status: 400, body: { code: "invalid_argument", message: error.message } };
  }
}

/**
 * 创建 Connect RPC JSON HTTP 服务（node:http，零第三方依赖）。
 * @param {object} options
 * @param {string} [options.host] 监听地址，默认 127.0.0.1
 * @param {number} [options.port] 监听端口，默认 9090
 * @param {string} [options.token] capset token（Bearer），留空为本地无鉴权演示模式
 * @param {string} [options.accessLogPath] access.log NDJSON 路径
 */
export function createTriageCapabilityServer({ host = "127.0.0.1", port = 9090, token, accessLogPath } = {}) {
  const accessLog = accessLogPath ? path.resolve(accessLogPath) : null;
  if (accessLog) mkdirSync(path.dirname(accessLog), { recursive: true });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
    const traceId = req.headers["x-octobus-ext-business-request-id"] ?? "";
    const finish = (status, body) => {
      // 留痕：每次能力调用一行 NDJSON（trace_id 贯穿，规范 §7.3 / §11）。
      if (accessLog) {
        appendFileSync(
          accessLog,
          `${JSON.stringify({ ts: new Date().toISOString(), trace_id: traceId, capability: url.pathname, status, method: req.method })}\n`
        );
      }
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.method !== "POST") return finish(405, { code: "method_not_allowed", message: "仅支持 POST" });
    const route = parseConnectRoute(url.pathname);
    if (!route) return finish(404, { code: "not_found", message: "非法的 Connect RPC 路由" });

    let body = {};
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const text = Buffer.concat(chunks).toString("utf8");
      body = text ? JSON.parse(text) : {};
    } catch {
      return finish(400, { code: "invalid_argument", message: "请求体不是合法 JSON" });
    }

    const authorization = req.headers.authorization ?? "";
    const bearer = authorization.startsWith("Bearer ") ? authorization.slice(7) : undefined;
    const { status, body: result } = handleConnectCall({
      service: route.service,
      method: route.method,
      body,
      token: bearer,
      expectedToken: token
    });
    finish(status, result);
  });

  return { server, host, port };
}

/** 直接执行（node dist/index.js）时启动独立服务，供本地与部署联调。 */
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { server, host, port } = createTriageCapabilityServer({
    host: process.env.TRIAGE_CAPABILITIES_HOST ?? "127.0.0.1",
    port: Number(process.env.TRIAGE_CAPABILITIES_PORT ?? 9090),
    token: process.env.TRIAGE_CAPABILITIES_TOKEN,
    accessLogPath: process.env.TRIAGE_CAPABILITIES_ACCESS_LOG ?? "runtime/access.log"
  });
  server.listen(port, host, () => {
    process.stderr.write(
      `${JSON.stringify({
        event: "triage_capabilities.started",
        host,
        port,
        service: SERVICE_NAME,
        capabilities: listCapabilityIds(),
        auth: process.env.TRIAGE_CAPABILITIES_TOKEN ? "token" : "none(local-demo)"
      })}\n`
    );
  });
}
