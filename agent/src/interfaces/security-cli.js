#!/usr/bin/env node
/**
 * 接口层：安全告警研判工作流组合根（规范 §5.2 interfaces/）。
 *
 * 职责：解析 CLI 入参 → 装配 Port 实现（组合根）→ 运行流水线 → 追加审计日志。
 * 判定逻辑不在此文件：本文件只做「触发层入参标准化 + 依赖注入 + 输出」。
 * 工作流选择只由统一入口（interfaces/cli.js）的显式 flag 决定。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { OctoBusConnectClient } from "../infrastructure/octobus/connect-client.js";
import { narratorFromEnvironment } from "../infrastructure/model-gateway/security-narrator.js";
import { stateStoreFromEnvironment } from "../infrastructure/db/security-state-store.js";
import { loadThreatEvidenceJsonl } from "../infrastructure/knowledge/threat-evidence-loader.js";
import { SecurityTriageAgent, IOC_ESCALATION_KNOWLEDGE } from "../application/pipelines/security-triage-pipeline.js";
import {
  SEVERITY_GATING_KNOWLEDGE,
  ASSET_CRITICALITY_KNOWLEDGE
} from "../capabilities/security/escalation-gates.js";
import { weComNotifierFromEnvironment } from "../infrastructure/notify/wecom-notifier.js";
import { auditLogFromEnvironment } from "../audit/audit-log.js";
import { requiredConfig, knowledgeAblationFromEnvironment } from "../config/env.js";
import { evidenceRefsFromJudgment } from "../domains/audit/evidence-chain.js";
import { logger } from "../shared/logger.js";

/** 读取 --name value 形式的命令行参数。 */
function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const recoverOutbox = process.argv.includes("--recover-outbox");
const alertId = recoverOutbox ? undefined : requiredConfig(argumentValue("--alert-id"), "--alert-id");

// 规范 §8 知识库：降噪规则是提交入库的结构化知识资产（含失效条件与证据口径）。
const currentDir = path.dirname(fileURLToPath(import.meta.url));
const defaultRules = path.resolve(currentDir, "../../../knowledge/corpus/security/false-positive-rules.json");
const rulesPath = argumentValue("--rules") ?? defaultRules;
const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));

// 知识消融（规范 §9.4）：加载规则后过滤掉 knowledge_id 在消融集合中的规则
// （规则无 knowledge_id 不过滤）；被过滤者并入结果显式标记。
const knowledgeAblation = knowledgeAblationFromEnvironment();
const activeRules = knowledgeAblation.size
  ? { ...rules, rules: (rules.rules ?? []).filter((rule) => !(rule.knowledge_id && knowledgeAblation.has(rule.knowledge_id))) }
  : rules;
const ablatedRuleKnowledgeIds = knowledgeAblation.size
  ? [...new Set((rules.rules ?? []).filter((rule) => rule.knowledge_id && knowledgeAblation.has(rule.knowledge_id)).map((rule) => rule.knowledge_id))]
  : [];

// 私有威胁证据包：调用方显式指定本地路径，仓库不内置任何 IOC。
const threatEvidencePath = argumentValue("--threat-evidence") ?? process.env.SECURITY_TRIAGE_THREAT_EVIDENCE_PATH;
const threatEvidence = threatEvidencePath ? loadThreatEvidenceJsonl(threatEvidencePath) : [];

// 能力总线：所有确定性能力调用必须经 OctoBus（规范红线 3）。
const octobus = new OctoBusConnectClient({
  baseUrl: requiredConfig(process.env.OCTOBUS_BASE_URL, "OCTOBUS_BASE_URL"),
  capsetId: requiredConfig(process.env.OCTOBUS_CAPSET_ID, "OCTOBUS_CAPSET_ID"),
  instanceId: requiredConfig(process.env.OCTOBUS_INSTANCE_ID, "OCTOBUS_INSTANCE_ID"),
  fullService: process.env.OCTOBUS_FULL_SERVICE ?? "security.triage.v1.SecurityTriageService",
  token: process.env.OCTOBUS_TOKEN
});

const stateStore = stateStoreFromEnvironment();
try {
  const agent = new SecurityTriageAgent({
    octobus,
    rules: activeRules,
    threatEvidence,
    narrator: narratorFromEnvironment(),
    stateStore,
    notifier: weComNotifierFromEnvironment(),
    knowledgeAblation
  });
  const audit = auditLogFromEnvironment();
  if (recoverOutbox) {
    // 恢复模式：重投 outbox 中到期 / 租约过期的投递项。
    const deliveries = await agent.recoverOutbox({ limit: Number(argumentValue("--limit")) || 20 });
    process.stdout.write(`${JSON.stringify({ recovered: deliveries.filter(item => item.delivered).length, pending: deliveries.filter(item => !item.delivered).length, deliveries }, null, 2)}\n`);
    process.exitCode = deliveries.some(item => !item.delivered) ? 2 : 0;
  } else {
    const result = await agent.triage({ alertId });
    // CLI 侧被过滤的规则知识资产并入消融显式标记（流水线只见过滤后的规则集）。
    if (ablatedRuleKnowledgeIds.length > 0) {
      result.knowledgeAblated = [...new Set([...(result.knowledgeAblated ?? []), ...ablatedRuleKnowledgeIds])];
    }
    // 留痕层：终态审计记录（结论 + 证据引用 + 原始入参 + 模型来源 + prompt 版本 + 终态指标）。
    try {
      audit.append({
        event: "workflow.completed",
        workflow: "security",
        traceId: result.traceId,
        input: { alertId },
        status: result.status,
        action: result.action,
        evidenceRefs: evidenceRefsFromJudgment(result),
        model: result.narrativeSource,
        promptVersion: "security-triage-v1",
        recorded: result.recorded,
        metrics: result.metrics
      });
    } catch (auditError) {
      // 审计写入失败必须可见，禁止静默（规范红线 5）。
      logger.error("audit.write_failed", { traceId: result.traceId, error: auditError.message });
      result.auditError = auditError.message;
    }
    // 知识-代码绑定反向留痕（规范 §9.5）：命中知识独立审计一行，
    // 携带对应资产 consumed_by 的合并视图；仅当命中非空时写入。
    if (Array.isArray(result.knowledgeHits) && result.knowledgeHits.length > 0) {
      const consumedByViews = new Map([
        [IOC_ESCALATION_KNOWLEDGE.knowledge_id, IOC_ESCALATION_KNOWLEDGE.consumed_by],
        [SEVERITY_GATING_KNOWLEDGE.knowledge_id, SEVERITY_GATING_KNOWLEDGE.consumed_by],
        [ASSET_CRITICALITY_KNOWLEDGE.knowledge_id, ASSET_CRITICALITY_KNOWLEDGE.consumed_by]
      ]);
      try {
        audit.append({
          event: "KNOWLEDGE_HIT",
          workflow: "security",
          traceId: result.traceId,
          knowledge_ids: result.knowledgeHits,
          consumed_by: result.knowledgeHits.map((knowledgeId) => ({
            knowledge_id: knowledgeId,
            consumed_by: consumedByViews.get(knowledgeId)
              ?? (rules.rules ?? []).find((rule) => rule.knowledge_id === knowledgeId)?.consumed_by
              ?? []
          }))
        });
      } catch (auditError) {
        logger.error("audit.write_failed", { traceId: result.traceId, error: auditError.message });
        result.auditError = auditError.message;
      }
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.status === "manual_review" ? 2 : 0;
  }
} finally {
  stateStore.close();
}
