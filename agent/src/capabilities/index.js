/**
 * 能力层：确定性能力注册表（规范 §5.2 capabilities/、§7.4 能力命名与注册）。
 *
 * capability_id 命名规范：{domain}.{operation}。
 * 每个能力必须声明：
 * - fn        纯函数实现（零 IO，可 100% 单测）
 * - idempotent 幂等性声明（相同输入必得相同输出）
 * - deterministic 是否确定性计算（规范红线：此类计算禁止交给模型）
 * - timeoutMs 建议超时
 * 未注册到此表的能力禁止被编排层直接调用；对外暴露统一经
 * octobus-services/triage-capabilities（OctoBus service package）。
 */
import { evaluateRules } from "./security/rule-engine.js";
import { correlateThreatEvidence, decisionFromThreatCorrelation } from "./security/threat-evidence.js";
import { applySeverityGating, applyAssetCriticalityGate } from "./security/escalation-gates.js";
import { normalizeSanitizedReport } from "./malware/report-contract.js";
import { assessRisk } from "./malware/risk-engine.js";
import { draftYaraCandidate } from "./malware/yara-drafter.js";

/** 能力注册表：capability_id → 实现 + 元数据。 */
export const CAPABILITIES = Object.freeze({
  "security.rules.evaluate_false_positive": {
    description: "对告警上下文应用版本化降噪规则，输出确定性判定",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: evaluateRules
  },
  "security.threat.match_indicators": {
    description: "将告警网络指标 / Snort SID 与私有威胁证据包做确定性匹配",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: correlateThreatEvidence
  },
  "security.threat.decision_from_correlation": {
    description: "将威胁证据命中结果转换为升级结论（仅标识符，不含原始 IOC）",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: decisionFromThreatCorrelation
  },
  "security.gates.apply_severity": {
    description: "严重度降噪门控：高/严重级告警的降噪复核结论降级人工确认（kb-security-severity-gating）",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: applySeverityGating
  },
  "security.gates.apply_asset_criticality": {
    description: "关键资产降噪提级：critical/high 资产上的降噪复核结论降级人工确认（kb-security-asset-criticality-escalation）",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: applyAssetCriticalityGate
  },
  "malware.report.validate_sanitized": {
    description: "校验脱敏报告契约：拒绝样本字节 / 路径等禁止字段，失败即关闭",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: normalizeSanitizedReport
  },
  "malware.risk.assess": {
    description: "确定性风险评分：权限 / 行为 / 网络指标 → 定级与证据",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: assessRisk
  },
  "malware.yara.draft_candidate": {
    description: "从稳定字符串指标起草 YARA 候选（仅候选，须验证 + 人工审核）",
    idempotent: true,
    deterministic: true,
    timeoutMs: 1000,
    fn: draftYaraCandidate
  }
});

/** 按能力 ID 查找注册项；未注册的能力禁止调用。 */
export function getCapability(capabilityId) {
  const capability = CAPABILITIES[capabilityId];
  if (!capability) {
    throw new Error(`未注册的能力：${capabilityId}（能力必须先注册到 capabilities/index.js）`);
  }
  return capability;
}

/** 列出全部能力 ID（供自检与能力目录核对）。 */
export function listCapabilityIds() {
  return Object.keys(CAPABILITIES);
}
