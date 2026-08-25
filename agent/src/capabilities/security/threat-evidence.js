/**
 * 领域层：私有威胁证据关联（纯函数，零 IO 依赖）。
 * 文件读取由 security/threat-evidence-engine.js 装配层完成。
 */

function asText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeIndicator(value) {
  return asText(value).toLowerCase().replace(/\.$/, "");
}

function snortSid(ruleText) {
  return asText(ruleText).match(/\bsid\s*:\s*(\d+)\s*;/i)?.[1] ?? null;
}

/**
 * Parse a private JSONL evidence package (pure). The caller deliberately
 * chooses how to obtain the text; no IOC data is bundled in, committed to,
 * or fetched by this repository.
 */
export function parseThreatEvidenceJsonl(text) {
  const rows = String(text ?? "").split(/\r?\n/).filter(Boolean);
  return rows.map((line, index) => {
    let item;
    try {
      item = JSON.parse(line);
    } catch {
      throw new Error(`威胁证据第 ${index + 1} 行不是有效 JSON`);
    }
    if (!asText(item.evidence_id) || !asText(item.source_type) || !asText(item.indicator_or_signature)) {
      throw new Error(`威胁证据第 ${index + 1} 行缺少 evidence_id、source_type 或 indicator_or_signature`);
    }
    return item;
  });
}

/**
 * Return identifiers only: the raw IOC and Snort text remain in the private
 * package and are intentionally excluded from state snapshots and LLM input.
 */
export function correlateThreatEvidence(context, evidenceRecords = []) {
  const observedIndicators = new Set(
    [...(context.networkIndicators ?? []), ...(context.observedIndicators ?? [])]
      .map(normalizeIndicator)
      .filter(Boolean)
  );
  const observedSids = new Set((context.matchedSnortSids ?? []).map((value) => asText(value)).filter(Boolean));
  const matches = [];

  for (const item of evidenceRecords) {
    const sourceType = asText(item.source_type);
    const indicator = normalizeIndicator(item.indicator_or_signature);
    const sid = sourceType === "SNORT" ? snortSid(item.indicator_or_signature) : null;
    const matched = sid ? observedSids.has(sid) : observedIndicators.has(indicator);
    if (matched) {
      matches.push({
        evidenceId: asText(item.evidence_id),
        sourceType,
        matchKind: sid ? "snort_sid" : "network_indicator"
      });
    }
  }

  return {
    matched: matches,
    matchedCount: matches.length,
    action: matches.length ? "open_case" : null
  };
}

/** A threat-evidence hit is escalation evidence, never an auto-block command. */
export function decisionFromThreatCorrelation(correlation) {
  return {
    status: "escalate",
    action: "open_case",
    matchedRuleId: null,
    falsePositiveScore: 0,
    evidence: correlation.matched,
    reason: `命中 ${correlation.matchedCount} 条私有威胁证据，需关联资产、时间与进程上下文后人工研判。`
  };
}
