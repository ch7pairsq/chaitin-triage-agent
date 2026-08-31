const fieldLabels = {
  alertId: "告警编号",
  title: "告警标题",
  severity: "告警严重度",
  assetCriticality: "资产关键度",
  sourceAssetTag: "源资产标签",
  eventTime: "告警时间",
  approvedScanWindow: "授权扫描窗口",
  destinationPort: "目标端口"
};

function hasValue(value) {
  return value !== undefined && value !== null && value !== "";
}

function matchesConditions(context, conditions) {
  return Object.entries(conditions).every(([field, expected]) => context[field] === expected);
}

function evidenceFor(context, rule) {
  return rule.evidenceRequired.map((field) => ({
    field,
    label: fieldLabels[field] ?? field,
    value: context[field],
    present: hasValue(context[field])
  }));
}

/**
 * Apply deterministic, versioned domain rules before using an LLM.
 * A missing required fact is intentionally never treated as a rule match.
 */
export function evaluateRules(context, rules) {
  const observedEvidence = [];
  for (const rule of rules.rules ?? []) {
    const evidence = evidenceFor(context, rule);
    for (const item of evidence) {
      if (item.present && !observedEvidence.some((known) => known.field === item.field)) {
        observedEvidence.push(item);
      }
    }
    const missing = evidence.filter((item) => !item.present);

    // Skip only rules that are already contradicted. Missing evidence on an
    // otherwise plausible rule must lead to manual review, not auto-approval.
    const hasKnownContradiction = Object.entries(rule.conditions).some(
      ([field, expected]) => hasValue(context[field]) && context[field] !== expected
    );

    if (hasKnownContradiction) {
      continue;
    }

    if (missing.length > 0) {
      return {
        status: "manual_review",
        action: "request_missing_evidence",
        matchedRuleId: rule.ruleId,
        falsePositiveScore: null,
        evidence,
        reason: `缺少研判所需证据：${missing.map((item) => item.label).join("、")}`
      };
    }

    if (matchesConditions(context, rule.conditions)) {
      return {
        status: "needs_review",
        action: rule.decision.action,
        matchedRuleId: rule.ruleId,
        falsePositiveScore: rule.decision.falsePositiveScore,
        evidence,
        reason: rule.description
      };
    }
  }

  if (observedEvidence.length === 0) {
    for (const field of ["alertId", "title", "severity", "assetCriticality"]) {
      if (hasValue(context[field])) {
        observedEvidence.push({
          field,
          label: fieldLabels[field],
          value: context[field],
          present: true
        });
      }
    }
  }

  return {
    status: "manual_review",
    action: "request_additional_evidence",
    matchedRuleId: null,
    falsePositiveScore: null,
    evidence: observedEvidence,
    reason: "现有证据未命中可执行判据，禁止无依据升级或降噪，转人工补充证据。"
  };
}
