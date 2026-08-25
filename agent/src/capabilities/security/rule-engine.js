const fieldLabels = {
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
  for (const rule of rules.rules ?? []) {
    const evidence = evidenceFor(context, rule);
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

  return {
    status: "escalate",
    action: "open_case",
    matchedRuleId: null,
    falsePositiveScore: 0.05,
    evidence: [],
    reason: "未命中降噪规则，需按高优先级进入人工研判。"
  };
}
