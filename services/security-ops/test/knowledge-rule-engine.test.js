import test from "node:test";
import assert from "node:assert/strict";

import { evaluateKnowledgeRule, validateKnowledgeRule } from "../src/knowledge-rule-engine.js";

function bruteForceRule() {
  return {
    version: "1.0",
    requiredFacts: ["data.auth_failures", "data.window_seconds", "data.distinct_accounts"],
    confirmWhen: {
      all: [
        { predicateId: "failure-burst", path: "data.auth_failures", op: "gte", value: 8 },
        { predicateId: "short-window", path: "data.window_seconds", op: "lte", value: 300 }
      ],
      any: [
        { predicateId: "account-spray", path: "data.distinct_accounts", op: "gte", value: 3 },
        { predicateId: "success-after-failures", path: "data.success_after_failures", op: "equals", value: true }
      ],
      minimumAny: 1
    },
    excludeWhen: {
      any: [
        { predicateId: "approved-change", path: "data.authorization_valid", op: "equals", value: true },
        { predicateId: "health-check", path: "data.client_tags", op: "contains_any", value: ["health-check", "synthetic-monitor"] }
      ]
    },
    thresholdBasis: {
      sourceIds: ["src-wazuh-reviewed-ticket-history"],
      statement: "复核记录中五分钟内至少八次失败且影响三个账号时进入人工升级。"
    }
  };
}

test("executable knowledge confirms a feature-complete event", () => {
  const result = evaluateKnowledgeRule(bruteForceRule(), {
    data: { auth_failures: 12, window_seconds: 180, distinct_accounts: 4, authorization_valid: false }
  });
  assert.equal(result.outcome, "confirmed");
  assert.deepEqual(result.missingFacts, []);
  assert.deepEqual(result.matchedPredicates.map((item) => item.predicateId), ["failure-burst", "short-window", "account-spray"]);
});

test("an operational exclusion wins over a matching attack pattern", () => {
  const result = evaluateKnowledgeRule(bruteForceRule(), {
    data: { auth_failures: 12, window_seconds: 180, distinct_accounts: 4, authorization_valid: true }
  });
  assert.equal(result.outcome, "excluded");
  assert.deepEqual(result.excludedBy.map((item) => item.predicateId), ["approved-change"]);
});

test("missing required facts produces an evidence request instead of a positive decision", () => {
  const result = evaluateKnowledgeRule(bruteForceRule(), {
    data: { auth_failures: 12, window_seconds: 180 }
  });
  assert.equal(result.outcome, "insufficient");
  assert.deepEqual(result.missingFacts, ["data.distinct_accounts"]);
});

test("complete facts below a threshold do not match", () => {
  const result = evaluateKnowledgeRule(bruteForceRule(), {
    data: { auth_failures: 7, window_seconds: 180, distinct_accounts: 4, authorization_valid: false }
  });
  assert.equal(result.outcome, "not_matched");
  assert.ok(result.failedPredicates.some((item) => item.predicateId === "failure-burst"));
});

test("unsafe fields and unsupported operators are rejected", () => {
  const unsafePath = bruteForceRule();
  unsafePath.confirmWhen.all[0].path = "__proto__.polluted";
  assert.throws(() => validateKnowledgeRule(unsafePath), /field path/);

  const unsafeOperator = bruteForceRule();
  unsafeOperator.confirmWhen.all[0].op = "matches_script";
  assert.throws(() => validateKnowledgeRule(unsafeOperator), /operator/);
});
