import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { OctoBusConnectClient } from "../../src/infrastructure/octobus/connect-client.js";
import { OpenAICompatibleNarrator } from "../../src/infrastructure/model-gateway/security-narrator.js";
import { ResilientExecutor } from "../../src/shared/resilience.js";
import { evaluateRules } from "../../src/capabilities/security/rule-engine.js";
import { SecurityTriageAgent } from "../../src/application/pipelines/security-triage-pipeline.js";
import { SqliteStateStore } from "../../src/infrastructure/db/security-state-store.js";
import { correlateThreatEvidence } from "../../src/capabilities/security/threat-evidence.js";
import { WeComWebhookNotifier, formatWeComResult, validateWeComWebhookUrl } from "../../src/infrastructure/notify/wecom-notifier.js";
import { assertJudgmentGrounded, finalizeJudgment } from "../../src/domains/judgment/judgment.js";

const rules = {
  rules: [
    {
      ruleId: "fp_dns_001",
      description: "Authorized scanner DNS activity.",
      evidenceRequired: ["sourceAssetTag", "eventTime", "approvedScanWindow", "destinationPort"],
      conditions: {
        sourceAssetTag: "vulnerability_scanner",
        approvedScanWindow: true,
        destinationPort: 53
      },
      decision: { falsePositiveScore: 0.85, action: "suppress_with_review" }
    }
  ]
};

const matchingContext = {
  found: true,
  alertId: "A-1001",
  title: "DNS activity",
  sourceAssetTag: "vulnerability_scanner",
  eventTime: "2026-08-20T02:05:00Z",
  approvedScanWindow: true,
  destinationPort: 53
};

test("rule engine requests manual review when evidence is missing", () => {
  const result = evaluateRules({ ...matchingContext, approvedScanWindow: undefined }, rules);
  assert.equal(result.status, "manual_review");
  assert.equal(result.action, "request_missing_evidence");
});

test("rule engine uses deterministic conditions before producing a suppression recommendation", () => {
  const result = evaluateRules(matchingContext, rules);
  assert.equal(result.status, "needs_review");
  assert.equal(result.action, "suppress_with_review");
  assert.equal(result.matchedRuleId, "fp_dns_001");
});

test("rule engine sends an unmatched alert to manual review with observed evidence", () => {
  const result = evaluateRules(
    { ...matchingContext, sourceAssetTag: "workstation", approvedScanWindow: undefined },
    rules
  );
  assert.equal(result.status, "manual_review");
  assert.equal(result.action, "request_additional_evidence");
  assert.ok(result.evidence.length > 0);
});

test("grounding rejects conclusions with an empty evidence reference list", () => {
  const unsupported = finalizeJudgment({
    status: "escalate",
    action: "open_case",
    evidence: []
  });
  assert.throws(() => assertJudgmentGrounded(unsupported), /非空 evidenceRefs/);
});

test("agent obtains context and persists its result through the OctoBus adapter", async () => {
  const calls = [];
  const octobus = {
    async getAlertContext(alertId, traceId) {
      calls.push({ method: "GetAlertContext", alertId, traceId });
      return matchingContext;
    },
    async recordTriageResult(result, traceId) {
      calls.push({ method: "RecordTriageResult", result, traceId });
      return { accepted: true, recordId: "TR-1" };
    }
  };
  const agent = new SecurityTriageAgent({
    octobus,
    rules,
    createTraceId: () => "trace-test-001"
  });

  const result = await agent.triage({ alertId: "A-1001" });
  assert.equal(result.recorded, true);
  assert.equal(result.recordId, "TR-1");
  assert.deepEqual(result.states, [
    "RECEIVED",
    "ACQUIRE_CONTEXT",
    "EXTRACT_SIGNALS",
    "CORRELATE_THREAT_EVIDENCE",
    "APPLY_RULES",
    "LLM_SUMMARIZE",
    "DECIDE_ACTION",
    "PERSIST_RESULT",
    "COMPLETED"
  ]);
  assert.equal(calls[0].traceId, "trace-test-001");
  assert.equal(calls[1].traceId, "trace-test-001");
});

test("SQLite snapshots preserve the complete workflow history across store reopen", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "triage-state-"));
  const databasePath = path.join(directory, "state.db");
  const stateStore = new SqliteStateStore({ databasePath });
  const octobus = {
    async getAlertContext() {
      return matchingContext;
    },
    async recordTriageResult() {
      return { accepted: true, recordId: "TR-snapshot" };
    }
  };
  const agent = new SecurityTriageAgent({
    octobus,
    rules,
    stateStore,
    createTraceId: () => "trace-snapshot-001"
  });

  try {
    const result = await agent.triage({ alertId: "A-1001" });
    assert.equal(result.recorded, true);
    assert.deepEqual(
      stateStore.list("trace-snapshot-001").map((snapshot) => snapshot.state),
      [
        "RECEIVED",
        "ACQUIRE_CONTEXT",
        "EXTRACT_SIGNALS",
        "CORRELATE_THREAT_EVIDENCE",
        "APPLY_RULES",
        "LLM_SUMMARIZE",
        "DECIDE_ACTION",
        "PERSIST_RESULT",
        "COMPLETED"
      ]
    );
    stateStore.close();

    const reopenedStore = new SqliteStateStore({ databasePath });
    const latest = reopenedStore.getLatest("trace-snapshot-001");
    assert.equal(latest.state, "COMPLETED");
    assert.equal(latest.payload.result.recorded, true);
    reopenedStore.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("private IOC evidence escalates a case but never exposes an IOC in the decision", async () => {
  const privateEvidence = [{
    evidence_id: "IOC-IP-0001",
    source_type: "APT_IP",
    indicator_or_signature: "203.0.113.77"
  }];
  const correlation = correlateThreatEvidence({ networkIndicators: ["203.0.113.77"] }, privateEvidence);
  assert.deepEqual(correlation.matched, [{ evidenceId: "IOC-IP-0001", sourceType: "APT_IP", matchKind: "network_indicator" }]);

  const octobus = {
    async getAlertContext() { return { ...matchingContext, networkIndicators: ["203.0.113.77"] }; },
    async recordTriageResult() { return { accepted: true, recordId: "TR-evidence" }; }
  };
  const result = await new SecurityTriageAgent({
    octobus, rules, threatEvidence: privateEvidence, createTraceId: () => "trace-private-evidence"
  }).triage({ alertId: "A-private" });
  assert.equal(result.status, "escalate");
  assert.equal(result.action, "open_case");
  assert.equal(result.threatEvidenceMatched, 1);
  assert.doesNotMatch(JSON.stringify(result.evidence), /203\.0\.113\.77/);
});

test("knowledge ablation changes a decision without exporting the private indicator", async () => {
  const privateEvidence = [{ evidence_id: "IOC-IP-ABLAT-001", source_type: "APT_IP", indicator_or_signature: "198.51.100.77" }];
  const octobus = {
    async getAlertContext() { return { ...matchingContext, networkIndicators: ["198.51.100.77"] }; },
    async recordTriageResult() { return { accepted: true, recordId: "TR-ablation" }; }
  };
  const withKnowledge = await new SecurityTriageAgent({ octobus, rules, threatEvidence: privateEvidence, createTraceId: () => "trace-with-knowledge" }).triage({ alertId: "A-ablation" });
  const withoutKnowledge = await new SecurityTriageAgent({ octobus, rules, threatEvidence: [], createTraceId: () => "trace-without-knowledge" }).triage({ alertId: "A-ablation" });
  assert.deepEqual([withKnowledge.status, withKnowledge.action], ["escalate", "open_case"]);
  assert.deepEqual([withoutKnowledge.status, withoutKnowledge.action], ["needs_review", "suppress_with_review"]);
  assert.doesNotMatch(JSON.stringify(withKnowledge), /198\.51\.100\.77/);
});

test("the committed false-positive rule carries safe provenance and explicit review boundaries", () => {
  const ruleFile = path.resolve(import.meta.dirname, "../../../knowledge/corpus/security/false-positive-rules.json");
  const [rule] = JSON.parse(readFileSync(ruleFile, "utf8")).rules;
  assert.equal(rule.provenance.evidenceVersion, "fp-rules-v1");
  assert.ok(rule.provenance.knownFailureModes.length >= 2);
  assert.ok(rule.provenance.manualReviewWhen.length >= 2);
  assert.doesNotMatch(JSON.stringify(rule.provenance), /IOC|token|secret/i);
});

test("the committed false-positive rule satisfies the knowledge substance schema", () => {
  const ruleFile = path.resolve(import.meta.dirname, "../../../knowledge/corpus/security/false-positive-rules.json");
  const committedRules = JSON.parse(readFileSync(ruleFile, "utf8")).rules;
  for (const rule of committedRules) {
    // 判据具体可执行：条件为显式取值，而非"疑似/可能"式描述。
    for (const value of Object.values(rule.conditions)) {
      assert.notEqual(typeof value, "undefined");
    }
    assert.doesNotMatch(rule.description, /疑似|可能/);
    // 失效与误判经验四要素齐备。
    for (const key of ["false_positive_conditions", "false_negative_conditions", "bypass_points", "unusable_fields"]) {
      assert.ok(Array.isArray(rule.invalidation[key]) && rule.invalidation[key].length >= 1, `invalidation.${key} 缺失`);
    }
    // 证据块：优先级存在；样本量缺失时必须显式声明为 null 而非伪造数字。
    assert.equal(typeof rule.evidence.priority, "number");
    if (rule.evidence.evidence_count === null) {
      assert.ok(rule.evidence.evidence_note, "evidence_count 为 null 时必须说明证据缺口");
    }
    // 知识实质性口径：来源 + 积累过程 + 适用边界。
    for (const key of ["source", "accumulation", "boundary"]) {
      assert.ok(rule.knowledgeStatement[key], `knowledgeStatement.${key} 缺失`);
    }
    // 知识资产 schema 对齐（规范 §8.2/§9.5）：knowledge_id + judgment + tradeoff + consumed_by。
    assert.ok(rule.knowledge_id, "knowledge_id 缺失");
    assert.ok(rule.judgment.threshold && Object.keys(rule.judgment.threshold).length >= 1, "judgment.threshold 缺失");
    assert.ok(rule.judgment.feature_string, "judgment.feature_string 缺失");
    assert.ok(rule.judgment.predicate, "judgment.predicate 缺失");
    assert.ok(rule.tradeoff.leveling, "tradeoff.leveling 缺失");
    assert.ok(Array.isArray(rule.tradeoff.manual_confirm) && rule.tradeoff.manual_confirm.length >= 1, "tradeoff.manual_confirm 缺失");
    assert.ok(rule.tradeoff.insufficient_evidence, "tradeoff.insufficient_evidence 缺失");
    assert.ok(Array.isArray(rule.consumed_by) && rule.consumed_by.length >= 1, "consumed_by 缺失");
    assert.ok(
      rule.consumed_by.some((consumer) => consumer.type === "capability" && consumer.ref),
      "consumed_by 至少一个 type=capability 的消费方"
    );
    for (const consumer of rule.consumed_by) {
      assert.ok(["capability", "prompt"].includes(consumer.type), `consumed_by 存在非法 type: ${consumer.type}`);
      assert.ok(consumer.ref, "consumed_by 消费方缺少 ref");
    }
  }
});

test("the committed threat-evidence judgment satisfies the knowledge asset schema", () => {
  const judgmentFile = path.resolve(import.meta.dirname, "../../../knowledge/corpus/security/threat-evidence-judgment.json");
  const asset = JSON.parse(readFileSync(judgmentFile, "utf8"));
  assert.equal(asset.knowledge_id, "kb-security-ioc-escalation");
  assert.equal(asset.subject, "私有威胁证据命中升级判据");
  // 判据：阈值 + 特征串 + 可执行谓词（命中即升级，优先级高于误报降噪）。
  assert.equal(asset.judgment.threshold.matchedCount, 1);
  assert.ok(asset.judgment.feature_string, "judgment.feature_string 缺失");
  assert.match(asset.judgment.predicate, /matchedCount\s*>=\s*1/);
  assert.match(asset.judgment.predicate, /ESCALATE|open_case/);
  // 失效与误判经验四要素齐备。
  for (const key of ["false_positive_conditions", "false_negative_conditions", "bypass_points", "unusable_fields"]) {
    assert.ok(Array.isArray(asset.invalidation[key]) && asset.invalidation[key].length >= 1, `invalidation.${key} 缺失`);
  }
  // 证据块：优先级存在；条目数不导出，必须显式为 null 且说明证据缺口。
  assert.equal(typeof asset.evidence.priority, "number");
  assert.equal(asset.evidence.evidence_count, null);
  assert.ok(asset.evidence.evidence_note);
  // 取舍：升级人工案件但不自动封禁；无命中回退降噪规则。
  assert.ok(asset.tradeoff.leveling);
  assert.ok(Array.isArray(asset.tradeoff.manual_confirm) && asset.tradeoff.manual_confirm.length >= 1);
  assert.ok(asset.tradeoff.insufficient_evidence);
  // 知识实质性口径：来源 + 积累过程 + 适用边界。
  for (const key of ["source", "accumulation", "boundary"]) {
    assert.ok(asset.knowledgeStatement[key], `knowledgeStatement.${key} 缺失`);
  }
  // 消费方：capability + prompt 双入口。
  assert.ok(asset.consumed_by.some((consumer) => consumer.type === "capability" && consumer.ref === "security.correlate_threat_evidence"));
  assert.ok(asset.consumed_by.some((consumer) => consumer.type === "prompt" && consumer.ref === "security-triage-pipeline#CORRELATE_THREAT_EVIDENCE"));
  // 红线：仓库内不携带任何真实 IOC 正文（IP / 域名形态指示符）。
  assert.doesNotMatch(JSON.stringify(asset), /\b\d{1,3}(\.\d{1,3}){3}\b/);
});

test("LLM narrator can explain evidence but receives an immutable policy decision", async () => {
  const requests = [];
  const narrator = new OpenAICompatibleNarrator({
    apiBase: "https://model.example/v1",
    apiKey: "test-key",
    model: "test-model",
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return {
        ok: true,
        status: 200,
        json: async () => ({ choices: [{ message: { content: "证据充分，建议进入降噪复核。" } }] })
      };
    }
  });
  const decision = evaluateRules(matchingContext, rules);
  const narrative = await narrator.summarize({ ...matchingContext, networkIndicators: ["sensitive.example.test"] }, decision);
  assert.equal(narrative, "证据充分，建议进入降噪复核。");
  assert.equal(requests[0].url, "https://model.example/v1/chat/completions");
  const requestBody = JSON.parse(requests[0].init.body);
  assert.equal(requestBody.temperature, 0);
  assert.match(requestBody.messages[0].content, /不得更改 action/);
  assert.match(requestBody.messages[1].content, /suppress_with_review/);
  assert.doesNotMatch(requestBody.messages[1].content, /sensitive\.example\.test/);
});

test("Connect RPC adapter targets only the configured OctoBus capset and forwards trace context", async () => {
  const requests = [];
  const client = new OctoBusConnectClient({
    baseUrl: "http://octobus.internal:9000/",
    capsetId: "triage-agent",
    instanceId: "chaitin-triage-capabilities",
    fullService: "security.triage.v1.SecurityTriageService",
    token: "test-token",
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return { ok: true, status: 200, text: async () => '{"found":true}' };
    }
  });

  await client.getAlertContext("A-1001", "trace-test-002");
  assert.equal(
    requests[0].url,
    "http://octobus.internal:9000/capsets/triage-agent/connect/chaitin-triage-capabilities/security.triage.v1.SecurityTriageService/GetAlertContext"
  );
  assert.equal(requests[0].init.headers.authorization, "Bearer test-token");
  assert.equal(requests[0].init.headers["x-octobus-ext-business-request-id"], "trace-test-002");
  assert.equal(requests[0].init.headers["x-idempotency-key"], "context:trace-test-002");
  assert.ok(requests[0].init.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(requests[0].init.body), { alert_id: "A-1001" });
});

test("resilient executor retries transient failures and opens a per-operation circuit", async () => {
  const executor = new ResilientExecutor({
    maxAttempts: 2,
    circuitFailureThreshold: 3,
    circuitOpenMs: 60_000,
    sleep: async () => {},
    random: () => 0
  });
  let attempts = 0;
  const unavailable = Object.assign(new Error("unavailable"), { status: 503 });
  await assert.rejects(() => executor.run("GetAlertContext", async () => { attempts += 1; throw unavailable; }), /unavailable/);
  assert.equal(attempts, 2);
  await assert.rejects(() => executor.run("GetAlertContext", async () => { throw unavailable; }), /unavailable/);
  await assert.rejects(() => executor.run("GetAlertContext", async () => { throw unavailable; }), /unavailable/);
  await assert.rejects(() => executor.run("GetAlertContext", async () => { throw unavailable; }), /circuit is open/);
});

test("failed idempotent result write remains in SQLite and is recovered once", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "triage-outbox-"));
  const stateStore = new SqliteStateStore({ databasePath: path.join(directory, "state.db") });
  let recordAttempts = 0;
  const octobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() {
      recordAttempts += 1;
      if (recordAttempts === 1) throw Object.assign(new Error("gateway unavailable"), { status: 503 });
      return { accepted: true, recordId: "TR-recovered" };
    }
  };
  const agent = new SecurityTriageAgent({
    octobus,
    rules,
    stateStore,
    createTraceId: () => "trace-outbox-001",
    executor: new ResilientExecutor({ maxAttempts: 1, circuitFailureThreshold: 5, sleep: async () => {} })
  });

  try {
    const initial = await agent.triage({ alertId: "A-1001" });
    assert.equal(initial.status, "manual_review");
    assert.equal(initial.recoveryPending, true);
    const deliveries = await agent.recoverOutbox({ now: new Date(Date.now() + 31_000) });
    assert.deepEqual(deliveries.map(item => item.delivered), [true]);
    assert.equal(recordAttempts, 2);
  } finally {
    stateStore.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Enterprise WeChat notification is outbound-only, redacted, and validates its webhook", async () => {
  assert.throws(() => validateWeComWebhookUrl("https://example.test/hook"), /official Enterprise WeChat/);
  const content = formatWeComResult({
    alertId: "A-42",
    status: "escalate",
    action: "open_case",
    traceId: "trace-wecom-001",
    recorded: false,
    narrative: "raw IOC 203.0.113.77",
    evidence: [{ value: "sensitive.example.test" }]
  });
  assert.doesNotMatch(content, /203\.0\.113\.77|sensitive\.example/);
  const requests = [];
  const notifier = new WeComWebhookNotifier({
    webhookUrl: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key",
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return { ok: true, status: 200, text: async () => '{"errcode":0}' };
    }
  });
  const outcome = await notifier.sendResult({ alertId: "A-42", status: "escalate", action: "open_case", traceId: "trace-wecom-001", recorded: true });
  assert.equal(outcome.delivered, true);
  assert.equal(requests[0].init.method, "POST");
  assert.ok(requests[0].init.signal instanceof AbortSignal);
  const body = JSON.parse(requests[0].init.body);
  assert.equal(body.msgtype, "text");
  assert.match(body.text.content, /trace-wecom-001/);
});

test("Enterprise WeChat notifier serializes sends below the group robot rate limit", async () => {
  let clock = 1_000;
  const delays = [];
  const notifier = new WeComWebhookNotifier({
    webhookUrl: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test-key",
    minIntervalMs: 3_000,
    now: () => clock,
    sleep: async delay => { delays.push(delay); clock += delay; },
    fetchImpl: async () => ({ ok: true, status: 200, text: async () => '{"errcode":0}' })
  });
  const result = { alertId: "A-43", status: "needs_review", action: "open_case", traceId: "trace-wecom-002", recorded: true };
  await notifier.sendResult(result);
  await notifier.sendResult(result);
  assert.deepEqual(delays, [3_000]);
});
