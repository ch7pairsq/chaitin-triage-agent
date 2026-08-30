import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applySeverityGating,
  applyAssetCriticalityGate,
  SEVERITY_GATING_KNOWLEDGE,
  ASSET_CRITICALITY_KNOWLEDGE
} from '../../src/capabilities/security/escalation-gates.js';
import { SecurityTriageAgent } from '../../src/application/pipelines/security-triage-pipeline.js';

const knowledgeDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../knowledge/corpus/security');

const rules = {
  rules: [
    {
      ruleId: 'fp_dns_001',
      knowledge_id: 'kb-security-fp-dns-001',
      description: 'Authorized scanner DNS activity.',
      evidenceRequired: ['sourceAssetTag', 'eventTime', 'approvedScanWindow', 'destinationPort'],
      conditions: {
        sourceAssetTag: 'vulnerability_scanner',
        approvedScanWindow: true,
        destinationPort: 53
      },
      decision: { falsePositiveScore: 0.85, action: 'suppress_with_review' }
    }
  ]
};

const suppression = {
  status: 'needs_review',
  action: 'suppress_with_review',
  matchedRuleId: 'fp_dns_001',
  falsePositiveScore: 0.85,
  evidence: [{ field: 'sourceAssetTag', label: '源资产标签', value: 'vulnerability_scanner', present: true }],
  reason: 'rule'
};

// ---------- 纯函数：严重度门控 ----------

test('severity gate passes low/medium suppressions and records the signal as evidence', () => {
  const { decision, gate } = applySeverityGating(suppression, { severity: 'medium' });
  assert.equal(gate.outcome, 'passed');
  assert.equal(gate.knowledgeId, SEVERITY_GATING_KNOWLEDGE.knowledge_id);
  assert.equal(decision.status, 'needs_review');
  assert.ok(decision.evidence.some((item) => item.field === 'severityGate' && item.value === 'medium'));
});

test('severity gate blocks high/critical suppressions by demoting to manual confirmation', () => {
  for (const severity of ['high', 'critical']) {
    const { decision, gate } = applySeverityGating(suppression, { severity });
    assert.equal(gate.outcome, 'blocked', `${severity} 应被门控拦截`);
    assert.equal(decision.status, 'manual_review');
    assert.equal(decision.action, 'manual_confirm_required');
    assert.equal(decision.matchedRuleId, 'fp_dns_001', '命中规则事实保留');
    assert.match(decision.reason, /降噪门控/);
  }
});

// ---------- 纯函数：关键资产提级 ----------

test('asset criticality gate blocks critical assets regardless of score', () => {
  const { decision, gate } = applyAssetCriticalityGate(
    { ...suppression, falsePositiveScore: 0.95 },
    { assetCriticality: 'critical' }
  );
  assert.equal(gate.outcome, 'blocked');
  assert.deepEqual([decision.status, decision.action], ['manual_review', 'manual_confirm_required']);
});

test('asset criticality gate blocks high assets when suppression confidence is below 0.9', () => {
  const { decision, gate } = applyAssetCriticalityGate(suppression, { assetCriticality: 'high' });
  assert.equal(gate.outcome, 'blocked');
  assert.equal(decision.status, 'manual_review');
  const confident = applyAssetCriticalityGate(
    { ...suppression, falsePositiveScore: 0.95 },
    { assetCriticality: 'high' }
  );
  assert.equal(confident.gate.outcome, 'passed', 'high 且置信度足够时应放行');
});

test('asset criticality gate passes medium/low assets with evidence left behind', () => {
  const { decision, gate } = applyAssetCriticalityGate(suppression, { assetCriticality: 'medium' });
  assert.equal(gate.outcome, 'passed');
  assert.ok(decision.evidence.some((item) => item.field === 'assetCriticalityGate' && item.value === 'medium'));
});

// ---------- 纯函数：不适用分支 ----------

test('both gates skip non-suppression decisions and missing signal fields', () => {
  for (const apply of [applySeverityGating, applyAssetCriticalityGate]) {
    const escalate = { status: 'escalate', action: 'open_case', evidence: [], reason: 'ioc' };
    assert.equal(apply(escalate, { severity: 'high', assetCriticality: 'critical' }).gate.outcome, 'skipped');
    assert.equal(apply(suppression, {}).gate.outcome, 'skipped');
    assert.equal(apply(suppression, { severity: '', assetCriticality: null }).gate.outcome, 'skipped');
  }
});

// ---------- 知识-代码绑定镜像（规范 §9.5）----------

test('gate binding constants mirror the committed knowledge assets', () => {
  for (const [constant, file] of [
    [SEVERITY_GATING_KNOWLEDGE, 'severity-gating.json'],
    [ASSET_CRITICALITY_KNOWLEDGE, 'asset-criticality-escalation.json']
  ]) {
    const asset = JSON.parse(readFileSync(path.join(knowledgeDirectory, file), 'utf8'));
    assert.equal(constant.knowledge_id, asset.knowledge_id, `${file} knowledge_id 应与代码常量一致`);
    assert.deepEqual(constant.consumed_by, asset.consumed_by, `${file} consumed_by 应与代码常量一致`);
  }
});

// ---------- 管线集成 ----------

const gatedContext = {
  found: true,
  alertId: 'A-1001',
  title: 'Internal DNS reconnaissance',
  severity: 'medium',
  sourceAssetTag: 'vulnerability_scanner',
  eventTime: '2026-08-20T02:05:00Z',
  approvedScanWindow: true,
  destinationPort: 53,
  assetCriticality: 'medium'
};

test('pipeline records severity and asset-criticality gate knowledge hits alongside the FP rule', async () => {
  const octobus = {
    async getAlertContext() { return gatedContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-gate-both' }; }
  };

  const result = await new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-gate-both' }).triage({ alertId: 'A-gate-both' });

  assert.deepEqual([result.status, result.action], ['needs_review', 'suppress_with_review'], 'medium 信号门控放行，原结论保持');
  assert.deepEqual(
    [...result.knowledgeHits].sort(),
    ['kb-security-asset-criticality-escalation', 'kb-security-fp-dns-001', 'kb-security-severity-gating'],
    '降噪 + IOC 之外的两个门控判据都应计入知识命中'
  );
  assert.equal(result.metrics.knowledge_hits, 3);
  assert.ok(result.evidenceRefs.includes('severityGate'), '严重度门控证据应进入 evidenceRefs');
  assert.ok(result.evidenceRefs.includes('assetCriticalityGate'), '关键资产门控证据应进入 evidenceRefs');
});

test('pipeline demotes suppression to manual review when severity is high', async () => {
  const octobus = {
    async getAlertContext() { return { ...gatedContext, severity: 'high' }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-gate-sev' }; }
  };

  const result = await new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-gate-sev' }).triage({ alertId: 'A-gate-sev' });

  assert.deepEqual([result.status, result.action], ['manual_review', 'manual_confirm_required'], '高危告警降噪复核必须让位人工确认');
  assert.ok(result.knowledgeHits.includes('kb-security-severity-gating'));
  assert.ok(result.knowledgeHits.includes('kb-security-fp-dns-001'), '规则命中事实保留在知识命中中');
});

test('pipeline demotes suppression on critical assets even with medium severity', async () => {
  const octobus = {
    async getAlertContext() { return { ...gatedContext, assetCriticality: 'critical' }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-gate-asset' }; }
  };

  const result = await new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-gate-asset' }).triage({ alertId: 'A-gate-asset' });

  assert.deepEqual([result.status, result.action], ['manual_review', 'manual_confirm_required']);
  assert.ok(result.knowledgeHits.includes('kb-security-asset-criticality-escalation'));
});

test('ablating a gate knowledge skips the gate and marks the ablation without touching the other gate', async () => {
  const octobus = {
    async getAlertContext() { return { ...gatedContext, severity: 'high' }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-gate-abl' }; }
  };

  const result = await new SecurityTriageAgent({
    octobus,
    rules,
    knowledgeAblation: ['kb-security-severity-gating'],
    createTraceId: () => 'trace-gate-abl'
  }).triage({ alertId: 'A-gate-abl' });

  assert.deepEqual([result.status, result.action], ['needs_review', 'suppress_with_review'], '严重度门控被消融后回退原降噪结论');
  assert.ok(result.knowledgeAblated.includes('kb-security-severity-gating'), '被消融门控应显式留痕');
  assert.ok(!result.knowledgeHits.includes('kb-security-severity-gating'), '被消融门控不得计入命中');
  assert.ok(result.knowledgeHits.includes('kb-security-asset-criticality-escalation'), '未消融门控照常命中');
});

test('IOC escalation decisions bypass both gates and record only the IOC knowledge hit', async () => {
  const privateEvidence = [{
    evidence_id: 'IOC-IP-GATE-0001',
    source_type: 'APT_IP',
    indicator_or_signature: '203.0.113.99'
  }];
  const octobus = {
    async getAlertContext() { return { ...gatedContext, severity: 'critical', assetCriticality: 'critical', networkIndicators: ['203.0.113.99'] }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-gate-ioc' }; }
  };

  const result = await new SecurityTriageAgent({
    octobus, rules, threatEvidence: privateEvidence, createTraceId: () => 'trace-gate-ioc'
  }).triage({ alertId: 'A-gate-ioc' });

  assert.deepEqual([result.status, result.action], ['escalate', 'open_case'], '升级类结论不经过降噪门控');
  assert.deepEqual(result.knowledgeHits, ['kb-security-ioc-escalation']);
  assert.equal(result.knowledgeAblated, undefined);
});
