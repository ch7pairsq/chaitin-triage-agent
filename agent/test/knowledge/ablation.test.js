import test from 'node:test';
import assert from 'node:assert/strict';

import { knowledgeAblationFromEnvironment } from '../../src/config/env.js';
import { SecurityTriageAgent } from '../../src/application/pipelines/security-triage-pipeline.js';
import { MalwareTriageAgent } from '../../src/application/pipelines/malware-triage-pipeline.js';
import { NoopStateStore } from '../../src/infrastructure/db/security-state-store.js';

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

const matchingContext = {
  found: true,
  alertId: 'A-1001',
  title: 'DNS activity',
  sourceAssetTag: 'vulnerability_scanner',
  eventTime: '2026-08-20T02:05:00Z',
  approvedScanWindow: true,
  destinationPort: 53
};

/** 捕获状态快照以断言消融标记（correlation.ablated）进入留痕。 */
class CapturingStateStore extends NoopStateStore {
  constructor() {
    super();
    this.saves = [];
  }

  save(event) {
    this.saves.push(event);
  }
}

test('knowledge ablation environment parsing yields an empty set when unconfigured', () => {
  assert.equal(knowledgeAblationFromEnvironment({}).size, 0);
  assert.equal(knowledgeAblationFromEnvironment({ KNOWLEDGE_ABLATION: '' }).size, 0);
  assert.deepEqual([...knowledgeAblationFromEnvironment({ KNOWLEDGE_ABLATION: ' kb-a , kb-b ,, ' })], ['kb-a', 'kb-b']);
});

test('ablating the matched false-positive rule removes suppression and marks the ablation', async () => {
  const octobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-abl-fp' }; }
  };

  const result = await new SecurityTriageAgent({
    octobus, rules, knowledgeAblation: ['kb-security-fp-dns-001'], createTraceId: () => 'trace-abl-fp'
  }).triage({ alertId: 'A-abl-fp' });

  assert.notEqual(result.action, 'suppress_with_review', '被消融规则不应再驱动降噪复核');
  assert.deepEqual([result.status, result.action], ['manual_review', 'request_additional_evidence']);
  assert.ok(result.evidenceRefs.length > 0, '消融后仍必须携带已有上下文证据引用');
  assert.ok(result.knowledgeAblated.includes('kb-security-fp-dns-001'), 'knowledgeAblated 应含被消融规则 id');
  assert.ok(!result.knowledgeHits.includes('kb-security-fp-dns-001'), '被消融规则不得再计入命中');
  assert.equal(result.metrics.knowledge_hits, 0);
});

test('ablating the IOC escalation knowledge falls back to rule judgment', async () => {
  const privateEvidence = [{
    evidence_id: 'IOC-IP-ABL-001',
    source_type: 'APT_IP',
    indicator_or_signature: '198.51.100.77'
  }];
  const octobus = {
    async getAlertContext() { return { ...matchingContext, networkIndicators: ['198.51.100.77'] }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-abl-ioc' }; }
  };
  const stateStore = new CapturingStateStore();

  const result = await new SecurityTriageAgent({
    octobus, rules, threatEvidence: privateEvidence,
    knowledgeAblation: ['kb-security-ioc-escalation'],
    stateStore,
    createTraceId: () => 'trace-abl-ioc'
  }).triage({ alertId: 'A-abl-ioc' });

  assert.deepEqual([result.status, result.action], ['needs_review', 'suppress_with_review'], 'IOC 判据消融后回退规则判定');
  assert.equal(result.threatEvidenceMatched, 0);
  assert.ok(result.knowledgeAblated.includes('kb-security-ioc-escalation'), 'knowledgeAblated 应含被消融 IOC 判据 id');
  assert.ok(result.knowledgeHits.includes('kb-security-fp-dns-001'), '回退后由规则知识驱动命中');
  assert.ok(!result.knowledgeHits.includes('kb-security-ioc-escalation'), '被消融判据不得计入命中');
  const correlateSnapshot = stateStore.saves.find((event) => event.state === 'CORRELATE_THREAT_EVIDENCE');
  assert.equal(correlateSnapshot.payload.correlation.ablated, true, '快照应携带 correlation.ablated 标记');
  assert.equal(correlateSnapshot.payload.correlation.matchedCount, 0);
  assert.doesNotMatch(JSON.stringify(result), /198\.51\.100\.77/);
});

test('without ablation the judgment, knowledge hits, and result fields stay unchanged', async () => {
  const ruleOctobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-no-abl-fp' }; }
  };
  const ruleRun = await new SecurityTriageAgent({ octobus: ruleOctobus, rules, createTraceId: () => 'trace-no-abl-fp' }).triage({ alertId: 'A-no-abl-fp' });
  assert.deepEqual([ruleRun.status, ruleRun.action], ['needs_review', 'suppress_with_review']);
  assert.equal(ruleRun.knowledgeAblated, undefined, '未配置消融时不应出现 knowledgeAblated 字段');
  assert.deepEqual(ruleRun.knowledgeHits, ['kb-security-fp-dns-001']);

  const privateEvidence = [{
    evidence_id: 'IOC-IP-NOABL-001',
    source_type: 'APT_IP',
    indicator_or_signature: '203.0.113.77'
  }];
  const iocOctobus = {
    async getAlertContext() { return { ...matchingContext, networkIndicators: ['203.0.113.77'] }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-no-abl-ioc' }; }
  };
  const iocRun = await new SecurityTriageAgent({
    octobus: iocOctobus, rules, threatEvidence: privateEvidence, createTraceId: () => 'trace-no-abl-ioc'
  }).triage({ alertId: 'A-no-abl-ioc' });
  assert.deepEqual([iocRun.status, iocRun.action], ['escalate', 'open_case']);
  assert.equal(iocRun.knowledgeAblated, undefined, '未配置消融时不应出现 knowledgeAblated 字段');
  assert.deepEqual(iocRun.knowledgeHits, ['kb-security-ioc-escalation']);
});

test('malware ablation strips citations of ablated knowledge ids', async () => {
  const sha256 = 'a'.repeat(64);
  const report = {
    sample_id: 'apk-abl', sha256, source: 'mock',
    findings: {
      permissions: ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.RECEIVE_BOOT_COMPLETED'],
      components: [], network_indicators: ['api.example.test'],
      behaviors: ['periodic beacon'], string_indicators: ['config_token', 'campaign_alpha']
    }
  };
  const octobus = { call: async (request) => {
    if (request.method === 'GetSanitizedReport') return report;
    if (request.method === 'ValidateYaraCandidate') return { status: 'passed', benign_false_positive_rate: 0 };
    return { task_id: 'review-abl-malware' };
  }};

  const result = await new MalwareTriageAgent({
    octobus,
    stateStore: { snapshot: async () => {} },
    retriever: { retrieve: () => ({
      status: 'grounded', topScore: 0.5,
      knowledgeIds: ['kb-malware-a', 'kb-malware-b'],
      citations: [
        { citationId: 'case-a#1', sourceRef: 'case-a', title: 'a', snippet: 'redacted', score: 0.5, knowledgeId: 'kb-malware-a' },
        { citationId: 'case-b#1', sourceRef: 'case-b', title: 'b', snippet: 'redacted', score: 0.4, knowledgeId: 'kb-malware-b' }
      ]
    }) },
    knowledgeAblation: ['kb-malware-a'],
    traceIdFactory: () => 'trace-abl-malware'
  }).run({ sampleId: 'apk-abl', sha256 });

  assert.deepEqual(result.retrieval.citations.map((citation) => citation.citationId), ['case-b#1'], '被消融知识的 citation 应被剔除');
  assert.deepEqual(result.knowledgeHits, ['kb-malware-b']);
  assert.deepEqual(result.knowledgeAblated, ['kb-malware-a']);
  assert.equal(result.metrics.knowledge_hits, 1);
});
