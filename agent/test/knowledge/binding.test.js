import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SecurityTriageAgent, IOC_ESCALATION_KNOWLEDGE } from '../../src/application/pipelines/security-triage-pipeline.js';
import { MalwareTriageAgent } from '../../src/application/pipelines/malware-triage-pipeline.js';
import { LocalRagRetriever, loadRagCorpusJsonl } from '../../src/infrastructure/knowledge/local-rag.js';

const agentDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const knowledgeDirectory = path.resolve(agentDirectory, '..', 'knowledge', 'corpus', 'security');

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

const sha256 = 'a'.repeat(64);
const sanitizedReport = {
  sample_id: 'apk-001', sha256, source: 'mock',
  findings: {
    permissions: ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.RECEIVE_BOOT_COMPLETED'],
    components: [], network_indicators: ['api.example.test'],
    behaviors: ['periodic beacon'], string_indicators: ['config_token', 'campaign_alpha']
  }
};

test('security pipeline records the IOC escalation knowledge hit with terminal metrics', async () => {
  const privateEvidence = [{
    evidence_id: 'IOC-IP-KB-0001',
    source_type: 'APT_IP',
    indicator_or_signature: '203.0.113.77'
  }];
  const octobus = {
    async getAlertContext() { return { ...matchingContext, networkIndicators: ['203.0.113.77'] }; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-kb-ioc' }; }
  };

  const result = await new SecurityTriageAgent({
    octobus, rules, threatEvidence: privateEvidence, createTraceId: () => 'trace-kb-ioc'
  }).triage({ alertId: 'A-kb-ioc' });

  assert.equal(result.status, 'escalate');
  assert.ok(result.knowledgeHits.includes('kb-security-ioc-escalation'), 'IOC 命中应留痕 kb-security-ioc-escalation');
  assert.equal(result.knowledgeHits.filter((id) => id === 'kb-security-ioc-escalation').length, 1, '命中列表应去重');
  assert.ok(result.metrics.knowledge_hits >= 1, '终态指标 knowledge_hits 应计入 IOC 命中');
  assert.doesNotMatch(JSON.stringify(result), /203\.0\.113\.77/);
});

test('security pipeline records the matched false-positive rule knowledge hit', async () => {
  const octobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-kb-fp' }; }
  };

  const result = await new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-kb-fp' }).triage({ alertId: 'A-kb-fp' });

  assert.equal(result.matchedRuleId, 'fp_dns_001');
  assert.deepEqual(result.knowledgeHits, ['kb-security-fp-dns-001']);
  assert.equal(result.metrics.knowledge_hits, 1);
});

test('security rules without knowledge_id produce no knowledge hit and keep the placeholder metric', async () => {
  const legacyRules = {
    rules: [{ ...rules.rules[0], knowledge_id: undefined }]
  };
  const octobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-kb-legacy' }; }
  };

  const result = await new SecurityTriageAgent({ octobus, rules: legacyRules, createTraceId: () => 'trace-kb-legacy' }).triage({ alertId: 'A-kb-legacy' });

  assert.equal(result.matchedRuleId, 'fp_dns_001');
  assert.deepEqual(result.knowledgeHits, []);
  assert.equal(result.metrics.knowledge_hits, 0);
});

test('malware pipeline records grounded RAG knowledge ids with terminal metrics', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'kb-rag-corpus-'));
  try {
    const corpusPath = path.join(directory, 'corpus.jsonl');
    writeFileSync(corpusPath, `${JSON.stringify({
      id: 'doc-c2',
      text: 'android periodic beacon command control campaign alpha',
      source_ref: 'private-case-001',
      knowledge_id: 'kb-malware-c2-001',
      consumed_by: [{ type: 'capability', ref: 'malware.assess_risk' }]
    })}\n`);
    const octobus = { call: async (request) => {
      if (request.method === 'GetSanitizedReport') return sanitizedReport;
      if (request.method === 'ValidateYaraCandidate') return { status: 'passed', benign_false_positive_rate: 0 };
      return { task_id: 'review-kb-rag' };
    }};

    const result = await new MalwareTriageAgent({
      octobus,
      stateStore: { snapshot: async () => {} },
      retriever: new LocalRagRetriever({ chunks: loadRagCorpusJsonl(corpusPath), topK: 2, minScore: 0.05 }),
      traceIdFactory: () => 'trace-kb-malware'
    }).run({ sampleId: 'apk-001', sha256 });

    assert.equal(result.retrieval.status, 'grounded');
    assert.deepEqual(result.knowledgeHits, ['kb-malware-c2-001']);
    assert.equal(result.metrics.knowledge_hits, 1);
    assert.deepEqual(
      result.retrieval.knowledgeConsumedBy['kb-malware-c2-001'],
      [{ type: 'capability', ref: 'malware.assess_risk' }]
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('the IOC escalation binding constant mirrors the committed knowledge asset', () => {
  const asset = JSON.parse(readFileSync(path.join(knowledgeDirectory, 'threat-evidence-judgment.json'), 'utf8'));
  assert.equal(IOC_ESCALATION_KNOWLEDGE.knowledge_id, asset.knowledge_id);
  assert.deepEqual(IOC_ESCALATION_KNOWLEDGE.consumed_by, asset.consumed_by);
});

test('security CLI appends an independent KNOWLEDGE_HIT audit record with the consumer view', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'triage-audit-kb-'));
  const auditPath = path.join(directory, 'audit.log');
  // 本地 OctoBus 网关替身：以真实 Connect RPC HTTP 语义响应取数与结论上报。
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      const payload = request.url.endsWith('/GetAlertContext')
        ? matchingContext
        : { accepted: true, recordId: 'TR-cli-kb' };
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify(payload));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  try {
    const cli = path.join(agentDirectory, 'src', 'interfaces', 'security-cli.js');
    // 必须用异步 spawn：同步 spawn 会阻塞本进程事件循环，本地网关无法响应子进程。
    const child = spawn(process.execPath, [cli, '--alert-id', 'A-1001'], {
      cwd: agentDirectory,
      env: {
        ...process.env,
        OCTOBUS_BASE_URL: `http://127.0.0.1:${port}`,
        OCTOBUS_CAPSET_ID: 'kb-test',
        OCTOBUS_INSTANCE_ID: 'kb-test',
        TRIAGE_STATE_DB_PATH: path.join(directory, 'state.db'),
        TRIAGE_AUDIT_LOG_PATH: auditPath,
        KNOWLEDGE_ABLATION: '',
        LLM_API_BASE: '', LLM_API_ENDPOINT: '', LLM_API_KEY: '', LLM_MODEL: '',
        WECOM_WEBHOOK_URL: ''
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const killTimer = setTimeout(() => child.kill(), 30_000);
    const status = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    clearTimeout(killTimer);
    assert.equal(status, 0, stderr || stdout);

    const stdoutResult = JSON.parse(stdout);
    assert.deepEqual(stdoutResult.knowledgeHits, ['kb-security-fp-dns-001']);
    assert.equal(stdoutResult.metrics.knowledge_hits, 1);

    const records = readFileSync(auditPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    const hit = records.find((record) => record.event === 'KNOWLEDGE_HIT');
    assert.ok(hit, '审计日志应存在 KNOWLEDGE_HIT 独立记录');
    assert.equal(hit.workflow, 'security');
    assert.equal(hit.traceId, stdoutResult.traceId);
    assert.deepEqual(hit.knowledge_ids, ['kb-security-fp-dns-001']);
    // consumed_by 合并视图取自提交入库的规则资产（规范 §9.5 反向留痕）。
    const [committedRule] = JSON.parse(readFileSync(path.join(knowledgeDirectory, 'false-positive-rules.json'), 'utf8')).rules;
    assert.deepEqual(hit.consumed_by, [{ knowledge_id: 'kb-security-fp-dns-001', consumed_by: committedRule.consumed_by }]);
  } finally {
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
