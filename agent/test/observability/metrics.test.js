import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SecurityTriageAgent } from '../../src/application/pipelines/security-triage-pipeline.js';
import { MalwareTriageAgent } from '../../src/application/pipelines/malware-triage-pipeline.js';

const agentDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const rules = {
  rules: [
    {
      ruleId: 'fp_dns_001',
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

function assertStageDurations(metrics, expectedStages) {
  assert.ok(metrics.stage_durations && typeof metrics.stage_durations === 'object', 'metrics.stage_durations 应为对象');
  assert.ok(Object.keys(metrics.stage_durations).length >= 1, 'stage_durations 至少包含主要阶段');
  for (const [state, duration] of Object.entries(metrics.stage_durations)) {
    assert.ok(Number.isInteger(duration) && duration >= 0, `阶段 ${state} 耗时应为非负整数毫秒，实际 ${duration}`);
  }
  for (const state of expectedStages) {
    assert.ok(state in metrics.stage_durations, `stage_durations 缺少主要阶段 ${state}`);
  }
}

test('security pipeline reports terminal metrics on a successful triage', async () => {
  const octobus = {
    async getAlertContext() { return matchingContext; },
    async recordTriageResult() { return { accepted: true, recordId: 'TR-metrics' }; }
  };
  const agent = new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-metrics-ok' });

  const result = await agent.triage({ alertId: 'A-1001' });

  assert.equal(result.status, 'needs_review');
  assert.ok(result.metrics, 'result.metrics 应存在');
  // GetAlertContext + RecordTriageResult 两次能力调用均成功。
  assert.ok(result.metrics.capability_calls >= 1);
  assert.equal(result.metrics.capability_calls, 2);
  assert.equal(result.metrics.capability_failures, 0);
  assert.equal(result.metrics.knowledge_hits, 0);
  assert.equal(result.metrics.narrative_source, 'deterministic');
  assert.equal(result.metrics.manual_escalation, false);
  assertStageDurations(result.metrics, ['RECEIVED', 'ACQUIRE_CONTEXT', 'APPLY_RULES', 'COMPLETED']);
});

test('security pipeline keeps collected metrics when the alert cannot be found', async () => {
  const octobus = {
    async getAlertContext() { return { found: false }; }
  };
  const agent = new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-metrics-miss' });

  const result = await agent.triage({ alertId: 'A-404' });

  assert.equal(result.status, 'manual_review');
  assert.ok(result.metrics, '失败路径同样携带 metrics');
  assert.equal(result.metrics.capability_calls, 1);
  assert.equal(result.metrics.capability_failures, 0);
  assert.equal(result.metrics.narrative_source, null);
  assert.equal(result.metrics.manual_escalation, true);
  assertStageDurations(result.metrics, ['RECEIVED', 'ACQUIRE_CONTEXT', 'NEED_HUMAN']);
});

test('security pipeline counts a failed capability call into capability_failures', async () => {
  const octobus = {
    async getAlertContext() { throw new Error('gateway unavailable'); }
  };
  const agent = new SecurityTriageAgent({ octobus, rules, createTraceId: () => 'trace-metrics-fail' });

  const result = await agent.triage({ alertId: 'A-500' });

  assert.equal(result.status, 'manual_review');
  assert.ok(result.metrics);
  assert.equal(result.metrics.capability_calls, 1);
  assert.equal(result.metrics.capability_failures, 1);
  assert.equal(result.metrics.manual_escalation, true);
});

test('malware pipeline reports terminal metrics on a successful triage', async () => {
  const octobus = { call: async (request) => {
    if (request.method === 'GetSanitizedReport') return sanitizedReport;
    if (request.method === 'ValidateYaraCandidate') return { status: 'passed', benign_false_positive_rate: 0 };
    if (request.method === 'CreateRuleReviewTask') return { task_id: 'review-metrics' };
  }};
  const agent = new MalwareTriageAgent({
    octobus,
    stateStore: { snapshot: async () => {} },
    narrator: { kind: 'llm', analyze: async () => ({ summary: 'LLM 仅解释脱敏证据。', ruleReview: '候选规则仍须人工复核。', evidenceGaps: [] }) },
    traceIdFactory: () => 'trace-metrics-malware'
  });

  const result = await agent.run({ sampleId: 'apk-001', sha256 });

  assert.equal(result.action, 'HUMAN_REVIEW_REQUIRED');
  assert.ok(result.metrics, 'result.metrics 应存在');
  // GetSanitizedReport + ValidateYaraCandidate + CreateRuleReviewTask。
  assert.equal(result.metrics.capability_calls, 3);
  assert.equal(result.metrics.capability_failures, 0);
  assert.equal(result.metrics.knowledge_hits, 0);
  assert.equal(result.metrics.narrative_source, 'llm');
  // 恶意样本工作流终态恒为人工复核（autoPublish 恒为 false），即升级人工。
  assert.equal(result.metrics.manual_escalation, true);
  assertStageDurations(result.metrics, ['RECEIVED', 'RETRIEVE_REPORT', 'LLM_ANALYZE', 'COMPLETED']);
});

test('malware pipeline keeps metrics and counts the failure on the NEED_HUMAN path', async () => {
  const agent = new MalwareTriageAgent({
    octobus: { call: async () => { throw new Error('gateway down'); } },
    stateStore: { snapshot: async () => {} },
    traceIdFactory: () => 'trace-metrics-malware-fail',
    sleep: async () => {}
  });

  const result = await agent.run({ sampleId: 'apk-err', sha256: 'b'.repeat(64) });

  assert.ok(result.error);
  assert.ok(result.metrics, '失败路径同样携带 metrics');
  assert.equal(result.metrics.capability_calls, 1);
  assert.equal(result.metrics.capability_failures, 1);
  assert.equal(result.metrics.narrative_source, null);
  assert.equal(result.metrics.manual_escalation, true);
  assertStageDurations(result.metrics, ['RECEIVED', 'RETRIEVE_REPORT', 'NEED_HUMAN']);
});

test('security CLI writes the terminal audit record with metrics', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'triage-audit-metrics-'));
  const auditPath = path.join(directory, 'audit.log');
  // 本地 OctoBus 网关替身：以真实 Connect RPC HTTP 语义响应取数与结论上报。
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      const payload = request.url.endsWith('/GetAlertContext')
        ? matchingContext
        : { accepted: true, recordId: 'TR-cli-metrics' };
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
        OCTOBUS_CAPSET_ID: 'metrics-test',
        OCTOBUS_INSTANCE_ID: 'metrics-test',
        TRIAGE_STATE_DB_PATH: path.join(directory, 'state.db'),
        TRIAGE_AUDIT_LOG_PATH: auditPath,
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
    assert.ok(stdoutResult.metrics, 'CLI 输出应包含 metrics');
    assert.equal(stdoutResult.metrics.manual_escalation, false);

    const records = readFileSync(auditPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    const completed = records.find((record) => record.event === 'workflow.completed');
    assert.ok(completed, '审计日志应存在 workflow.completed 记录');
    assert.ok(completed.metrics, '审计记录应包含 metrics 字段');
    assert.ok(completed.metrics.capability_calls >= 1);
    assert.equal(completed.metrics.capability_failures, 0);
    assert.equal(completed.metrics.manual_escalation, false);
    assert.equal(completed.metrics.narrative_source, 'deterministic');
    assertStageDurations(completed.metrics, ['RECEIVED', 'COMPLETED']);
  } finally {
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
