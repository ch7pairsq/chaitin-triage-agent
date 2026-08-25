import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  handleConnectCall,
  parseConnectRoute,
  createTriageCapabilityServer
} from '../../../octobus-services/triage-capabilities/dist/index.js';
import { OctoBusConnectClient } from '../../src/infrastructure/octobus/connect-client.js';

const rules = {
  rules: [
    {
      ruleId: 'fp_dns_001',
      description: 'Authorized scanner DNS activity.',
      evidenceRequired: ['sourceAssetTag', 'eventTime', 'approvedScanWindow', 'destinationPort'],
      conditions: { sourceAssetTag: 'vulnerability_scanner', approvedScanWindow: true, destinationPort: 53 },
      decision: { falsePositiveScore: 0.85, action: 'suppress_with_review' }
    }
  ]
};

test('routes a Connect RPC path to the capability service', () => {
  const route = parseConnectRoute('/capsets/triage-capabilities/connect/demo-1/triage.capabilities.v1.CapabilityService/AssessRisk');
  assert.equal(route.service, 'triage.capabilities.v1.CapabilityService');
  assert.equal(route.method, 'AssessRisk');
  assert.equal(parseConnectRoute('/backend/sandbox/exec'), null);
});

test('exposes only registered capabilities and rejects unknown methods', () => {
  const ok = handleConnectCall({
    service: 'triage.capabilities.v1.CapabilityService',
    method: 'EvaluateFalsePositiveRules',
    body: {
      context: { sourceAssetTag: 'vulnerability_scanner', eventTime: '2026-08-25T10:00:00Z', approvedScanWindow: true, destinationPort: 53 },
      rules
    }
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.status, 'needs_review');
  assert.equal(ok.body.action, 'suppress_with_review');

  const unknown = handleConnectCall({
    service: 'triage.capabilities.v1.CapabilityService',
    method: 'CallModel',
    body: {}
  });
  assert.equal(unknown.status, 404);
});

test('enforces the capset token when one is configured', () => {
  const denied = handleConnectCall({
    service: 'triage.capabilities.v1.CapabilityService',
    method: 'AssessRisk',
    body: { report: {} },
    token: 'wrong',
    expectedToken: 'x'.repeat(16)
  });
  assert.equal(denied.status, 401);
});

test('serves the agent OctoBusConnectClient end to end and logs access', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'triage-capabilities-'));
  const accessLog = path.join(directory, 'access.log');
  const { server } = createTriageCapabilityServer({ port: 0, accessLogPath: accessLog });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  try {
    const client = new OctoBusConnectClient({
      baseUrl: `http://127.0.0.1:${address.port}`,
      capsetId: 'triage-capabilities',
      instanceId: 'demo-1',
      fullService: 'triage.capabilities.v1.CapabilityService'
    });
    const result = await client.call({
      method: 'EvaluateFalsePositiveRules',
      body: {
        context: { sourceAssetTag: 'vulnerability_scanner', eventTime: '2026-08-25T10:00:00Z', approvedScanWindow: true, destinationPort: 53 },
        rules
      },
      traceId: 'trace-service-1'
    });
    assert.equal(result.status, 'needs_review');
    // 留痕：能力调用在网关侧追加 NDJSON access.log，trace_id 贯穿。
    const logged = JSON.parse(readFileSync(accessLog, 'utf8').trim());
    assert.equal(logged.trace_id, 'trace-service-1');
    assert.match(logged.capability, /EvaluateFalsePositiveRules$/);
  } finally {
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
