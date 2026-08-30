import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const agentDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(agentDirectory, 'src', 'interfaces', 'cli.js');

function run(args, environment = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: agentDirectory,
    encoding: 'utf8',
    env: { ...process.env, ...environment }
  });
}

test('rejects an explicit malware workflow request (not enabled in demo)', () => {
  const result = run(['--workflow', 'malware', '--self-check']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Malware workflow is not enabled in this demo/);
});

test('rejects malware-specific flags even without --workflow', () => {
  const result = run(['--sample-id', 'apk-001', '--sha256', 'a'.repeat(64)]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Malware workflow is not enabled in this demo/);
});

test('rejects a command that mixes security and malware arguments', () => {
  const result = run(['--alert-id', 'A-1001', '--self-check']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Malware workflow is not enabled in this demo/);
});

test('routes security flags to the security configuration contract', () => {
  const result = run(['--workflow', 'security', '--alert-id', 'A-1001']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /OCTOBUS_BASE_URL/);
});
