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

test('routes an explicit malware self-check through the unified CLI', () => {
  const result = run(['--workflow', 'malware', '--self-check']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /"status": "ok"/);
});

test('rejects a command that would select both capability domains', () => {
  const result = run(['--alert-id', 'A-1001', '--self-check']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Choose exactly one workflow/);
});

test('routes security flags to the security configuration contract', () => {
  const result = run(['--workflow', 'security', '--alert-id', 'A-1001']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /OCTOBUS_BASE_URL/);
});
