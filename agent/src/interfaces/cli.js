#!/usr/bin/env node
/**
 * 接口层：统一分发入口（规范 §5.2 interfaces/）。
 *
 * 两条有界工作流（security / malware）的唯一触发入口：
 * - 工作流选择只来自显式 CLI flag（--workflow / 专属参数），不受 prompt
 *   文本影响——prompt 永远不能选择权限（规范 §6 权限边界）；
 * - 同时命中两个域的参数直接报错拒绝（避免能力越界）；
 * - 按所选工作流做域前缀环境变量别名（SECURITY_TRIAGE_* / MALWARE_TRIAGE_*），
 *   未选中的工作流变量不生效。
 */
const args = process.argv.slice(2);
const requestedWorkflow = option('--workflow');
const securityRequested = args.includes('--alert-id') || args.includes('--recover-outbox') || requestedWorkflow === 'security';
const malwareRequested = args.some((value) => ['--sample-id', '--sample-ref', '--sha256', '--session-id', '--message', '--event-file', '--self-check'].includes(value)) || requestedWorkflow === 'malware';

if (securityRequested && malwareRequested) {
  throw new Error('Choose exactly one workflow: security or malware.');
}
if (requestedWorkflow && !['security', 'malware'].includes(requestedWorkflow)) {
  throw new Error('--workflow must be security or malware.');
}

if (securityRequested) {
  aliasEnvironment('SECURITY_TRIAGE_', ['OCTOBUS_BASE_URL', 'OCTOBUS_CAPSET_ID', 'OCTOBUS_INSTANCE_ID', 'OCTOBUS_FULL_SERVICE', 'OCTOBUS_TOKEN', 'TRIAGE_STATE_DB_PATH', 'LLM_API_BASE', 'LLM_API_KEY', 'LLM_MODEL', 'LLM_TIMEOUT_MS']);
  await import('./security-cli.js');
} else {
  aliasEnvironment('MALWARE_TRIAGE_', ['OCTOBUS_BASE_URL', 'OCTOBUS_CAPSET_ID', 'OCTOBUS_INSTANCE_ID', 'OCTOBUS_AUTH_TOKEN', 'TRIAGE_STATE_DB_PATH', 'LLM_BASE_URL', 'LLM_MODEL', 'LLM_TIMEOUT_MS']);
  await import('./malware-cli.js');
}

function option(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function aliasEnvironment(prefix, names) {
  for (const name of names) {
    const scoped = `${prefix}${name}`;
    if (!process.env[name] && process.env[scoped]) process.env[name] = process.env[scoped];
  }
}
