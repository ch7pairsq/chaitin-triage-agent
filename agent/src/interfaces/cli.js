#!/usr/bin/env node
/**
 * 接口层：统一分发入口（规范 §5.2 interfaces/）。
 *
 * 演示范围：本部署单元只启用安全告警降噪工作流（security）。
 * - 工作流选择只来自显式 CLI flag（--workflow / 专属参数），不受 prompt
 *   文本影响——prompt 永远不能选择权限（规范 §6 权限边界）；
 * - malware（恶意样本研判）工作流代码保留但未在演示部署中启用：
 *   其专属入参与 --workflow malware 一律显式拒绝（fail closed），不猜测回退；
 * - 按所选工作流做域前缀环境变量别名（SECURITY_TRIAGE_*）。
 */
const args = process.argv.slice(2);
const requestedWorkflow = option('--workflow');
const malwareArguments = ['--sample-id', '--sample-ref', '--sha256', '--session-id', '--message', '--event-file', '--self-check'];
const malwareRequested = args.some((value) => malwareArguments.includes(value)) || requestedWorkflow === 'malware';

if (malwareRequested) {
  throw new Error('Malware workflow is not enabled in this demo: only the security alert triage workflow is registered.');
}
if (requestedWorkflow && requestedWorkflow !== 'security') {
  throw new Error('--workflow must be security (malware is not enabled in this demo).');
}

// 配对映射：域前缀变量 → 无前缀运行时变量。状态库源名是
// SECURITY_TRIAGE_STATE_DB_PATH（无双重 TRIAGE），目标名是 TRIAGE_STATE_DB_PATH，
// 两者无法用统一前缀拼接表达，因此使用显式 [源名, 目标名] 配对。
//start by zhangyuqiao，保留security 单入口
aliasEnvironment('SECURITY_TRIAGE_', [
  ['OCTOBUS_BASE_URL', 'OCTOBUS_BASE_URL'],
  ['OCTOBUS_CAPSET_ID', 'OCTOBUS_CAPSET_ID'],
  ['OCTOBUS_INSTANCE_ID', 'OCTOBUS_INSTANCE_ID'],
  ['OCTOBUS_FULL_SERVICE', 'OCTOBUS_FULL_SERVICE'],
  ['OCTOBUS_TOKEN', 'OCTOBUS_TOKEN'],
  ['STATE_DB_PATH', 'TRIAGE_STATE_DB_PATH'],
  ['LLM_API_BASE', 'LLM_API_BASE'],
  ['LLM_API_KEY', 'LLM_API_KEY'],
  ['LLM_MODEL', 'LLM_MODEL'],
  ['LLM_TIMEOUT_MS', 'LLM_TIMEOUT_MS']
]);
await import('./security-cli.js');

//end

function option(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function aliasEnvironment(prefix, pairs) {
  for (const [suffix, plainName] of pairs) {
    const scoped = `${prefix}${suffix}`;
    if (!process.env[plainName] && process.env[scoped]) process.env[plainName] = process.env[scoped];
  }
}
