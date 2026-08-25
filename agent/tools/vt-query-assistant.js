#!/usr/bin/env node
/**
 * 运维工具：SHA-256 补全助手（VirusTotal GUI 查询队列）。
 *
 * 用途：操作员在隔离环境中按 MD5 逐条查询 VT DETAILS 页，人工核对后回填
 * SHA-256 到私有样本登记册；导出结果只含哈希，绝不包含样本路径 / 字节 / 凭据。
 * 子命令：init / next / fetch / record / skip / status / export / simulate。
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import {
  createQueryState,
  exportEnrichedRegistry,
  exportSimulationRegistry,
  fetchPendingVtDetails,
  nextPendingRecord,
  readState,
  recordSha256,
  skipRecord,
  summarizeState,
  writeState
} from '../src/infrastructure/vt/vt-query-assistant.js';

/** 解析 --key value 形式的命令行参数（无值时记为 true）。 */
function args(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) continue;
    const key = item.slice(2);
    values[key] = argv[index + 1]?.startsWith('--') ? true : (argv[index + 1] ?? true);
    if (values[key] !== true) index += 1;
  }
  return values;
}

function requireArg(values, key) {
  if (!values[key] || values[key] === true) throw new Error(`缺少 --${key}`);
  return values[key];
}

/** 用 Windows 交互式 shell 启动 Chrome 打开 VT DETAILS 页（绕开 Node 直启 GUI 进程的限制）。 */
function openInChrome(url) {
  const chromePath = process.env.VT_CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!existsSync(chromePath)) throw new Error(`未找到 Chrome；请设置 VT_CHROME_PATH。当前路径：${chromePath}`);
  // Start-Process 走交互式 shell；两个入参均为本地固定路径或 MD5 查询 URL，已做引号转义。
  const quote = (value) => `'${value.replaceAll("'", "''")}'`;
  const result = spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command',
    `Start-Process -FilePath ${quote(chromePath)} -ArgumentList ${quote(url)}`
  ], { encoding: 'utf8' });
  if (result.error || result.status !== 0) {
    throw new Error(`无法启动 Chrome：${result.error?.message || result.stderr || `退出码 ${result.status}`}`);
  }
}

function printNext(state, shouldOpen) {
  const record = nextPendingRecord(state);
  if (!record) {
    console.log('队列已无待查询项。');
    return;
  }
  if (shouldOpen) openInChrome(record.url);
  console.log(JSON.stringify(record, null, 2));
}

function usage() {
  console.log(`用法：
  node tools/vt-query-assistant.js init --registry <私有登记册.jsonl> --state <本地状态.json>
  node tools/vt-query-assistant.js next --state <本地状态.json> [--open]
  node tools/vt-query-assistant.js fetch --state <本地状态.json> [--limit 1] [--delay-ms 3000] [--timeout-ms 30000] [--on-miss skip|retry] [--screenshot-dir <目录>]
  node tools/vt-query-assistant.js record --state <本地状态.json> --sample-ref MAL-0001 --sha256 <64位值>
  node tools/vt-query-assistant.js skip --state <本地状态.json> --sample-ref MAL-0001 [--reason <原因>]
  node tools/vt-query-assistant.js status --state <本地状态.json>
  node tools/vt-query-assistant.js export --registry <私有登记册.jsonl> --state <本地状态.json> --out <新登记册.jsonl>
  node tools/vt-query-assistant.js simulate --registry <私有登记册.jsonl> --state <本地状态.json> --out <模拟登记册.jsonl> [--screenshot-dir <目录>]`);
}

try {
  const [command] = process.argv.slice(2);
  const values = args(process.argv.slice(3));
  if (command === 'init') {
    const state = createQueryState(requireArg(values, 'registry'), requireArg(values, 'state'));
    console.log(JSON.stringify(summarizeState(state), null, 2));
  } else if (command === 'next') {
    printNext(readState(requireArg(values, 'state')), values.open === true);
  } else if (command === 'fetch') {
    const statePath = requireArg(values, 'state');
    const state = readState(statePath);
    const result = await fetchPendingVtDetails(state, {
      statePath,
      limit: values.limit,
      delayMs: values['delay-ms'],
      timeoutMs: values['timeout-ms'],
      skipOnMiss: values['on-miss'] !== 'retry',
      screenshotDir: values['screenshot-dir']
    });
    writeState(statePath, state);
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'record') {
    const statePath = requireArg(values, 'state');
    const state = recordSha256(readState(statePath), requireArg(values, 'sample-ref'), requireArg(values, 'sha256'));
    writeState(statePath, state);
    console.log(JSON.stringify(summarizeState(state), null, 2));
  } else if (command === 'skip') {
    const statePath = requireArg(values, 'state');
    const state = skipRecord(readState(statePath), requireArg(values, 'sample-ref'), values.reason);
    writeState(statePath, state);
    console.log(JSON.stringify(summarizeState(state), null, 2));
  } else if (command === 'status') {
    console.log(JSON.stringify(summarizeState(readState(requireArg(values, 'state'))), null, 2));
  } else if (command === 'export') {
    const count = exportEnrichedRegistry(requireArg(values, 'registry'), readState(requireArg(values, 'state')), requireArg(values, 'out'));
    console.log(JSON.stringify({ exportedRecords: count, output: path.resolve(values.out) }, null, 2));
  } else if (command === 'simulate') {
    const output = requireArg(values, 'out');
    const summary = exportSimulationRegistry(requireArg(values, 'registry'), readState(requireArg(values, 'state')), output, values['screenshot-dir']);
    console.log(JSON.stringify({ ...summary, output: path.resolve(output), simulationOnly: true }, null, 2));
  } else {
    usage();
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`错误：${error.message}`);
  process.exitCode = 1;
}
