/**
 * 基础设施层：SHA-256 补全助手（仅哈希的 VirusTotal 查询队列）。
 *
 * 定位：为私有样本登记册补全 SHA-256 的「人工核对」辅助工具：
 * - 队列只存 MD5 / SHA-256 / 状态，刻意不含样本路径、样本字节、API key，
 *   也没有任何自动上传能力（规范红线 2）；
 * - 查询页由操作员在隔离环境人工打开并核对，工具只负责排队与回填；
 * - 逐条处理、可断点续跑（状态文件 0600 权限本地保存）；
 * - 模拟值必须显式导出到单独登记册并带 simulation_only 标记，禁止混入真实数据。
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const MD5 = /^[a-fA-F0-9]{32}$/;
const SHA256 = /^[a-fA-F0-9]{64}$/;

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function readJsonl(filePath) {
  return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`样本登记册第 ${index + 1} 行不是有效 JSON`);
    }
  });
}

/**
 * 由登记册创建本地、可断点续跑的「仅哈希」VT GUI 查询队列。
 * 队列刻意不含样本路径、样本字节、API key，也没有任何自动上传能力。
 */
export function createQueryState(registryPath, statePath, now = new Date().toISOString()) {
  const records = {};
  for (const record of readJsonl(registryPath)) {
    const sampleRef = text(record.sample_ref);
    const md5 = text(record.md5).toLowerCase();
    if (!sampleRef) throw new Error('样本登记册缺少 sample_ref');
    if (!MD5.test(md5)) throw new Error(`样本 ${sampleRef} 缺少有效 MD5，无法创建查询队列`);
    if (records[sampleRef]) throw new Error(`样本登记册 sample_ref 重复：${sampleRef}`);
    records[sampleRef] = { md5, status: 'pending', sha256: '', source: '', updatedAt: now };
  }
  const state = { version: 1, createdAt: now, updatedAt: now, records };
  writeState(statePath, state);
  return state;
}

export function readState(statePath) {
  let state;
  try {
    state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch {
    throw new Error(`无法读取查询状态文件：${statePath}`);
  }
  if (state?.version !== 1 || !state.records || typeof state.records !== 'object') {
    throw new Error('查询状态文件格式无效');
  }
  return state;
}

export function writeState(statePath, state) {
  fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

export function nextPendingRecord(state) {
  const entry = Object.entries(state.records).find(([, record]) => record.status === 'pending');
  if (!entry) return null;
  const [sampleRef, record] = entry;
  if (!MD5.test(text(record.md5))) throw new Error(`查询状态中的样本 ${sampleRef} 含有无效 MD5`);
  return {
    sampleRef,
    md5: record.md5.toLowerCase(),
    url: `https://www.virustotal.com/gui/file/${record.md5.toLowerCase()}/details`
  };
}

/** Record a SHA-256 copied by the operator from the VT GUI. */
export function recordSha256(state, sampleRef, sha256, now = new Date().toISOString()) {
  const record = state.records[sampleRef];
  if (!record) throw new Error(`查询状态中不存在 sample_ref：${sampleRef}`);
  const normalized = text(sha256).toLowerCase();
  if (!SHA256.test(normalized)) throw new Error('SHA-256 必须是 64 位十六进制值');
  record.sha256 = normalized;
  record.status = 'verified';
  record.source = 'virustotal_gui_operator_verified';
  record.updatedAt = now;
  state.updatedAt = now;
  return state;
}

/** Extract the value shown in the VirusTotal DETAILS basic-properties block. */
export function extractSha256FromDetails(pageText) {
  const match = String(pageText || '').match(/SHA-?256\s*[:\n\r ]+([a-fA-F0-9]{64})/i);
  return match ? match[1].toLowerCase() : null;
}

export function applyVtDetailsResult(state, sampleRef, result, now = new Date().toISOString()) {
  const record = state.records[sampleRef];
  if (!record) throw new Error(`查询状态中不存在 sample_ref：${sampleRef}`);
  const sha256 = text(result?.sha256).toLowerCase();
  if (!SHA256.test(sha256)) throw new Error('VT DETAILS 页面未返回有效 SHA-256');
  record.sha256 = sha256;
  record.status = 'verified';
  record.source = 'virustotal_details_browser';
  record.screenshot = text(result?.screenshot);
  record.updatedAt = now;
  delete record.lastError;
  state.updatedAt = now;
  return state;
}

export function markLookupFailure(state, sampleRef, error, now = new Date().toISOString()) {
  const record = state.records[sampleRef];
  if (!record) throw new Error(`查询状态中不存在 sample_ref：${sampleRef}`);
  record.lastError = text(error).slice(0, 500);
  record.updatedAt = now;
  state.updatedAt = now;
  return state;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function validatePort(port) {
  const parsed = Number(port);
  if (!Number.isInteger(parsed) || parsed < 1024 || parsed > 65535) throw new Error('Chrome 调试端口必须是 1024-65535 的整数');
  return parsed;
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`Chrome 调试接口返回 HTTP ${response.status}`);
  return response.json();
}

function launchChromeDebug(port, profileDir) {
  const chromePath = process.env.VT_CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!fs.existsSync(chromePath)) throw new Error(`未找到 Chrome；请设置 VT_CHROME_PATH。当前路径：${chromePath}`);
  fs.mkdirSync(profileDir, { recursive: true, mode: 0o700 });
  const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
  const argumentsList = [
    `--remote-debugging-port=${port}`,
    '--remote-allow-origins=http://localhost',
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank'
  ].map(quote).join(', ');
  const launched = spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command',
    `Start-Process -FilePath ${quote(chromePath)} -ArgumentList ${argumentsList}`
  ], { encoding: 'utf8' });
  if (launched.error || launched.status !== 0) {
    throw new Error(`无法启动 Chrome 调试实例：${launched.error?.message || launched.stderr || `退出码 ${launched.status}`}`);
  }
}

async function ensureChromeDebug(port, profileDir) {
  const endpoint = `http://127.0.0.1:${port}/json/version`;
  try {
    return await jsonRequest(endpoint);
  } catch {
    launchChromeDebug(port, profileDir);
  }
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await delay(500);
    try {
      return await jsonRequest(endpoint);
    } catch {
      // Chrome can take a few seconds to create its debug endpoint.
    }
  }
  throw new Error('Chrome 调试实例未在预期时间内启动');
}

function connectCdp(webSocketUrl) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(webSocketUrl);
    const pending = new Map();
    let sequence = 0;
    const timeout = setTimeout(() => reject(new Error('Chrome DevTools 连接超时')), 10000);
    socket.addEventListener('open', () => {
      clearTimeout(timeout);
      resolve({
        send(method, params = {}) {
          return new Promise((resolveCommand, rejectCommand) => {
            const id = ++sequence;
            pending.set(id, { resolve: resolveCommand, reject: rejectCommand });
            socket.send(JSON.stringify({ id, method, params }));
          });
        },
        close() { socket.close(); }
      });
    });
    socket.addEventListener('message', ({ data }) => {
      let message;
      try { message = JSON.parse(data); } catch { return; }
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      if (message.error) request.reject(new Error(message.error.message || 'Chrome DevTools 调用失败'));
      else request.resolve(message.result);
    });
    socket.addEventListener('error', () => reject(new Error('Chrome DevTools 连接失败')));
    socket.addEventListener('close', () => {
      for (const request of pending.values()) request.reject(new Error('Chrome DevTools 连接已关闭'));
      pending.clear();
    });
  });
}

async function readDetailsPage(port, sampleRef, md5, screenshotDir, timeoutMs) {
  const detailsUrl = `https://www.virustotal.com/gui/file/${md5}/details`;
  const target = await jsonRequest(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(detailsUrl)}`, { method: 'PUT' });
  const cdp = await connectCdp(target.webSocketDebuggerUrl);
  try {
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    const captureScreenshot = async (suffix = '') => {
      fs.mkdirSync(screenshotDir, { recursive: true, mode: 0o700 });
      const image = await cdp.send('Page.captureScreenshot', { format: 'png', fromSurface: true });
      const screenshot = path.join(screenshotDir, `${sampleRef}${suffix}.png`);
      fs.writeFileSync(screenshot, Buffer.from(image.data, 'base64'), { mode: 0o600 });
      return screenshot;
    };
    const detailsTabExpression = `(() => {
        const candidates = [];
        const visit = (root) => {
          for (const element of root.querySelectorAll?.('*') || []) {
            candidates.push(element);
            if (element.shadowRoot) visit(element.shadowRoot);
          }
        };
        visit(document);
        const label = candidates.find((element) => element.textContent?.trim().toUpperCase() === 'DETAILS');
        let clickable = label;
        while (clickable && !clickable.matches?.('a, button, [role="tab"]')) {
          clickable = clickable.parentElement || clickable.getRootNode?.().host || null;
        }
        clickable ||= label;
        if (!clickable) return false;
        const rect = clickable.getBoundingClientRect();
        if (!rect.width || !rect.height) return false;
        return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
      })()`;
    const tabDeadline = Date.now() + timeoutMs;
    let detailsTab;
    while (Date.now() < tabDeadline) {
      detailsTab = await cdp.send('Runtime.evaluate', {
        expression: detailsTabExpression,
        returnByValue: true,
        userGesture: true
      });
      if (detailsTab.result?.value?.x && detailsTab.result?.value?.y) break;
      await delay(500);
    }
    if (!detailsTab?.result?.value?.x || !detailsTab?.result?.value?.y) {
      const screenshot = await captureScreenshot('.failed');
      throw new Error(`VT 页面在 ${Math.round(timeoutMs / 1000)} 秒内未加载 DETAILS 标签；截图=${screenshot}`);
    }
    await cdp.send('Input.dispatchMouseEvent', {
      type: 'mousePressed', x: detailsTab.result.value.x, y: detailsTab.result.value.y, button: 'left', clickCount: 1
    });
    await cdp.send('Input.dispatchMouseEvent', {
      type: 'mouseReleased', x: detailsTab.result.value.x, y: detailsTab.result.value.y, button: 'left', clickCount: 1
    });
    await delay(1000);
    const started = Date.now();
    let pageText = '';
    while (Date.now() - started < timeoutMs) {
      const evaluation = await cdp.send('Runtime.evaluate', {
        expression: `(() => {
          const text = [];
          const visit = (node) => {
            if (node.nodeType === Node.TEXT_NODE) text.push(node.nodeValue);
            if (node.shadowRoot) visit(node.shadowRoot);
            for (const child of node.childNodes || []) visit(child);
          };
          visit(document);
          return text.join('\\n');
        })()`,
        returnByValue: true
      });
      pageText = evaluation.result?.value || '';
      const sha256 = extractSha256FromDetails(pageText);
      if (sha256) {
        const screenshot = await captureScreenshot();
        return { sha256, screenshot };
      }
      await delay(1000);
    }
    const title = await cdp.send('Runtime.evaluate', { expression: 'document.title', returnByValue: true });
    const screenshot = await captureScreenshot('.failed');
    const shortText = pageText.replace(/\s+/g, ' ').slice(0, 180);
    throw new Error(`DETAILS 页面在 ${Math.round(timeoutMs / 1000)} 秒内未显示 SHA-256；标题=${title.result?.value || '空'}；截图=${screenshot}${shortText ? `；页面=${shortText}` : ''}`);
  } finally {
    cdp.close();
    await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`, { method: 'GET' }).catch(() => undefined);
  }
}

/**
 * Look up a bounded number of pending records in a dedicated local Chrome
 * profile. This makes only VT GUI GET requests for MD5 values, sequentially.
 */
export async function fetchPendingVtDetails(state, options = {}) {
  const port = validatePort(options.port ?? 9223);
  const limit = Number(options.limit ?? 1);
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new Error('每批查询数量必须是 1-20 的整数');
  const profileDir = options.profileDir || path.join(path.dirname(options.statePath || '.'), '.vt-chrome-profile');
  const screenshotDir = options.screenshotDir || path.join(path.dirname(options.statePath || '.'), 'vt-details-screenshots');
  const timeoutMs = Number(options.timeoutMs ?? 30000);
  const delayMs = Number(options.delayMs ?? 3000);
  const skipOnMiss = options.skipOnMiss ?? true;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 5000 || timeoutMs > 120000) throw new Error('页面等待时间必须为 5-120 秒');
  if (!Number.isFinite(delayMs) || delayMs < 1000 || delayMs > 60000) throw new Error('查询间隔必须为 1-60 秒');

  await ensureChromeDebug(port, profileDir);
  const completed = [];
  const failed = [];
  for (let index = 0; index < limit; index += 1) {
    const next = nextPendingRecord(state);
    if (!next) break;
    try {
      const result = await readDetailsPage(port, next.sampleRef, next.md5, screenshotDir, timeoutMs);
      applyVtDetailsResult(state, next.sampleRef, result);
      completed.push({ sampleRef: next.sampleRef, screenshot: result.screenshot });
    } catch (error) {
      if (skipOnMiss) {
        skipRecord(state, next.sampleRef, `VT DETAILS 未返回 SHA-256：${error.message}`);
      } else {
        markLookupFailure(state, next.sampleRef, error.message);
      }
      failed.push({ sampleRef: next.sampleRef, skipped: skipOnMiss, error: error.message });
    }
    if (index + 1 < limit) await delay(delayMs);
  }
  return { completed, failed, summary: summarizeState(state) };
}

export function skipRecord(state, sampleRef, reason, now = new Date().toISOString()) {
  const record = state.records[sampleRef];
  if (!record) throw new Error(`查询状态中不存在 sample_ref：${sampleRef}`);
  record.status = 'skipped';
  record.source = text(reason) || 'operator_skipped';
  record.updatedAt = now;
  state.updatedAt = now;
  return state;
}

export function summarizeState(state) {
  return Object.values(state.records).reduce((summary, record) => {
    summary.total += 1;
    summary[record.status] = (summary[record.status] || 0) + 1;
    return summary;
  }, { total: 0, pending: 0, verified: 0, skipped: 0 });
}

/**
 * Produce a new registry after human verification. The original registry is
 * never overwritten, so every external hash result remains reviewable.
 */
export function exportEnrichedRegistry(registryPath, state, outputPath) {
  const exportedAt = new Date().toISOString();
  const enriched = readJsonl(registryPath).map((record) => {
    const result = state.records[text(record.sample_ref)];
    if (result?.status !== 'verified') return record;
    return {
      ...record,
      sha256: result.sha256,
      sha256_status: '已由自动流程从 VirusTotal DETAILS 提取（当前 MVP 以 VT 为准）',
      sha256_source: result.source,
      sha256_verified_at: result.updatedAt,
      sha256_exported_at: exportedAt
    };
  });
  fs.writeFileSync(outputPath, `${enriched.map((record) => JSON.stringify(record)).join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  return enriched.length;
}

/**
 * Create a clearly isolated demo dataset when interactive VT browsing is
 * blocked. Synthetic hashes are deterministic only for repeatable demos;
 * they are never represented as file hashes and must not drive detection,
 * attribution, or YARA approval.
 */
export function exportSimulationRegistry(registryPath, state, outputPath, screenshotDir) {
  const records = readJsonl(registryPath);
  const summary = { total: records.length, verifiedFromVt: 0, simulatedFromScreenshot: 0, simulatedFromQueue: 0 };
  const generatedAt = new Date().toISOString();
  const simulated = records.map((record) => {
    const sampleRef = text(record.sample_ref);
    const stateRecord = state.records[sampleRef];
    if (stateRecord?.status === 'verified' && SHA256.test(text(stateRecord.sha256))) {
      summary.verifiedFromVt += 1;
      return {
        ...record,
        sha256: stateRecord.sha256,
        sha256_status: '真实：由自动流程从 VirusTotal DETAILS 提取',
        sha256_source: stateRecord.source,
        sha256_verified_at: stateRecord.updatedAt,
        simulation_only: false
      };
    }
    const screenshotExists = Boolean(screenshotDir && fs.existsSync(path.join(screenshotDir, `${sampleRef}.png`)));
    const source = screenshotExists ? 'simulation_from_vt_details_screenshot' : 'simulation_from_queue_metadata';
    if (screenshotExists) summary.simulatedFromScreenshot += 1;
    else summary.simulatedFromQueue += 1;
    return {
      ...record,
      sha256: createHash('sha256').update(`DEMO_ONLY|${sampleRef}|${text(record.md5).toLowerCase()}`).digest('hex'),
      sha256_status: '模拟值：仅用于 Agent 流程演示，不是样本真实 SHA-256',
      sha256_source: source,
      simulated_at: generatedAt,
      simulation_only: true,
      evidence_level: 'simulation_only',
      rule_eligibility: '禁止生成、验证或批准 YARA；不得用于真实检测或归因'
    };
  });
  fs.writeFileSync(outputPath, `${simulated.map((record) => JSON.stringify(record)).join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  return summary;
}
