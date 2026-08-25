import fs from 'node:fs';

const SHA256 = /^[a-fA-F0-9]{64}$/;

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

/** 由登记册元数据推导受支持的报告画像；无法识别时返回 null（调用方拒绝）。 */
function profileFor(record) {
  if (['android-apk', 'windows-pe', 'linux-elf'].includes(record.analysis_profile)) return record.analysis_profile;
  const platform = text(record.platform).toLowerCase();
  const fileType = text(record.file_type).toLowerCase();
  if (platform === 'android' && fileType === 'apk') return 'android-apk';
  if (platform === 'windows' && ['exe', 'dll'].includes(fileType)) return 'windows-pe';
  if (platform === 'linux' && fileType === 'elf') return 'linux-elf';
  return null;
}

/**
 * Resolve a local sample reference without opening or transferring the original
 * artifact. The registry contains identifiers only and is intentionally kept
 * outside this Git repository.
 */
export function loadSampleRegistryJsonl(filePath) {
  const records = new Map();
  for (const [index, line] of fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).entries()) {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      throw new Error(`样本登记册第 ${index + 1} 行不是有效 JSON`);
    }
    const sampleRef = text(record.sample_ref);
    if (!sampleRef) throw new Error(`样本登记册第 ${index + 1} 行缺少 sample_ref`);
    if (records.has(sampleRef)) throw new Error(`样本登记册 sample_ref 重复：${sampleRef}`);
    records.set(sampleRef, record);
  }
  return records;
}

/**
 * 解析样本引用为最小化研判请求（sampleId + sha256 + profile）。
 * 任一校验失败即抛错（fail closed）：哈希缺失 / 模拟未声明 / 画像不支持。
 */
export function resolveSampleReference(records, sampleRef, { allowSimulation = false } = {}) {
  const record = records.get(sampleRef);
  if (!record) throw new Error(`样本登记册中不存在 sample_ref：${sampleRef}`);
  const sha256 = text(record.sha256);
  if (!SHA256.test(sha256)) {
    throw new Error(`样本 ${sampleRef} 尚未补全有效 SHA-256；请先在隔离样本库本地计算，或按审批流程回填哈希查询结果`);
  }
  const simulationOnly = record.simulation_only === true;
  if (simulationOnly && !allowSimulation) {
    throw new Error(`样本 ${sampleRef} 使用模拟 SHA-256；演示时必须显式传入 --demo-simulation，禁止作为真实研判输入`);
  }
  const profile = profileFor(record);
  if (!profile) {
    throw new Error(`样本 ${sampleRef} 的平台/文件类型暂不支持自动研判；需先补充 windows-pe、linux-elf 或 android-apk 报告类型`);
  }
  const resolved = { sampleId: sampleRef, sampleRef, sha256: sha256.toLowerCase(), profile };
  if (simulationOnly) resolved.simulationOnly = true;
  return resolved;
}
