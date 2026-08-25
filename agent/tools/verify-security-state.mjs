/**
 * 运维工具：安全工作流留痕校验。
 *
 * 用途：按 trace_id 回读 SQLite 状态快照，验证业务闭环「留痕」阶段完整性。
 * 刻意只输出快照数量与终态（不输出 payload 内容），避免把状态校验工具
 * 变成 IOC / 告警上下文 / 敏感数据的导出通道。
 */
import { stateStoreFromEnvironment } from '../src/infrastructure/db/security-state-store.js';

const traceId = process.argv[2];
if (!/^[a-f0-9-]{36}$/i.test(traceId ?? '')) {
  console.error('用法：node tools/verify-security-state.mjs <UUID trace_id>');
  process.exitCode = 2;
} else {
  const store = stateStoreFromEnvironment();
  try {
    const snapshots = store.list(traceId);
    const latest = snapshots.at(-1);
    // 刻意省略 payload 取值：状态留痕证明不应变成 IOC、告警上下文或密钥的导出命令。
    console.log(JSON.stringify(latest ? {
      traceId, snapshotCount: snapshots.length, latestState: latest.state, latestSequence: latest.sequence
    } : { traceId, snapshotCount: 0, latestState: null }, null, 2));
    if (!latest) process.exitCode = 1;
  } finally {
    store.close();
  }
}
