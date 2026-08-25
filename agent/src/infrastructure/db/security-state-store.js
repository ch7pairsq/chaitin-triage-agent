/**
 * 基础设施层：安全告警工作流留痕存储（SQLite，规范 §5.2 infrastructure/db/）。
 *
 * 两张核心表：
 * - workflow_snapshots：追加式状态快照（trace_id + sequence 主键），
 *   每次状态迁移先落库再执行下一个副作用，支持完整回放；
 * - delivery_outbox：出站投递发件箱（幂等键唯一），失败按指数退避重试，
 *   超限转 manual，由 --recover-outbox 恢复，禁止静默丢失。
 * SQLite 刻意部署在 Agent 本地：无需引入额外服务即可获得可审计的
 * 持久留痕；生产环境必须把数据库目录挂载到持久卷。
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * 默认空实现：供聚焦单测或显式禁用持久化的调用方使用。
 * 生产 CLI 组合根始终装配 SqliteStateStore。
 */
export class NoopStateStore {
  save() {}

  getLatest() {
    return null;
  }

  list() {
    return [];
  }

  enqueueDelivery(entry) {
    return { ...entry, id: entry.idempotencyKey, status: "pending", attempts: 0 };
  }

  claimDueDeliveries() {
    return [];
  }

  markDeliveryDelivered() {}

  markDeliveryRetry() {}

  markDeliveryManual() {}

  close() {}
}

/**
 * Append-only workflow snapshot store.
 *
 * SQLite is intentionally local to the Agent deployment: it provides durable,
 * inspectable evidence without adding another service to the assessment stack.
 * Callers must mount the database directory on durable storage in production.
 */
export class SqliteStateStore {
  constructor({ databasePath }) {
    if (!databasePath) {
      throw new Error("databasePath is required for SqliteStateStore");
    }

    mkdirSync(path.dirname(databasePath), { recursive: true });
    this.database = new DatabaseSync(databasePath);
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS workflow_snapshots (
        trace_id TEXT NOT NULL,
        alert_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        state TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (trace_id, sequence)
      );
      CREATE INDEX IF NOT EXISTS idx_workflow_snapshots_alert_created
        ON workflow_snapshots(alert_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS delivery_outbox (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        trace_id TEXT NOT NULL,
        alert_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'delivered', 'manual')),
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        lease_until TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_delivery_outbox_due
        ON delivery_outbox(status, next_attempt_at);
    `);
    this.insert = this.database.prepare(`
      INSERT INTO workflow_snapshots
        (trace_id, alert_id, sequence, state, payload_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    this.selectLatest = this.database.prepare(`
      SELECT trace_id, alert_id, sequence, state, payload_json, created_at
      FROM workflow_snapshots
      WHERE trace_id = ?
      ORDER BY sequence DESC
      LIMIT 1
    `);
    this.selectAll = this.database.prepare(`
      SELECT trace_id, alert_id, sequence, state, payload_json, created_at
      FROM workflow_snapshots
      WHERE trace_id = ?
      ORDER BY sequence ASC
    `);
    this.insertDelivery = this.database.prepare(`
      INSERT INTO delivery_outbox
        (id, kind, trace_id, alert_id, idempotency_key, payload_json, status, attempts, next_attempt_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
      ON CONFLICT(idempotency_key) DO NOTHING
    `);
    this.selectDeliveryByKey = this.database.prepare(`
      SELECT * FROM delivery_outbox WHERE idempotency_key = ?
    `);
    this.selectDueDeliveries = this.database.prepare(`
      SELECT * FROM delivery_outbox
      WHERE (status = 'pending' AND next_attempt_at <= ?)
         OR (status = 'processing' AND lease_until <= ?)
      ORDER BY created_at ASC LIMIT ?
    `);
    this.claimDelivery = this.database.prepare(`
      UPDATE delivery_outbox
      SET status = 'processing', lease_until = ?, updated_at = ?
      WHERE id = ? AND (
        (status = 'pending' AND next_attempt_at <= ?)
        OR (status = 'processing' AND lease_until <= ?)
      )
    `);
    this.markDelivered = this.database.prepare(`
      UPDATE delivery_outbox
      SET status = 'delivered', lease_until = NULL, last_error = NULL, updated_at = ?
      WHERE id = ?
    `);
    this.markRetry = this.database.prepare(`
      UPDATE delivery_outbox
      SET status = 'pending', attempts = attempts + 1, next_attempt_at = ?, lease_until = NULL, last_error = ?, updated_at = ?
      WHERE id = ?
    `);
    this.markManual = this.database.prepare(`
      UPDATE delivery_outbox
      SET status = 'manual', lease_until = NULL, last_error = ?, updated_at = ?
      WHERE id = ?
    `);
  }

  save(snapshot) {
    const createdAt = new Date().toISOString();
    this.insert.run(
      snapshot.traceId,
      snapshot.alertId,
      snapshot.sequence,
      snapshot.state,
      JSON.stringify(snapshot.payload),
      createdAt
    );
    return { ...snapshot, createdAt };
  }

  getLatest(traceId) {
    const row = this.selectLatest.get(traceId);
    return row ? decodeRow(row) : null;
  }

  list(traceId) {
    return this.selectAll.all(traceId).map(decodeRow);
  }

  enqueueDelivery({ kind, traceId, alertId, idempotencyKey, payload }) {
    if (!kind || !traceId || !alertId || !idempotencyKey) throw new Error("delivery entry requires kind, traceId, alertId, and idempotencyKey");
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    this.insertDelivery.run(id, kind, traceId, alertId, idempotencyKey, JSON.stringify(payload ?? {}), now, now, now);
    return decodeDelivery(this.selectDeliveryByKey.get(idempotencyKey));
  }

  claimDueDeliveries({ limit = 20, leaseMs = 30_000, now = new Date() } = {}) {
    const nowIso = now.toISOString();
    const leaseUntil = new Date(now.getTime() + leaseMs).toISOString();
    const rows = this.selectDueDeliveries.all(nowIso, nowIso, Math.max(1, Math.min(limit, 100)));
    const claimed = [];
    for (const row of rows) {
      const changed = this.claimDelivery.run(leaseUntil, nowIso, row.id, nowIso, nowIso);
      if (changed.changes === 1) claimed.push(decodeDelivery({ ...row, status: "processing", lease_until: leaseUntil, updated_at: nowIso }));
    }
    return claimed;
  }

  markDeliveryDelivered(id) {
    this.markDelivered.run(new Date().toISOString(), id);
  }

  markDeliveryRetry(id, { error, delayMs = 30_000 } = {}) {
    const nextAttemptAt = new Date(Date.now() + Math.max(1000, Math.min(delayMs, 15 * 60_000))).toISOString();
    const safeError = String(error ?? "delivery failed").slice(0, 512);
    this.markRetry.run(nextAttemptAt, safeError, new Date().toISOString(), id);
  }

  markDeliveryManual(id, { error } = {}) {
    this.markManual.run(String(error ?? "manual recovery required").slice(0, 512), new Date().toISOString(), id);
  }

  close() {
    this.database.close();
  }
}

function decodeRow(row) {
  return {
    traceId: row.trace_id,
    alertId: row.alert_id,
    sequence: row.sequence,
    state: row.state,
    payload: JSON.parse(row.payload_json),
    createdAt: row.created_at
  };
}

function decodeDelivery(row) {
  return {
    id: row.id,
    kind: row.kind,
    traceId: row.trace_id,
    alertId: row.alert_id,
    idempotencyKey: row.idempotency_key,
    payload: JSON.parse(row.payload_json),
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    leaseUntil: row.lease_until,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function stateStoreFromEnvironment(environment = process.env) {
  const databasePath = environment.TRIAGE_STATE_DB_PATH
    ? path.resolve(environment.TRIAGE_STATE_DB_PATH)
    : path.resolve(process.cwd(), "runtime", "triage-state.db");
  return new SqliteStateStore({ databasePath });
}
