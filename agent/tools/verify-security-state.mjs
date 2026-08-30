#!/usr/bin/env node
/**
 * verify-security-state.mjs
 * README §7.4 步骤 2 提到的 traceId → SQLite 快照校验工具。
 *
 * 零依赖：Node 内置 node:sqlite / node:fs / node:path / node:process
 * 参数：process.argv[2] = traceId（必填）
 * 环境变量：
 *   SECURITY_TRIAGE_STATE_DB_PATH  默认值：../runtime/security-triage-state.db
 *   SECURITY_TRIAGE_AUDIT_LOG_PATH 默认值：../runtime/audit.log
 *
 * 输出 stdout JSON：
 * { traceId, snapshotCount, latestState, latestSequence,
 *   snapshots:[{sequence, state, createdAt, stateKeyFields}],
 *   outboxCount: {pending, manual, done, total},
 *   auditMatches: {workflowCompleted: bool, knowledgeHit: bool, matchedTraceRows: int} }
 */
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

const traceId = process.argv[2];
if (!traceId) {
  console.error("Usage: node tools/verify-security-state.mjs <traceId>");
  process.exit(2);
}

const dbPath =
  process.env.SECURITY_TRIAGE_STATE_DB_PATH ||
  path.resolve(path.dirname(process.argv[1]), "..", "runtime", "security-triage-state.db");
const auditPath =
  process.env.SECURITY_TRIAGE_AUDIT_LOG_PATH ||
  path.resolve(path.dirname(process.argv[1]), "..", "runtime", "audit.log");

if (!fs.existsSync(dbPath)) {
  console.error(
    JSON.stringify({
      traceId,
      error: "STATE_DB_NOT_FOUND",
      dbPath,
      hint: "Set SECURITY_TRIAGE_STATE_DB_PATH or run cli.js first to create it.",
    })
  );
  process.exit(1);
}

const ALLOWED_KEY_FIELDS = [
  "alertId",
  "status",
  "action",
  "severity",
  "decision",
  "matchedRuleId",
  "falsePositiveScore",
  "narrativeSource",
  "evidenceRefs",
  "knowledgeAblated",
  "recorded",
  "reviewTaskId",
];

function extractKeyFields(payloadStr) {
  try {
    if (!payloadStr) return {};
    const p = typeof payloadStr === "string" ? JSON.parse(payloadStr) : payloadStr;
    const out = {};
    for (const k of ALLOWED_KEY_FIELDS) {
      if (p[k] === undefined) continue;
      const v = p[k];
      if (Array.isArray(v)) {
        out[k + "Count"] = v.length;
      } else if (typeof v === "object" && v !== null) {
        out[k] = Object.fromEntries(
          Object.entries(v).filter(([kk]) =>
            ["status", "action", "evidenceRefs", "matchedCount", "ablated"].includes(kk)
          )
        );
      } else {
        out[k] = v;
      }
    }
    return out;
  } catch (e) {
    return { _parseError: e.message };
  }
}

try {
  const db = new DatabaseSync(dbPath);
  // Node < 23.4 has no DatabaseSync.pragma (sandbox guest images run Node 22); WAL is optional for read-only verification.
  if (typeof db.pragma === "function") db.pragma("journal_mode = WAL");

  // --- workflow_snapshots ---
  const snapRows = db
    .prepare(
      `SELECT sequence, state, payload_json, created_at
       FROM workflow_snapshots
       WHERE trace_id = ?
       ORDER BY sequence ASC`
    )
    .all(traceId);

  const snapshots = snapRows.map((r) => ({
    sequence: r.sequence,
    state: r.state,
    createdAt: r.created_at,
    stateKeyFields: extractKeyFields(r.payload_json),
  }));

  const latest = snapRows[snapshots.length - 1];

  // --- delivery_outbox ---
  let outboxCount = { pending: 0, manual: 0, done: 0, total: 0 };
  try {
    const o = db
      .prepare(
        `SELECT status, COUNT(*) AS c FROM delivery_outbox WHERE trace_id = ? GROUP BY status`
      )
      .all(traceId);
    for (const row of o) {
      const s = String(row.status || "").toLowerCase();
      if (s in outboxCount) outboxCount[s] = Number(row.c) || 0;
    }
    outboxCount.total = Object.values(outboxCount).reduce((a, b) => a + b, 0) - outboxCount.total; // dedup
    outboxCount.total = outboxCount.pending + outboxCount.manual + outboxCount.done;
  } catch (e) {
    outboxCount = { pending: 0, manual: 0, done: 0, total: 0, _error: e.message };
  }

  db.close();

  // --- audit.log 双事件核验 ---
  let auditMatches = { workflowCompleted: false, knowledgeHit: false, matchedTraceRows: 0 };
  if (fs.existsSync(auditPath)) {
    const lines = fs.readFileSync(auditPath, "utf8").split(/\r?\n/);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      if (line.indexOf(traceId) === -1) continue;
      auditMatches.matchedTraceRows += 1;
      try {
        const ev = JSON.parse(line);
        if (ev.event === "workflow.completed") auditMatches.workflowCompleted = true;
        if (ev.event === "KNOWLEDGE_HIT") auditMatches.knowledgeHit = true;
      } catch (_) {}
    }
  }

  const result = {
    traceId,
    dbPath,
    snapshotCount: snapshots.length,
    latestState: latest ? latest.state : null,
    latestSequence: latest ? latest.sequence : null,
    snapshots,
    outboxCount,
    auditMatches,
  };
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(0);
} catch (e) {
  console.error(
    JSON.stringify({ traceId, error: e.code || "STATE_DB_ERROR", message: e.message })
  );
  process.exit(1);
}
