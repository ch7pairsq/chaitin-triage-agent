import test from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import { SecurityOpsStore } from "../src/store.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.resolve(TEST_DIR, "../migrations");

function tempDirectory() {
  return mkdtempSync(path.join(os.tmpdir(), "security-ops-migrations-"));
}

function inspectSchema(databasePath) {
  const database = new DatabaseSync(databasePath);
  try {
    return {
      versions: database.prepare("SELECT version FROM schema_migrations ORDER BY version").all().map((row) => Number(row.version)),
      tables: database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name),
      runColumns: database.prepare("PRAGMA table_info(triage_runs)").all().map((row) => row.name),
      policyColumns: database.prepare("PRAGMA table_info(policy_decisions)").all().map((row) => row.name),
      resultColumns: database.prepare("PRAGMA table_info(triage_results)").all().map((row) => row.name),
      triggerColumns: database.prepare("PRAGMA table_info(trigger_outbox)").all().map((row) => row.name)
    };
  } finally {
    database.close();
  }
}

test("fresh and version-one databases reach the same ordered schema", () => {
  const directory = tempDirectory();
  const freshPath = path.join(directory, "fresh.db");
  const upgradedPath = path.join(directory, "upgraded.db");
  try {
    const fresh = new SecurityOpsStore({ databasePath: freshPath });
    fresh.close();

    const legacy = new DatabaseSync(upgradedPath);
    legacy.exec(readFileSync(path.join(MIGRATIONS_DIR, "001_initial.sql"), "utf8"));
    legacy.prepare("INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)").run("2026-09-01T00:00:00.000Z");
    legacy.prepare("INSERT INTO ingress_events VALUES (?, ?, ?, ?, ?, 'processing', ?, ?)").run(
      "event-legacy", "wazuh-legacy", "correlation-legacy", "2026-09-01T00:00:00.000Z", "{}",
      "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z"
    );
    legacy.prepare("INSERT INTO triage_runs VALUES (?, ?, NULL, NULL, 'processing', ?, NULL)").run(
      "trace-legacy", "event-legacy", "2026-09-01T00:00:00.000Z"
    );
    legacy.prepare("INSERT INTO policy_decisions VALUES (?, 'manual_review', 'request_additional_evidence', '[]', '[]', 'legacy', 1, 0, ?, ?, ?)").run(
      "trace-legacy", "legacy-sensitive-token", "legacy-sensitive-token-hash", "2026-09-01T00:00:00.000Z"
    );
    legacy.prepare("INSERT INTO triage_results VALUES (?, ?, 'manual_review', 'request_additional_evidence', '[]', '[]', ?, ?, ?)").run(
      "result-legacy", "trace-legacy", "legacy narrative", "legacy-sensitive-token-hash", "2026-09-01T00:00:00.000Z"
    );
    legacy.prepare("INSERT INTO manual_tickets VALUES (?, ?, ?, 'open', ?, ?)").run(
      "ticket-legacy", "trace-legacy", "result-legacy", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z"
    );
    legacy.prepare("INSERT INTO delivery_outbox VALUES (?, ?, ?, ?, '{}', 'delivered', 1, ?, NULL, NULL, ?, ?)").run(
      "delivery-legacy", "trace-legacy", "ticket-legacy", "feishu:ticket-legacy",
      "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z"
    );
    legacy.close();
    const upgraded = new SecurityOpsStore({ databasePath: upgradedPath });
    upgraded.close();

    const expected = inspectSchema(freshPath);
    assert.deepEqual(inspectSchema(upgradedPath), expected);
    assert.deepEqual(expected.versions, [1, 2, 3, 4]);
    assert.ok(expected.runColumns.includes("claim_token_hash"));
    assert.ok(expected.runColumns.includes("lease_until"));
    assert.ok(expected.policyColumns.includes("evaluation_json"));
    assert.ok(expected.policyColumns.every((name) => !name.includes("decision_token")));
    assert.ok(expected.resultColumns.every((name) => !name.includes("decision_token")));
    assert.ok(expected.tables.includes("authorization_records"));
    assert.ok(expected.triggerColumns.includes("delivery_kind"));
    assert.ok(expected.triggerColumns.includes("recovery_attempt"));
    const migrated = new DatabaseSync(upgradedPath);
    try {
      assert.equal(migrated.prepare("SELECT policy_status FROM policy_decisions WHERE trace_id = ?").get("trace-legacy").policy_status, "legacy");
      assert.equal(migrated.prepare("SELECT narrative FROM triage_results WHERE trace_id = ?").get("trace-legacy").narrative, "legacy narrative");
      assert.equal(migrated.prepare("SELECT status FROM manual_tickets WHERE trace_id = ?").get("trace-legacy").status, "open");
      assert.equal(migrated.prepare("SELECT status FROM delivery_outbox WHERE trace_id = ?").get("trace-legacy").status, "delivered");
      assert.deepEqual(migrated.prepare("PRAGMA foreign_key_check").all(), []);
    } finally {
      migrated.close();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a failed migration rolls back without recording its version", () => {
  const directory = tempDirectory();
  const customMigrations = path.join(directory, "migrations");
  const databasePath = path.join(directory, "failed.db");
  mkdirSync(customMigrations);
  copyFileSync(path.join(MIGRATIONS_DIR, "001_initial.sql"), path.join(customMigrations, "001_initial.sql"));
  copyFileSync(path.join(MIGRATIONS_DIR, "002_recovery_and_leases.sql"), path.join(customMigrations, "002_recovery_and_leases.sql"));
  writeFileSync(
    path.join(customMigrations, "003_invalid.sql"),
    "CREATE TABLE should_rollback(value TEXT);\nTHIS IS NOT SQL;\n",
    "utf8"
  );
  try {
    assert.throws(() => new SecurityOpsStore({ databasePath, migrationsDir: customMigrations }));
    const database = new DatabaseSync(databasePath);
    try {
      assert.deepEqual(
        database.prepare("SELECT version FROM schema_migrations ORDER BY version").all().map((row) => Number(row.version)),
        [1, 2]
      );
      assert.equal(
        database.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'should_rollback'").get().count,
        0
      );
    } finally {
      database.close();
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
