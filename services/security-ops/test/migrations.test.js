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
    legacy.close();
    const upgraded = new SecurityOpsStore({ databasePath: upgradedPath });
    upgraded.close();

    const expected = inspectSchema(freshPath);
    assert.deepEqual(inspectSchema(upgradedPath), expected);
    assert.deepEqual(expected.versions, [1, 2]);
    assert.ok(expected.runColumns.includes("claim_token_hash"));
    assert.ok(expected.runColumns.includes("lease_until"));
    assert.ok(expected.tables.includes("authorization_records"));
    assert.ok(expected.triggerColumns.includes("delivery_kind"));
    assert.ok(expected.triggerColumns.includes("recovery_attempt"));
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
