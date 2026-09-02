import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SecurityOpsError } from "../src/errors.js";
import {
  normalizeClaimToken,
  normalizePutAuthorizationRecord,
  normalizeRequeueStalledAlerts
} from "../src/validation.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROTO = readFileSync(path.resolve(TEST_DIR, "../proto/security_ops.proto"), "utf8");
const RUNTIME = readFileSync(path.resolve(TEST_DIR, "../src/runtime.js"), "utf8");

test("Proto exposes lease, recovery and authorization contracts", () => {
  assert.match(PROTO, /rpc RequeueStalledAlerts\(/);
  assert.match(PROTO, /rpc PutAuthorizationRecord\(/);
  assert.match(PROTO, /rpc GetWorkerReadiness\(/);
  assert.match(PROTO, /message ClaimAlertResponse \{[\s\S]*string claim_token = 5;[\s\S]*uint32 attempt = 6;[\s\S]*string lease_until = 7;/);
  assert.match(PROTO, /message EnrichAlertRequest \{[\s\S]*string claim_token = 2;/);
  assert.doesNotMatch(PROTO, /message RequeueStalledAlertsRequest \{[\s\S]*\b(limit|stale_after|max_attempts)\b/);
  assert.match(PROTO, /message GetWorkerReadinessResponse \{[\s\S]*uint32 backlog = 2;[\s\S]*uint64 oldest_pending_age_ms = 4;[\s\S]*bool active_batch = 5;[\s\S]*string last_error_json = 7;/);
  assert.match(PROTO, /message KnowledgeMatch \{[\s\S]*string evaluation_json = 5;/);
  assert.match(PROTO, /message EvaluatePolicyResponse \{[\s\S]*string evaluation_json = 10;/);
  assert.doesNotMatch(PROTO, /decision_token/);
});

test("claim tokens are required and strictly bounded", () => {
  assert.equal(normalizeClaimToken("A".repeat(43)), "A".repeat(43));
  for (const token of ["", "short", "contains spaces".repeat(3), "!".repeat(43)]) {
    assert.throws(
      () => normalizeClaimToken(token),
      (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
    );
  }
});

test("authorization records require ordered timestamps and evidence", () => {
  const normalized = normalizePutAuthorizationRecord({
    authorizationId: "auth-1",
    status: "active",
    scopeType: "asset",
    scopeValue: "vehicle-platform-gateway",
    validFrom: "2026-09-01T00:00:00Z",
    validUntil: "2026-09-01T01:00:00Z",
    evidenceRefs: ["change:approved-1"]
  });
  assert.equal(normalized.validFrom, "2026-09-01T00:00:00.000Z");
  assert.throws(
    () => normalizePutAuthorizationRecord({ ...normalized, validUntil: normalized.validFrom }),
    (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
  );
  assert.throws(
    () => normalizePutAuthorizationRecord({ ...normalized, evidenceRefs: [] }),
    (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
  );
});

test("stalled-alert recovery accepts no caller policy overrides", () => {
  assert.deepEqual(normalizeRequeueStalledAlerts({}), {});
  assert.match(RUNTIME, /RequeueStalledAlerts`\]: unary\(\(service,[^)]*\) => \{[\s\S]*?service\.requeueStalledAlerts\(\{\}\)/);
  for (const request of [{ limit: 10 }, { staleAfter: 1 }, { maxAttempts: 99 }]) {
    assert.throws(
      () => normalizeRequeueStalledAlerts(request),
      (error) => error instanceof SecurityOpsError && error.code === "INVALID_ARGUMENT"
    );
  }
});
