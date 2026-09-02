# Deterministic Intake and Leased Triage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the minute/hourly LLM polling model with a sub-30-second deterministic intake cycle, event-driven triage, leased recovery, bounded concurrency, and one shared deployment path.

**Architecture:** agent-compose owns the minute schedule and webhook-triggered Agent runtime. The deterministic intake process and the triage Agent call every business method through OctoBus. SecurityOps remains the sole owner of business SQLite state, idempotency, leases, policy, tickets, and Feishu delivery.

**Tech Stack:** Node.js 22, Proto3, OctoBus SDK, agent-compose scheduler, SQLite, Docker Compose/Portainer Stack, Wazuh, Feishu Webhook.

---

## Task 1: Add ordered migrations and the recovery schema

**Files:**

- Create: `services/security-ops/migrations/002_recovery_and_leases.sql`
- Modify: `services/security-ops/src/store.js`
- Modify: `services/security-ops/test/ingress.test.js`
- Create: `services/security-ops/test/migrations.test.js`

### Step 1: Write failing migration tests

Add tests that open an empty database and a database containing only `001_initial.sql`. Assert both reach the same schema and contain:

```js
assert.deepEqual(appliedVersions, ["001_initial.sql", "002_recovery_and_leases.sql"]);
assert.ok(columns.triage_runs.includes("claim_token_hash"));
assert.ok(columns.triage_runs.includes("lease_until"));
assert.ok(tables.includes("authorization_records"));
```

Also assert a deliberately invalid migration rolls back without recording its version.

### Step 2: Run the focused test and confirm failure

Run: `node --test services/security-ops/test/migrations.test.js`

Expected: FAIL because the migration ledger and `002` schema do not exist.

### Step 3: Implement the migration runner and schema

Add a `schema_migrations` ledger. Discover `*.sql`, sort lexically, execute each unapplied file in one transaction, and record the version only after success.

`002_recovery_and_leases.sql` must add lease/recovery fields, rebuild `trigger_outbox` for initial and recovery deliveries, add `authorization_records`, and create these uniqueness rules:

```sql
UNIQUE(event_id, delivery_kind, recovery_attempt)
UNIQUE(idempotency_key)
```

### Step 4: Run focused and package tests

Run:

```bash
node --test services/security-ops/test/migrations.test.js
npm --prefix services/security-ops test
```

Expected: PASS.

### Step 5: Commit

```bash
git add services/security-ops/migrations services/security-ops/src/store.js services/security-ops/test
git commit -m "增加业务库有序迁移与恢复结构"
```

## Task 2: Add lease, recovery, and authorization contracts

**Files:**

- Modify: `services/security-ops/proto/security_ops.proto`
- Modify: `services/security-ops/proto/descriptor.pb`
- Modify: `services/security-ops/src/errors.js`
- Modify: `services/security-ops/src/validation.js`
- Modify: `services/security-ops/tools/validate-package.mjs`
- Modify: `services/security-ops/test/workflow.test.js`

### Step 1: Write failing contract tests

Assert the descriptor contains `RequeueStalledAlerts` and `PutAuthorizationRecord`, and `ClaimAlertResponse` contains `claimToken`, `attempt`, and `leaseUntil`. Add input tests for malformed tokens, invalid authorization time ranges, and caller-supplied recovery limits.

### Step 2: Confirm failure

Run: `npm --prefix services/security-ops test`

Expected: FAIL on the missing methods and fields.

### Step 3: Extend Proto and stable errors

Add the new methods and messages. Recovery request must not expose `limit`, `staleAfter`, or `maxAttempts`; those remain server constants. Add stable errors:

```text
LEASE_BUSY
LEASE_EXPIRED
CLAIM_FENCED
AUTHORIZATION_INVALID
```

### Step 4: Rebuild and validate descriptor

Run:

```bash
npm --prefix services/security-ops run build:descriptor
npm --prefix services/security-ops run validate:package
```

Expected: PASS and the descriptor changes are tracked.

### Step 5: Commit

```bash
git add services/security-ops/proto services/security-ops/src/errors.js services/security-ops/src/validation.js services/security-ops/tools/validate-package.mjs services/security-ops/test/workflow.test.js
git commit -m "扩展租约恢复与授权记录契约"
```

## Task 3: Implement claim leases, fencing, and concurrency limits

**Files:**

- Modify: `services/security-ops/src/store.js`
- Modify: `services/security-ops/src/service.js`
- Modify: `services/security-ops/test/workflow.test.js`
- Modify: `services/security-ops/config.schema.json`

### Step 1: Write failing state-machine tests

Cover:

- first claim returns `acquired` with token, attempt 1, and lease;
- concurrent claim returns `busy`;
- completed/manual events return their terminal claim status;
- a method with a wrong or expired token returns `CLAIM_FENCED` or `LEASE_EXPIRED`;
- a valid method refreshes activity and lease;
- after recovery, the previous token cannot write;
- a third concurrent event cannot be acquired when two are active.

Use a controllable clock rather than real sleeps.

### Step 2: Confirm failure

Run: `node --test services/security-ops/test/workflow.test.js`

Expected: FAIL on missing lease and concurrency behavior.

### Step 3: Implement the lease transaction

Generate a cryptographically random token, store only its hash, and return the plaintext only to the acquiring caller. Perform claim, active-count check, token rotation, and state transition in one SQLite transaction.

Require the token on every workflow method that reads or appends a workflow step:

```text
GetAlertContext, EnrichAlert, MatchKnowledge, EvaluatePolicy,
RecordTriageResult, CreateManualTicket, QueueFeishuNotification, FinalizeTriage
```

Set `max_active_triage` default and maximum to 2 in the service configuration.

### Step 4: Run tests

Run:

```bash
npm --prefix services/security-ops run check
npm --prefix services/security-ops test
```

Expected: PASS.

### Step 5: Commit

```bash
git add services/security-ops/src services/security-ops/test/workflow.test.js services/security-ops/config.schema.json
git commit -m "实现研判租约围栏与并发上限"
```

## Task 4: Implement deterministic stalled-run recovery

**Files:**

- Modify: `services/security-ops/src/store.js`
- Modify: `services/security-ops/src/service.js`
- Modify: `services/security-ops/src/outbox.js`
- Modify: `services/security-ops/test/ingress.test.js`
- Modify: `services/security-ops/test/outbox.test.js`

### Step 1: Write failing recovery tests

Test the fixed policy with a fake clock:

- activity newer than 3 minutes is not recovered;
- at most 5 stale events are handled per cycle;
- recovery attempts 1 and 2 create one recovery outbox row each;
- identical recovery calls do not duplicate an attempt;
- attempt 3 produces `manual_review/request_additional_evidence`, one ticket, and one Feishu outbox row;
- recovery does not fabricate a completed Agent state.

Expected idempotency key:

```text
triage:<eventId>:recovery:<attempt>
```

### Step 2: Confirm failure

Run:

```bash
node --test services/security-ops/test/ingress.test.js
node --test services/security-ops/test/outbox.test.js
```

Expected: FAIL because recovery is not implemented.

### Step 3: Implement recovery and slot-aware dispatch

Implement `RequeueStalledAlerts` with server constants: batch 5, stale after 3 minutes, maximum 3 recoveries. Rotate claim state before queuing a new attempt. Dispatch initial/recovery events only while `claimed + processing < 2`.

Replace swallowed worker exceptions with one structured error record containing worker name, event ID, attempt, error code, and retry time.

### Step 4: Run service tests

Run: `npm --prefix services/security-ops test`

Expected: PASS.

### Step 5: Commit

```bash
git add services/security-ops/src services/security-ops/test
git commit -m "实现停滞研判恢复与受限投递"
```

## Task 5: Make authorization-based noise reduction server-authoritative

**Files:**

- Modify: `services/security-ops/src/store.js`
- Modify: `services/security-ops/src/service.js`
- Modify: `services/security-ops/src/validation.js`
- Modify: `services/security-ops/test/workflow.test.js`
- Modify: `services/security-ops/README.md`

### Step 1: Write failing policy tests

Add cases proving that raw `authorizationRecord=true` does not suppress. Suppression is allowed only when `authorization_record_id` resolves to an active, unexpired, scope-matching record with evidence. Test missing, expired, revoked, and scope-mismatched records.

### Step 2: Confirm failure

Run: `node --test services/security-ops/test/workflow.test.js`

Expected: FAIL because policy still trusts the alert field.

### Step 3: Implement the registry

Implement `PutAuthorizationRecord` as an ops-only method supporting active and revoked states. Resolve authorization inside `EvaluatePolicy`; never trust the alert boolean. Preserve the existing knowledge match, evidence-reference, decision-token, manual-ticket, and no-auto-close gates.

### Step 4: Run tests

Run: `npm --prefix services/security-ops test`

Expected: PASS, including existing noise-reduction tests.

### Step 5: Commit

```bash
git add services/security-ops/src services/security-ops/test/workflow.test.js services/security-ops/README.md
git commit -m "收紧授权降噪的服务端校验"
```

## Task 6: Bound Wazuh retry latency

**Files:**

- Modify: `services/wazuh-connector/src/client.js`
- Modify: `services/wazuh-connector/src/runtime.js`
- Modify: `services/wazuh-connector/config.schema.json`
- Modify: `services/wazuh-connector/test/client.test.js`
- Modify: `services/wazuh-connector/test/runtime.test.js`
- Modify: `deploy/stacks/triage-platform/tools/render-config.mjs`

### Step 1: Write failing retry tests

With injected fetch, clock, and jitter sources, assert:

- one request times out after 8 seconds;
- only timeout, 429, and 5xx receive a second attempt;
- 400/401/403 are not retried;
- two attempts plus backoff stay under 17 seconds;
- a failed cycle does not advance the Wazuh cursor.

### Step 2: Confirm failure

Run: `npm --prefix services/wazuh-connector test`

Expected: FAIL on timeout/retry classification.

### Step 3: Implement bounded retry

Use `AbortSignal.timeout(8000)` or an equivalent abort controller. Permit exactly two total attempts and a short jittered delay. Set `minimum_rule_level` default to 0 while retaining `rule.groups=triage_input`.

### Step 4: Run connector tests

Run:

```bash
npm --prefix services/wazuh-connector run check
npm --prefix services/wazuh-connector test
```

Expected: PASS.

### Step 5: Commit

```bash
git add services/wazuh-connector deploy/stacks/triage-platform/tools/render-config.mjs
git commit -m "限制Wazuh查询重试时延"
```

## Task 7: Split deterministic intake from the triage Agent

**Files:**

- Create: `scheduler/wazuh-intake.js`
- Modify: `scheduler/triage-scheduler.js`
- Modify: `scheduler/test/triage-scheduler.test.js`
- Create: `scheduler/test/wazuh-intake.test.js`
- Modify: `agent-compose.yml`
- Modify: `deploy/stacks/triage-platform/docker-compose.yml`

### Step 1: Write failing scheduler tests

Assert the project has exactly these triggers:

```text
wazuh-intake: cron * * * * *, concurrency skip, sticky sandbox, exec timeout 25s
triage-operator: webhook.wazuh.alert, parallel, new sandbox, agent timeout 3m
```

Assert no hourly cron and no poll-mode `scheduler.agent` call remain. Validate the intake result has exactly `success`, `polled`, `ingested`, `duplicates`, `requeued`, `manualized`, and `durationMs`.

### Step 2: Confirm failure

Run: `npm --prefix scheduler test`

Expected: FAIL because the current scheduler uses one Agent for poll, event, and hourly modes.

### Step 3: Implement the two-agent project

Move fixed intake orchestration to `scheduler/wazuh-intake.js`. It may call only OctoBus through `CAP_GRPC_TARGET`, must reject arbitrary command input, and must invoke ListAlerts, IngestAlertEvent, and RequeueStalledAlerts in order.

Keep `scheduler/triage-scheduler.js` event-only. Add the claim token to every subsequent method call and require the final structured result schema.

Mount the new scheduler file read-only into agent-compose.

### Step 4: Run scheduler and repository tests

Run:

```bash
npm --prefix scheduler run check
npm --prefix scheduler test
npm run check
```

Expected: PASS and no hourly trigger is found.

### Step 5: Commit

```bash
git add scheduler agent-compose.yml deploy/stacks/triage-platform/docker-compose.yml
git commit -m "拆分分钟采集与事件研判编排"
```

## Task 8: Align OctoBus capsets and bootstrap

**Files:**

- Modify: `deploy/stacks/triage-platform/bootstrap.sh`
- Modify: `deploy/stacks/triage-platform/tools/render-config.mjs`
- Modify: `deploy/stacks/triage-platform/tools/configure-agent-webhook.mjs`
- Modify: `services/security-ops/tools/validate-deployment.mjs`
- Modify: `tools/verify-repository.mjs`

### Step 1: Write failing repository validations

Require exact capset memberships:

- `wazuh-ingress`: `ListAlerts`, `IngestAlertEvent`, `RequeueStalledAlerts`;
- `triage-runner`: the nine leased workflow methods;
- `triage-ops`: `GetTriageTrace`, `RecoverDelivery`, `PutAuthorizationRecord`.

Reject `ListPendingAlerts` and any direct Wazuh/SQLite/Feishu call in scheduler code.

### Step 2: Confirm failure

Run: `npm run check`

Expected: FAIL on stale capsets or forbidden references.

### Step 3: Update bootstrap and validation

Register each service, instance, method, capset, token, and webhook idempotently. Scope the intake token only to `wazuh-ingress`, the Agent token only to `triage-runner`, and keep `triage-ops` separate from both.

### Step 4: Run validation

Run:

```bash
npm run check
npm --prefix services/security-ops run validate:deployment
```

Expected: PASS.

### Step 5: Commit

```bash
git add deploy/stacks/triage-platform services/security-ops/tools/validate-deployment.mjs tools/verify-repository.mjs
git commit -m "收敛OctoBus能力授权与注册"
```

## Task 9: Add one shared Stack update script and backup convention

**Files:**

- Create: `deploy/update-stacks.sh`
- Create: `deploy/test/update-stacks.test.mjs`
- Modify: `tools/release-webhook/src/worker.js`
- Modify: `tools/release-webhook/test/worker.test.js`
- Modify: `deploy/stacks/release-webhook/docker-compose.yml`
- Modify: `deploy/stacks/release-webhook/README.md`
- Modify: `deploy/stacks/triage-platform/README.md`
- Modify: `deploy/stacks/wazuh/README.md`

### Step 1: Write failing deployment tests

Use a fake command runner and temporary directories to assert:

- every backup name matches `<purpose>-backup-YYYYMMDD-HHMMSS`;
- configuration validation occurs before mutation;
- commit, generated configuration, and SQLite are backed up before update;
- update order is Wazuh, triage platform, bootstrap, release worker, verification;
- restricted release mode delays its own replacement;
- a failed stage exits nonzero and prints the matching rollback point.

### Step 2: Confirm failure

Run: `node --test deploy/test/update-stacks.test.mjs`

Expected: FAIL because the shared script does not exist.

### Step 3: Implement the shared script

Use the checked-in compose files as the only source. Support an interactive server mode and a restricted release-worker mode. The Portainer documentation must point to the same compose files and preparation steps rather than duplicate YAML.

Update the GitHub webhook worker to call only this script after branch/ref allow-list and signature verification succeed.

### Step 4: Run deployment and webhook tests

Run:

```bash
node --test deploy/test/update-stacks.test.mjs
npm --prefix tools/release-webhook test
```

Expected: PASS.

### Step 5: Commit

```bash
git add deploy tools/release-webhook
git commit -m "统一Stack更新与备份流程"
```

## Task 10: Add graceful workers and delivery degradation

**Files:**

- Modify: `services/security-ops/src/outbox.js`
- Modify: `services/security-ops/src/runtime.js`
- Modify: `services/security-ops/test/outbox.test.js`
- Modify: `deploy/stacks/triage-platform/verify.sh`

### Step 1: Write failing fault tests

Assert:

- Feishu failure preserves result and ticket;
- retry exhaustion moves delivery to a visible manual state;
- SIGTERM stops new claims and waits for the current batch within a bounded grace period;
- worker exceptions produce structured logs and do not disappear.

### Step 2: Confirm failure

Run: `node --test services/security-ops/test/outbox.test.js`

Expected: FAIL on graceful shutdown or manual delivery state.

### Step 3: Implement and expose health

Separate business transaction completion from delivery acknowledgement. Add worker readiness fields for backlog, oldest pending age, active batch, and last error. Implement bounded drain on shutdown.

### Step 4: Run tests

Run: `npm --prefix services/security-ops test`

Expected: PASS.

### Step 5: Commit

```bash
git add services/security-ops/src services/security-ops/test/outbox.test.js deploy/stacks/triage-platform/verify.sh
git commit -m "增强投递降级与优雅退出"
```

## Task 11: Synchronize README diagrams and verification procedures

**Files:**

- Modify: `README.md`
- Modify: `services/security-ops/README.md`
- Modify: `services/wazuh-connector/README.md`
- Modify: `deploy/stacks/triage-platform/verify-trace.sh`
- Modify: `deploy/stacks/triage-platform/tools/verify-trace.mjs`
- Modify: `tools/verify-repository.mjs`

### Step 1: Add failing documentation checks

Reject stale statements or commands:

```text
hourly-security-triage
scheduler trigger wazuh-intake
minimum_rule_level: 3
Agent direct HTTP, SQLite, or Feishu calls
```

Require architecture and sequence diagrams to show minute intake, OctoBus on both sides of the Agent, claim lease, recovery, ticket, and Feishu outbox.

### Step 2: Confirm failure

Run: `npm run check`

Expected: FAIL until the documentation and scripts are synchronized.

### Step 3: Update README and trace checks

Document both manual Portainer and server-script updates, plus the signed GitHub webhook path. Explain that Wazuh dashboard is visualization-only. Add separate procedures for empty-cycle timing, normal event, recovery, concurrency, duplicate idempotency, and Feishu retry.

Use the supported manual command:

```bash
agent-compose -p chaitin-triage-agent scheduler invoke wazuh-intake \
  --payload '{"mode":"cycle"}' --timeout 30s
```

Trace verification must accept `completed` for the normal path and `manual` for the explicit safe-degradation path, while requiring nonempty evidence, ticket, and delivery state.

### Step 4: Run repository validation

Run:

```bash
npm run check
npm test
git diff --check
```

Expected: PASS.

### Step 5: Commit

```bash
git add README.md services deploy/stacks/triage-platform tools/verify-repository.mjs
git commit -m "同步架构说明与恢复验证步骤"
```

## Task 12: Perform clean-clone and two-round end-to-end verification

**Files:**

- Modify if evidence format needs correction: `README.md`
- Modify if validation needs correction: `deploy/stacks/triage-platform/verify.sh`
- No production source changes during the evidence run.

### Step 1: Run local quality gates

Run:

```bash
npm run verify
npm --prefix services/security-ops run pack:check
npm --prefix services/wazuh-connector run pack:check
git diff --check
```

Expected: all commands pass and the worktree is clean after the final documentation commit.

### Step 2: Deploy from a clean Linux clone

Use an empty target directory, clone `develop`, fill secrets outside Git, prepare configuration, and invoke `deploy/update-stacks.sh`. Do not reuse old containers or old business databases as proof of reproducibility.

### Step 3: Verify the intake timing boundary

Invoke `wazuh-intake` 10 consecutive times with a 30-second client timeout. Record every duration and assert all are below 30 seconds.

### Step 4: Verify normal, duplicate, and concurrent paths twice

For each round:

1. create two distinct Wazuh alerts through the documented injection entry;
2. confirm both webhook events start triage and active concurrency never exceeds 2;
3. repeat one source alert and one webhook delivery;
4. confirm no duplicate triage run or ticket is created;
5. trace each event through Agent run, OctoBus audit, `triage.db`, ticket, and Feishu outbox.

### Step 5: Verify recovery and delivery degradation

Force one controlled Agent timeout, advance it through recovery, and verify the old token is fenced. Force one Feishu failure and verify the result/ticket remain committed and delivery becomes retryable or manual.

### Step 6: Record final evidence and commit only documentation corrections

If the run reveals documentation-only corrections, apply them and repeat the affected verification. Do not hide or delete failed runs; identify the final successful runs by trace ID.

```bash
git add README.md deploy/stacks/triage-platform
git commit -m "完善独立部署与两轮验证说明"
```
