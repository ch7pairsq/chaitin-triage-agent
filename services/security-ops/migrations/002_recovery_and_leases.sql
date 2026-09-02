ALTER TABLE ingress_events ADD COLUMN recovery_count INTEGER NOT NULL DEFAULT 0 CHECK(recovery_count >= 0);
ALTER TABLE ingress_events ADD COLUMN next_recovery_at TEXT;
ALTER TABLE ingress_events ADD COLUMN last_recovery_error TEXT;

ALTER TABLE triage_runs ADD COLUMN claim_token_hash TEXT;
ALTER TABLE triage_runs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 1 CHECK(attempt >= 1);
ALTER TABLE triage_runs ADD COLUMN lease_until TEXT;
ALTER TABLE triage_runs ADD COLUMN last_activity_at TEXT;

CREATE TABLE trigger_outbox_v2 (
  delivery_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES ingress_events(event_id) ON DELETE CASCADE,
  delivery_kind TEXT NOT NULL DEFAULT 'initial' CHECK(delivery_kind IN ('initial', 'recovery')),
  recovery_attempt INTEGER NOT NULL DEFAULT 0 CHECK(recovery_attempt >= 0),
  idempotency_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'delivered', 'manual')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_until TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(event_id, delivery_kind, recovery_attempt)
);

INSERT INTO trigger_outbox_v2 (
  delivery_id, event_id, delivery_kind, recovery_attempt, idempotency_key,
  payload_json, status, attempts, next_attempt_at, lease_until, last_error,
  created_at, updated_at
)
SELECT
  delivery_id, event_id, 'initial', 0, idempotency_key,
  payload_json, status, attempts, next_attempt_at, lease_until, last_error,
  created_at, updated_at
FROM trigger_outbox;

DROP TABLE trigger_outbox;
ALTER TABLE trigger_outbox_v2 RENAME TO trigger_outbox;

CREATE INDEX idx_trigger_outbox_due
  ON trigger_outbox(status, next_attempt_at);

CREATE INDEX idx_ingress_events_recovery
  ON ingress_events(status, next_recovery_at, updated_at);

CREATE INDEX idx_triage_runs_active
  ON triage_runs(state, lease_until, last_activity_at);

CREATE TABLE authorization_records (
  authorization_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
  scope_type TEXT NOT NULL CHECK(scope_type IN ('asset', 'account', 'rule', 'change_window')),
  scope_value TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(valid_from < valid_until)
);

CREATE INDEX idx_authorization_records_lookup
  ON authorization_records(status, scope_type, scope_value, valid_from, valid_until);
