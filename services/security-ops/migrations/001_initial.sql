CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingress_events (
  event_id TEXT PRIMARY KEY,
  wazuh_alert_id TEXT NOT NULL UNIQUE,
  correlation_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  alert_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'claimed', 'processing', 'completed', 'manual')),
  received_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingress_events_pending
  ON ingress_events(status, received_at);

CREATE TABLE IF NOT EXISTS trigger_outbox (
  delivery_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE REFERENCES ingress_events(event_id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'delivered', 'manual')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_until TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trigger_outbox_due
  ON trigger_outbox(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS alert_claims (
  claim_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE REFERENCES ingress_events(event_id),
  trace_id TEXT NOT NULL UNIQUE,
  scheduler_run_id TEXT,
  sandbox_id TEXT,
  claimed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage_runs (
  trace_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE REFERENCES ingress_events(event_id),
  scheduler_run_id TEXT,
  sandbox_id TEXT,
  state TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finalized_at TEXT
);

CREATE TABLE IF NOT EXISTS triage_steps (
  step_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL REFERENCES triage_runs(trace_id),
  sequence INTEGER NOT NULL,
  method TEXT NOT NULL,
  status TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  UNIQUE(trace_id, sequence)
);

CREATE TABLE IF NOT EXISTS triage_results (
  result_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL UNIQUE REFERENCES triage_runs(trace_id),
  decision TEXT NOT NULL,
  action TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  knowledge_json TEXT NOT NULL,
  narrative TEXT NOT NULL,
  decision_token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_tickets (
  ticket_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL UNIQUE REFERENCES triage_runs(trace_id),
  result_id TEXT NOT NULL UNIQUE REFERENCES triage_results(result_id),
  status TEXT NOT NULL CHECK(status IN ('open', 'in_review', 'resolved')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_outbox (
  delivery_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL REFERENCES triage_runs(trace_id),
  ticket_id TEXT NOT NULL UNIQUE REFERENCES manual_tickets(ticket_id),
  idempotency_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'processing', 'delivered', 'manual')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  next_attempt_at TEXT NOT NULL,
  lease_until TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delivery_outbox_due
  ON delivery_outbox(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS policy_decisions (
  trace_id TEXT PRIMARY KEY REFERENCES triage_runs(trace_id),
  decision TEXT NOT NULL,
  action TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  knowledge_json TEXT NOT NULL,
  policy_status TEXT NOT NULL,
  ticket_required INTEGER NOT NULL CHECK(ticket_required = 1),
  auto_close_allowed INTEGER NOT NULL CHECK(auto_close_allowed = 0),
  decision_token TEXT NOT NULL,
  decision_token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_versions (
  version TEXT PRIMARY KEY,
  artifact_sha256 TEXT NOT NULL,
  knowledge_count INTEGER NOT NULL CHECK(knowledge_count > 0),
  activated_at TEXT NOT NULL
);
