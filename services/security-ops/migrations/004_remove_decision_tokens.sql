CREATE TABLE policy_decisions_v4 (
  trace_id TEXT PRIMARY KEY REFERENCES triage_runs(trace_id),
  decision TEXT NOT NULL,
  action TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  knowledge_json TEXT NOT NULL,
  evaluation_json TEXT NOT NULL DEFAULT '[]',
  policy_status TEXT NOT NULL,
  ticket_required INTEGER NOT NULL CHECK(ticket_required = 1),
  auto_close_allowed INTEGER NOT NULL CHECK(auto_close_allowed = 0),
  created_at TEXT NOT NULL
);

INSERT INTO policy_decisions_v4 (
  trace_id, decision, action, evidence_json, knowledge_json, evaluation_json,
  policy_status, ticket_required, auto_close_allowed, created_at
)
SELECT
  trace_id, decision, action, evidence_json, knowledge_json, evaluation_json,
  policy_status, ticket_required, auto_close_allowed, created_at
FROM policy_decisions;

DROP TABLE policy_decisions;
ALTER TABLE policy_decisions_v4 RENAME TO policy_decisions;

CREATE TABLE triage_results_v4 (
  result_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL UNIQUE REFERENCES triage_runs(trace_id),
  decision TEXT NOT NULL,
  action TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  knowledge_json TEXT NOT NULL,
  narrative TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO triage_results_v4 (
  result_id, trace_id, decision, action, evidence_json, knowledge_json, narrative, created_at
)
SELECT
  result_id, trace_id, decision, action, evidence_json, knowledge_json, narrative, created_at
FROM triage_results;

DROP TABLE triage_results;
ALTER TABLE triage_results_v4 RENAME TO triage_results;
