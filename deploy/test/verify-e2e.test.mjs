import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  findMatchingRun,
  findSourceAlert,
  parseInjectionOutput,
  validateIntakeInvocation
} from "../stacks/triage-platform/tools/verify-e2e.mjs";
import { validateTrace } from "../stacks/triage-platform/tools/verify-trace.mjs";

test("parses a structured injector receipt without exposing the event body", () => {
  assert.deepEqual(parseInjectionOutput(JSON.stringify({
    status: "sent",
    eventId: "triage-event-1-0",
    scenarioId: "kb-vehicle_platform-brute_force-confirmed-attack",
    domainId: "vehicle_platform",
    attackTypeId: "brute_force",
    bytes: 512
  })), {
    eventId: "triage-event-1-0",
    scenarioId: "kb-vehicle_platform-brute_force-confirmed-attack",
    domainId: "vehicle_platform",
    attackTypeId: "brute_force"
  });
});

test("finds the Wazuh document created from the exact source event", () => {
  const alert = findSourceAlert({ alerts: [{
    alertId: "wazuh-document-1",
    alertJson: JSON.stringify({ data: {
      event_id: "triage-event-1-0",
      scenario_id: "kb-vehicle_platform-brute_force-confirmed-attack"
    } })
  }] }, {
    sourceEventId: "triage-event-1-0",
    scenarioId: "kb-vehicle_platform-brute_force-confirmed-attack"
  });
  assert.equal(alert.alertId, "wazuh-document-1");
});

test("validates the deterministic intake result and 30 second boundary", () => {
  const result = validateIntakeInvocation(JSON.stringify({
    status: "succeeded",
    duration_ms: 950,
    result_json: JSON.stringify({
      success: true,
      polled: 1,
      ingested: 1,
      duplicates: 0,
      requeued: 0,
      manualized: 0,
      durationMs: 800
    })
  }));
  assert.equal(result.ingested, 1);
  assert.throws(() => validateIntakeInvocation(JSON.stringify({
    status: "succeeded",
    duration_ms: 31000,
    result_json: JSON.stringify({ success: true, polled: 0, ingested: 0, duplicates: 0, requeued: 0, manualized: 0, durationMs: 31000 })
  })), /30 second boundary/);
});

test("matches the exact webhook payload and returns its completed trace", () => {
  const found = findMatchingRun(JSON.stringify({ runs: [{
    run_id: "run-1",
    trigger_id: "wazuh-alert",
    status: "succeeded",
    duration_ms: 42000,
    payload_json: JSON.stringify({ payload: { body: { eventId: "wazuh:wazuh-document-1" } } }),
    result_json: JSON.stringify({
      success: true,
      mode: "event",
      polled: 0,
      ingested: 0,
      processed: 1,
      traceIds: ["trace-1"],
      terminalStates: ["completed"]
    })
  }] }), "wazuh:wazuh-document-1");
  assert.deepEqual(found, { status: "completed", runId: "run-1", traceId: "trace-1", durationMs: 42000 });
});

test("does not accept an unrelated run and fails the matching failed run", () => {
  const unrelated = JSON.stringify({ runs: [{
    run_id: "run-other",
    status: "succeeded",
    payload_json: JSON.stringify({ payload: { body: { eventId: "wazuh:other" } } }),
    result_json: "{}"
  }] });
  assert.deepEqual(findMatchingRun(unrelated, "wazuh:wazuh-document-1"), { status: "pending" });

  const failed = JSON.stringify({ runs: [{
    run_id: "run-failed",
    status: "failed",
    error: "agent failed",
    payload_json: JSON.stringify({ payload: { body: { eventId: "wazuh:wazuh-document-1" } } })
  }] });
  assert.throws(() => findMatchingRun(failed, "wazuh:wazuh-document-1"), /matching Agent run failed/);
});

test("the unified shell entrypoint preserves strict event-to-trace correlation", () => {
  const script = readFileSync(new URL("../stacks/triage-platform/verify-e2e.sh", import.meta.url), "utf8");
  assert.match(script, /verify\.sh/);
  assert.match(script, /INJECT_PROFILE/);
  assert.match(script, /INJECT_SEQUENCE/);
  assert.match(script, /resolve-alert/);
  assert.match(script, /scheduler invoke wazuh-intake/);
  assert.match(script, /find-run/);
  assert.match(script, /verify-trace\.sh/);
  assert.doesNotMatch(script, /docker\.sock|sqlite3|curl .*octobus/);
});

test("completed trace verification requires the ordered OctoBus business chain", () => {
  const methods = [
    "ClaimAlert",
    "GetAlertContext",
    "EnrichAlert",
    "MatchKnowledge",
    "EvaluatePolicy",
    "RecordTriageResult",
    "CreateManualTicket",
    "QueueFeishuNotification",
    "FinalizeTriage"
  ];
  const trace = {
    traceId: "trace-1",
    state: "completed",
    policy: { autoCloseAllowed: false, ticketRequired: true },
    result: { resultId: "result-1", evidenceRefs: ["wazuh-alert:1"] },
    ticket: { ticketId: "ticket-1", status: "open" },
    delivery: { deliveryId: "delivery-1", status: "delivered" },
    steps: methods.map((method, index) => ({ sequence: index + 1, method }))
  };
  assert.doesNotThrow(() => validateTrace(trace, { traceId: "trace-1", expectedState: "completed" }));
  assert.throws(
    () => validateTrace({ ...trace, steps: trace.steps.filter((step) => step.method !== "MatchKnowledge") }, { traceId: "trace-1", expectedState: "completed" }),
    /business method chain is incomplete/
  );
});
