import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

const script = readFileSync(new URL("../triage-scheduler.js", import.meta.url), "utf8");

function loadScheduler({ resultSuccess = true, formatResult = JSON.stringify } = {}) {
  const registrations = { events: new Map(), crons: new Map() };
  const calls = [];
  const scheduler = {
    on(topic, triggerId, callback) {
      registrations.events.set(triggerId, { topic, callback });
    },
    cron(triggerId, expression, callback, options) {
      registrations.crons.set(triggerId, { expression, callback, options });
    },
    agent(prompt, options) {
      calls.push({ prompt, options });
      const mode = prompt.includes("Mode: poll") ? "poll" : prompt.includes("Mode: hourly") ? "hourly" : prompt.includes("Mode: manual") ? "manual" : "event";
      const result = {
        mode,
        success: resultSuccess,
        polled: 0,
        ingested: 0,
        processed: mode === "poll" ? 0 : 1,
        traceIds: mode === "poll" ? [] : ["trace-1"],
        terminalStates: mode === "poll" ? [] : ["COMPLETED"],
      };
      return {
        success: true,
        finalText: formatResult(result),
      };
    },
    log() {},
  };
  const context = { scheduler, Date, JSON, Array, String, Error };
  runInNewContext(script, context, { filename: "triage-scheduler.js" });
  return { registrations, calls, main: context.main };
}

test("registers stable Wazuh event and hourly cron triggers", () => {
  const { registrations } = loadScheduler();
  assert.equal(registrations.events.get("wazuh-alert").topic, "webhook.wazuh.alert");
  assert.equal(registrations.crons.get("wazuh-alert-poll").expression, "1-59 * * * *");
  assert.equal(registrations.crons.get("wazuh-alert-poll").options.timezone, "Asia/Shanghai");
  assert.equal(registrations.crons.get("hourly-security-triage").expression, "0 * * * *");
  assert.equal(registrations.crons.get("hourly-security-triage").options.timezone, "Asia/Shanghai");
});

test("minute poll reads Wazuh and ingests alerts only through OctoBus capabilities", () => {
  const { registrations, calls } = loadScheduler();
  const result = registrations.crons.get("wazuh-alert-poll").callback();
  assert.equal(result.mode, "poll");
  assert.match(calls[0].prompt, /WazuhConnector\.ListAlerts/);
  assert.match(calls[0].prompt, /SecurityOps\.IngestAlertEvent/);
  assert.match(calls[0].prompt, /eventId='wazuh:' \+ alertId/);
  assert.match(calls[0].prompt, /status=pending or duplicate=true/);
  assert.match(calls[0].prompt, /Do not run any triage method in this poll run/);
  assert.doesNotMatch(calls[0].prompt, /ClaimAlert|GetTriageTrace/);
  assert.match(calls[0].prompt, /wazuh-ingress capset/);
});

test("event trigger reads only business ids from the webhook body", () => {
  const { registrations, calls } = loadScheduler();
  const result = registrations.events.get("wazuh-alert").callback({
    payload: {
      eventId: "agent-compose-envelope-id",
      body: { eventId: "business-event-1", correlationId: "wazuh-42" },
    },
  });
  assert.equal(result.mode, "event");
  assert.match(calls[0].prompt, /business-event-1/);
  assert.doesNotMatch(calls[0].prompt, /agent-compose-envelope-id/);
  assert.equal(Object.hasOwn(calls[0].options, "agent"), false);
  assert.equal(Object.hasOwn(calls[0].options, "timeout"), false);
  assert.equal(Object.hasOwn(calls[0].options, "title"), false);
  assert.equal(calls[0].options.sandboxPolicy, "new");
  assert.equal(Object.hasOwn(calls[0].options, "outputSchema"), false);
});

test("hourly trigger launches pending-alert processing without operational recovery permission", () => {
  const { registrations, calls } = loadScheduler();
  const result = registrations.crons.get("hourly-security-triage").callback();
  assert.equal(result.mode, "hourly");
  assert.match(calls[0].prompt, /List pending alerts through SecurityOps/);
  assert.doesNotMatch(calls[0].prompt, /RecoverDelivery/);
  assert.match(calls[0].prompt, /GetTriageTrace/);
  assert.match(calls[0].prompt, /triage-runner capset/);
  assert.doesNotMatch(calls[0].prompt, /scheduler\.exec|scheduler\.shell/);
});

test("manual entry requires a real event id and does not accept placeholders", () => {
  const { main, calls } = loadScheduler();
  assert.throws(() => main({ mode: "manual", eventId: "<TRACE_ID>" }), /eventId is missing or invalid/);
  const result = main({ eventId: "business-event-2", correlationId: "wazuh-43" });
  assert.equal(result.mode, "manual");
  assert.match(calls[0].prompt, /business-event-2/);
});

test("an incomplete Agent business result fails the outer scheduler run", () => {
  const { registrations } = loadScheduler({ resultSuccess: false });
  assert.throws(
    () => registrations.crons.get("hourly-security-triage").callback(),
    /incomplete business run/
  );
});

test("extracts one fenced result from model metadata and keeps strict contract validation", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return "Model metadata warning\nResult follows:\n```json\n" + JSON.stringify(result) + "\n```\nNo further data.";
    },
  });
  const result = registrations.crons.get("wazuh-alert-poll").callback();
  assert.equal(result.mode, "poll");
  assert.equal(result.success, true);
});

test("rejects an ambiguous model response containing multiple business results", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return JSON.stringify(result) + "\n" + JSON.stringify({ ...result, processed: result.processed + 1 });
    },
  });
  assert.throws(
    () => registrations.crons.get("wazuh-alert-poll").callback(),
    /ambiguous JSON results/
  );
});

test("accepts an identical result repeated by the runtime transcript", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return "tool output\n" + JSON.stringify(result) + "\n" + JSON.stringify(result);
    },
  });
  const result = registrations.crons.get("wazuh-alert-poll").callback();
  assert.equal(result.mode, "poll");
  assert.equal(result.processed, 0);
});

test("accepts a corrected result only when the runtime repeats the final object", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      const early = { ...result, success: false, processed: 0 };
      return JSON.stringify(early) + "\nself-correction\n" + JSON.stringify(result) + "\n" + JSON.stringify(result);
    },
  });
  const result = registrations.crons.get("wazuh-alert-poll").callback();
  assert.equal(result.success, true);
  assert.equal(result.processed, 0);
});

test("normalizes an exact terminal-state mapping returned by the Agent", () => {
  const { registrations, calls } = loadScheduler({
    formatResult(result) {
      return JSON.stringify({
        ...result,
        terminalStates: { [result.traceIds[0]]: "COMPLETED" },
      });
    },
  });
  const result = registrations.crons.get("hourly-security-triage").callback();
  assert.deepEqual(Array.from(result.terminalStates), ["COMPLETED"]);
  assert.match(calls[0].prompt, /terminalStates MUST both be JSON arrays of strings/);
});

test("rejects a terminal-state mapping that does not match traceIds", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return JSON.stringify({
        ...result,
        terminalStates: { "different-trace": "COMPLETED" },
      });
    },
  });
  assert.throws(
    () => registrations.crons.get("hourly-security-triage").callback(),
    /result list is invalid: terminalStates/
  );
});

test("rejects Wazuh counters invented by a non-poll run", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return JSON.stringify({ ...result, polled: 3, ingested: 3 });
    },
  });
  assert.throws(
    () => registrations.crons.get("hourly-security-triage").callback(),
    /non-poll counters are invalid/
  );
});

test("rejects a processed count that does not match returned traces", () => {
  const { registrations } = loadScheduler({
    formatResult(result) {
      return JSON.stringify({ ...result, processed: 2 });
    },
  });
  assert.throws(
    () => registrations.crons.get("hourly-security-triage").callback(),
    /processed count does not match returned traces/
  );
});
