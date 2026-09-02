import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

const script = readFileSync(new URL("../triage-scheduler.js", import.meta.url), "utf8");

function loadScheduler({ resultSuccess = true } = {}) {
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
      const result = {
        mode: prompt.includes("Mode: poll") ? "poll" : prompt.includes("Mode: hourly") ? "hourly" : prompt.includes("Mode: manual") ? "manual" : "event",
        success: resultSuccess,
        polled: 0,
        ingested: 0,
        processed: 1,
        traceIds: ["trace-1"],
        terminalStates: ["COMPLETED"],
      };
      return {
        success: true,
        finalText: JSON.stringify(result),
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
  assert.equal(registrations.crons.get("wazuh-alert-poll").expression, "* * * * *");
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
