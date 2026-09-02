import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

const script = readFileSync(new URL("../triage-scheduler.js", import.meta.url), "utf8");

function loadScheduler({ resultSuccess = true, structuredResult = null, finalTextOnly = false, finalText = null } = {}) {
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
      const mode = prompt.includes("Mode: manual") ? "manual" : "event";
      const json = structuredResult ?? {
        success: resultSuccess,
        mode,
        polled: 0,
        ingested: 0,
        processed: 1,
        traceIds: ["trace-1"],
        terminalStates: ["COMPLETED"],
      };
      return {
        success: true,
        ...(finalTextOnly ? {} : { json }),
        finalText: finalText ?? JSON.stringify(json),
      };
    },
    log() {},
  };
  const context = { scheduler, Date, JSON, Array, String, Error, Object };
  runInNewContext(script, context, { filename: "triage-scheduler.js" });
  return { registrations, calls, main: context.main };
}

test("registers only the Wazuh webhook event trigger", () => {
  const { registrations } = loadScheduler();
  assert.equal(registrations.events.size, 1);
  assert.equal(registrations.events.get("wazuh-alert").topic, "webhook.wazuh.alert");
  assert.equal(registrations.crons.size, 0);
  assert.doesNotMatch(script, /hourly-security-triage|wazuh-alert-poll|Mode: poll/);
});

test("event trigger uses a new sandbox, three-minute timeout, and a scheduler-enforced output schema", () => {
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
  assert.equal(calls[0].options.sandboxPolicy, "new");
  assert.equal(calls[0].options.timeout, "3m");
  assert.equal(calls[0].options.outputSchema, undefined);
  assert.match(calls[0].prompt, /"additionalProperties":false/);
  assert.match(calls[0].prompt, /"required":\["success","mode","polled","ingested","processed","traceIds","terminalStates"\]/);
});

test("triage prompt passes the acquired claim token to all eight leased methods", () => {
  const { registrations, calls } = loadScheduler();
  registrations.events.get("wazuh-alert").callback({
    payload: { body: { eventId: "business-event-2", correlationId: "wazuh-43" } },
  });
  const prompt = calls[0].prompt;
  assert.match(prompt, /ClaimAlert/);
  assert.match(prompt, /claimToken/);
  for (const method of [
    "GetAlertContext", "EnrichAlert", "MatchKnowledge", "EvaluatePolicy",
    "RecordTriageResult", "CreateManualTicket", "QueueFeishuNotification", "FinalizeTriage",
  ]) {
    assert.match(prompt, new RegExp("claimToken.*" + method, "s"));
  }
  assert.doesNotMatch(prompt, /GetTriageTrace|ListPendingAlerts|ListAlerts|IngestAlertEvent/);
  assert.match(prompt, /Do not call grpcurl list, describe, or any reflection method/);
  assert.match(prompt, /GetAlertContext \{eventId,claimToken\}/);
  assert.match(prompt, /MatchKnowledge \{traceId,claimToken\}/);
  assert.match(prompt, /EvaluatePolicy \{traceId,claimToken\}/);
  assert.doesNotMatch(prompt, /MatchKnowledge \{traceId,domainId|EvaluatePolicy \{traceId,contextJson/);
  assert.match(prompt, /FinalizeTriage \{traceId,claimToken\}/);
  assert.match(prompt, /first character must be \{/);
  assert.match(prompt, /Do not use Markdown fences/);
  assert.match(prompt, /triage-runner capset/);
  assert.doesNotMatch(prompt, /decisionToken|decision_token/);
});

test("manual entry requires a real event id and uses the same event workflow", () => {
  const { main, calls } = loadScheduler();
  assert.throws(() => main({ mode: "manual", eventId: "<TRACE_ID>" }), /eventId is missing or invalid/);
  const result = main({ mode: "manual", eventId: "business-event-3", correlationId: "wazuh-44" });
  assert.equal(result.mode, "manual");
  assert.match(calls[0].prompt, /business-event-3/);
});

test("uses scheduler-validated structured JSON and rejects an incomplete result", () => {
  const success = loadScheduler();
  assert.equal(success.registrations.events.get("wazuh-alert").callback({
    payload: { body: { eventId: "business-event-4" } },
  }).success, true);

  const incomplete = loadScheduler({ resultSuccess: false });
  assert.throws(
    () => incomplete.registrations.events.get("wazuh-alert").callback({
      payload: { body: { eventId: "business-event-4" } },
    }),
    /incomplete business run/
  );
});

test("extracts one contract-shaped JSON result from chat-completions text but rejects ambiguity", () => {
  const fenced = loadScheduler({
    finalTextOnly: true,
    finalText: "Done.\n```json\n{\"success\":true,\"mode\":\"event\",\"polled\":0,\"ingested\":0,\"processed\":1,\"traceIds\":[\"trace-1\"],\"terminalStates\":[\"completed\"]}\n```\nSummary.",
  });
  assert.equal(fenced.registrations.events.get("wazuh-alert").callback({
    payload: { body: { eventId: "business-event-6" } },
  }).success, true);

  const trailing = loadScheduler({
    finalTextOnly: true,
    finalText: "RPC complete. {\"success\":true,\"mode\":\"event\",\"polled\":0,\"ingested\":0,\"processed\":1,\"traceIds\":[\"trace-2\"],\"terminalStates\":[\"completed\"]}",
  });
  assert.deepEqual(Array.from(trailing.registrations.events.get("wazuh-alert").callback({
    payload: { body: { eventId: "business-event-7" } },
  }).traceIds), ["trace-2"]);

  const ambiguous = loadScheduler({
    finalTextOnly: true,
    finalText: "{\"success\":true,\"mode\":\"event\",\"polled\":0,\"ingested\":0,\"processed\":1,\"traceIds\":[\"trace-1\"],\"terminalStates\":[\"completed\"]}\n{\"success\":true,\"mode\":\"event\",\"polled\":0,\"ingested\":0,\"processed\":1,\"traceIds\":[\"trace-2\"],\"terminalStates\":[\"completed\"]}",
  });
  assert.throws(
    () => ambiguous.registrations.events.get("wazuh-alert").callback({
      payload: { body: { eventId: "business-event-8" } },
    }),
    /not valid structured JSON/
  );
});

test("rejects invalid structured counters and terminal arrays", () => {
  const invalid = loadScheduler({
    structuredResult: {
      success: true,
      mode: "event",
      polled: 1,
      ingested: 0,
      processed: 2,
      traceIds: ["trace-1"],
      terminalStates: ["COMPLETED"],
    },
  });
  assert.throws(
    () => invalid.registrations.events.get("wazuh-alert").callback({
      payload: { body: { eventId: "business-event-5" } },
    }),
    /non-intake counters|processed count/
  );
});
