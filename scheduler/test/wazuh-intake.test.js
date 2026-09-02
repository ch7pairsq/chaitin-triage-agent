import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

const script = readFileSync(new URL("../wazuh-intake.js", import.meta.url), "utf8");
const expectedKeys = ["duplicates", "durationMs", "ingested", "manualized", "polled", "requeued", "success"];

function loadScheduler({ commandResult } = {}) {
  const registrations = { events: new Map(), crons: new Map() };
  const calls = [];
  const scheduler = {
    on(topic, triggerId, callback) {
      registrations.events.set(triggerId, { topic, callback });
    },
    cron(triggerId, expression, callback, options) {
      registrations.crons.set(triggerId, { expression, callback, options });
    },
    exec(request) {
      calls.push(request);
      const output = commandResult ?? {
        success: true,
        polled: 2,
        ingested: 1,
        duplicates: 1,
        requeued: 0,
        manualized: 0,
        durationMs: 123,
      };
      return { success: true, exitCode: 0, stdout: JSON.stringify(output), stderr: "" };
    },
    log() {},
  };
  const context = { scheduler, Date, JSON, Array, String, Error, Object };
  runInNewContext(script, context, { filename: "wazuh-intake.js" });
  return { registrations, calls, main: context.main };
}

test("registers exactly one minute cron trigger", () => {
  const { registrations } = loadScheduler();
  assert.equal(registrations.events.size, 0);
  assert.equal(registrations.crons.size, 1);
  const trigger = registrations.crons.get("wazuh-intake");
  assert.equal(trigger.expression, "* * * * *");
  assert.equal(trigger.options.timezone, "Asia/Shanghai");
});

test("runs one fixed deterministic command in a sticky sandbox with a 25-second timeout", () => {
  const { registrations, calls } = loadScheduler();
  const result = registrations.crons.get("wazuh-intake").callback();
  assert.deepEqual(Object.keys(result).sort(), expectedKeys);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "node");
  assert.equal(calls[0].args[0], "-e");
  assert.equal(calls[0].timeoutMs, 25_000);
  assert.equal(calls[0].sandboxPolicy, "sticky");
  assert.equal(Object.hasOwn(calls[0], "env"), false);
});

test("fixed command calls only the three intake capabilities through the injected gRPC target", () => {
  const { registrations, calls } = loadScheduler();
  registrations.crons.get("wazuh-intake").callback();
  const program = calls[0].args[1];
  for (const method of ["ListAlerts", "IngestAlertEvent", "RequeueStalledAlerts"]) {
    assert.match(program, new RegExp(method));
  }
  assert.match(program, /CAP_GRPC_TARGET/);
  assert.match(program, /CAP_TOKEN/);
  assert.match(program, /wazuh\/wazuh-ingress/);
  assert.doesNotMatch(program, /https?:\/\/|sqlite|feishu|curl\s/i);
});

test("manual invocation accepts only the fixed cycle payload", () => {
  const { main, calls } = loadScheduler();
  assert.equal(main({ mode: "cycle" }).success, true);
  assert.equal(calls.length, 1);
  assert.throws(() => main({ mode: "cycle", command: "whoami" }), /unsupported intake payload/);
  assert.throws(() => main({ mode: "poll" }), /unsupported intake payload/);
  assert.throws(() => main("cycle"), /unsupported intake payload/);
});

test("rejects command failure and malformed output", () => {
  const scheduler = {
    cron(_id, _expression, callback) { this.callback = callback; },
    exec() { return { success: false, exitCode: 1, stdout: "", stderr: "failed" }; },
    log() {},
  };
  runInNewContext(script, { scheduler, Date, JSON, Array, String, Error, Object });
  assert.throws(() => scheduler.callback(), /deterministic intake command failed/);

  const malformed = loadScheduler({ commandResult: { success: true, polled: 1 } });
  assert.throws(() => malformed.registrations.crons.get("wazuh-intake").callback(), /result fields/);
});
