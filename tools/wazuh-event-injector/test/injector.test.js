import assert from "node:assert/strict";
import test from "node:test";

import { buildEvent, run, sendEvent } from "../src/index.js";

test("rotates deterministic events across all three security domains", () => {
  const now = new Date("2026-09-02T00:00:00.000Z");
  assert.equal(buildEvent({ sequence: 0, now }).domain_id, "vehicle_platform");
  assert.equal(buildEvent({ sequence: 1, now }).domain_id, "iot_platform");
  assert.equal(buildEvent({ sequence: 2, now }).domain_id, "industrial_internet");
  assert.equal(buildEvent({ sequence: 3, now }).domain_id, "vehicle_platform");
  assert.equal(buildEvent({ sequence: 0, now }).authorized, false);
});

test("sends one-line JSON over the configured Wazuh syslog channel", async () => {
  let captured;
  const socket = {
    send(payload, port, host, callback) {
      captured = { payload: payload.toString("utf8"), port, host };
      callback();
    },
    close() {}
  };
  const event = buildEvent({ sequence: 0, now: new Date("2026-09-02T00:00:00.000Z") });
  const result = await sendEvent(event, { host: "wazuh.manager", port: 514, socketFactory: () => socket });
  assert.equal(captured.host, "wazuh.manager");
  assert.equal(captured.port, 514);
  assert.deepEqual(JSON.parse(captured.payload), event);
  assert.equal(result.eventId, event.event_id);
});

test("one-shot mode exits after one event instead of creating a timer", async () => {
  let sent = 0;
  const socketFactory = () => ({
    send(_payload, _port, _host, callback) { sent += 1; callback(); },
    close() {}
  });
  const original = globalThis.setInterval;
  globalThis.setInterval = () => { throw new Error("timer must not be created"); };
  try {
    await run({ host: "wazuh.manager", port: 514, intervalMs: 60_000, enabled: true, once: true, socketFactory });
  } finally {
    globalThis.setInterval = original;
  }
  assert.equal(sent, 1);
});
