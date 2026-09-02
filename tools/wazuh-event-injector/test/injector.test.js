import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { buildEvent, listScenarios, run, sendEvent } from "../src/index.js";
import { KnowledgeRepository } from "../../../services/security-ops/src/knowledge-repository.js";

test("publishes reviewed validation coverage for every runtime knowledge record", () => {
  const coverage = listScenarios("coverage");
  const runtimeKnowledge = readFileSync(new URL("../../../services/security-ops/resources/knowledge.jsonl", import.meta.url), "utf8")
    .split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  assert.equal(coverage.length, 99);
  assert.equal(new Set(coverage.map((item) => item.scenarioId)).size, 99);
  assert.deepEqual(
    coverage.map((item) => item.knowledgeId).sort(),
    runtimeKnowledge.map((item) => item.knowledgeId).sort()
  );
  assert.deepEqual(
    Object.fromEntries([...Map.groupBy(coverage, (item) => item.domainId)].map(([key, value]) => [key, value.length])),
    { industrial_internet: 33, iot_platform: 33, vehicle_platform: 33 }
  );
  assert.equal(new Set(coverage.map((item) => item.attackTypeId)).size, 33);
});

test("quick and acceptance profiles cover distinct domains and rule shapes", () => {
  const quick = listScenarios("quick");
  const acceptance = listScenarios("acceptance");
  assert.equal(quick.length, 3);
  assert.equal(acceptance.length, 15);
  assert.equal(new Set(quick.map((item) => item.domainId)).size, 3);
  assert.equal(new Set(acceptance.map((item) => item.domainId)).size, 3);
  assert.ok(new Set(acceptance.map((item) => item.attackTypeId)).size >= 12);
});

test("every coverage event activates its corresponding executable knowledge", () => {
  const knowledgePath = new URL("../../../services/security-ops/resources/knowledge.jsonl", import.meta.url);
  const repository = KnowledgeRepository.fromJsonLines(knowledgePath);
  for (const scenario of listScenarios("coverage")) {
    const event = buildEvent({ scenarioId: scenario.scenarioId, sequence: 0, now: new Date("2026-09-03T00:00:00.000Z") });
    const matches = repository.match({
      domainId: event.domain_id,
      attackTypeId: event.attack_type_id,
      context: {
        domainId: event.domain_id,
        attackTypeId: event.attack_type_id,
        evidenceRefs: ["wazuh-alert:validation", "event:validation"],
        data: event
      }
    });
    const selected = matches.find((match) => match.knowledgeId === scenario.knowledgeId);
    assert.equal(selected?.evaluation.outcome, "confirmed", scenario.scenarioId);
  }
});

test("selects deterministic events by profile sequence or stable scenario id", () => {
  const now = new Date("2026-09-02T00:00:00.000Z");
  assert.equal(buildEvent({ profile: "quick", sequence: 0, now }).domain_id, "vehicle_platform");
  assert.equal(buildEvent({ profile: "quick", sequence: 1, now }).domain_id, "iot_platform");
  assert.equal(buildEvent({ profile: "quick", sequence: 2, now }).domain_id, "industrial_internet");
  assert.equal(buildEvent({ profile: "quick", sequence: 3, now }).domain_id, "vehicle_platform");
  const selected = buildEvent({ scenarioId: "kb-iot_platform-denial_of_service-confirmed-attack", sequence: 0, now });
  assert.equal(selected.scenario_id, "kb-iot_platform-denial_of_service-confirmed-attack");
  assert.equal(selected.attack_type_id, "denial_of_service");
  assert.equal(selected.request_rate_per_second, 500);
  assert.equal(selected.authorized, false);
  assert.deepEqual(
    {
      authFailures: buildEvent({ profile: "quick", sequence: 0, now }).auth_failures,
      protectedAction: buildEvent({ profile: "quick", sequence: 1, now }).protected_action_succeeded,
      shellEffect: buildEvent({ profile: "quick", sequence: 2, now }).execution_side_effect
    },
    { authFailures: 12, protectedAction: true, shellEffect: true }
  );
  assert.ok(buildEvent({ profile: "quick", sequence: 0, now }).observed_evidence.length >= 2);
});

test("rejects unknown profiles, scenarios, and invalid sequences", () => {
  assert.throws(() => listScenarios("missing"), /unknown validation profile/);
  assert.throws(() => buildEvent({ scenarioId: "missing", sequence: 0 }), /unknown validation scenario/);
  assert.throws(() => buildEvent({ profile: "quick", sequence: -1 }), /non-negative safe integer/);
});

test("separate one-shot processes do not rely on timestamps for event identity", () => {
  const now = new Date("2026-09-03T00:00:00.000Z");
  const first = buildEvent({ profile: "quick", sequence: 0, now });
  const second = buildEvent({ profile: "quick", sequence: 0, now });
  assert.notEqual(first.event_id, second.event_id);
  assert.equal(first.scenario_id, second.scenario_id);
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
  const event = buildEvent({ profile: "quick", sequence: 0, now: new Date("2026-09-02T00:00:00.000Z") });
  const result = await sendEvent(event, { host: "wazuh.manager", port: 514, socketFactory: () => socket });
  assert.equal(captured.host, "wazuh.manager");
  assert.equal(captured.port, 514);
  assert.deepEqual(JSON.parse(captured.payload), event);
  assert.equal(result.eventId, event.event_id);
});

test("one-shot mode exits after one event instead of creating a timer", async () => {
  let sent = 0;
  let capturedEvent;
  const socketFactory = () => ({
    send(payload, _port, _host, callback) {
      sent += 1;
      capturedEvent = JSON.parse(payload.toString("utf8"));
      callback();
    },
    close() {}
  });
  const original = globalThis.setInterval;
  globalThis.setInterval = () => { throw new Error("timer must not be created"); };
  try {
    await run({
      host: "wazuh.manager",
      port: 514,
      intervalMs: 60_000,
      enabled: true,
      once: true,
      profile: "quick",
      initialSequence: 1,
      socketFactory
    });
  } finally {
    globalThis.setInterval = original;
  }
  assert.equal(sent, 1);
  assert.equal(capturedEvent.domain_id, "iot_platform");
  assert.equal(capturedEvent.scenario_id, "kb-iot_platform-unauthorized_access-confirmed-attack");
});

test("disabled Stack process stays available for later one-shot exec", async () => {
  let waited = false;
  await run({
    enabled: false,
    stayAlive: true,
    waitForShutdown: async () => { waited = true; }
  });
  assert.equal(waited, true);
});
