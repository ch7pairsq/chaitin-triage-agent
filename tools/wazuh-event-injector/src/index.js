import dgram from "node:dgram";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const manifest = JSON.parse(readFileSync(new URL("./scenarios.json", import.meta.url), "utf8"));
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function validateManifest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("validation scenario manifest must be an object");
  if (!Array.isArray(value.scenarios) || value.scenarios.length !== 99) throw new TypeError("validation scenario manifest must contain 99 scenarios");
  if (!value.profiles || typeof value.profiles !== "object" || Array.isArray(value.profiles)) throw new TypeError("validation profiles are missing");
  const scenarioIds = new Set();
  for (const scenario of value.scenarios) {
    for (const field of ["scenarioId", "knowledgeId", "domainId", "attackTypeId"]) {
      if (!identifierPattern.test(String(scenario?.[field] ?? ""))) throw new TypeError(`validation scenario ${field} is invalid`);
    }
    if (scenarioIds.has(scenario.scenarioId)) throw new TypeError(`duplicate validation scenario: ${scenario.scenarioId}`);
    scenarioIds.add(scenario.scenarioId);
    if (!scenario.data || typeof scenario.data !== "object" || Array.isArray(scenario.data)) throw new TypeError(`validation scenario data is invalid: ${scenario.scenarioId}`);
    if (!Array.isArray(scenario.observedEvidence) || scenario.observedEvidence.length < 2) throw new TypeError(`validation scenario evidence is incomplete: ${scenario.scenarioId}`);
  }
  for (const [profile, scenarioList] of Object.entries(value.profiles)) {
    if (!identifierPattern.test(profile) || !Array.isArray(scenarioList) || scenarioList.length === 0) throw new TypeError(`validation profile is invalid: ${profile}`);
    if (new Set(scenarioList).size !== scenarioList.length) throw new TypeError(`validation profile contains duplicates: ${profile}`);
    for (const scenarioId of scenarioList) {
      if (!scenarioIds.has(scenarioId)) throw new TypeError(`validation profile references an unknown scenario: ${scenarioId}`);
    }
  }
}

validateManifest(manifest);

const scenariosById = new Map(manifest.scenarios.map((scenario) => [scenario.scenarioId, Object.freeze(scenario)]));
const profiles = Object.freeze(Object.fromEntries(
  Object.entries(manifest.profiles).map(([name, scenarioIds]) => [name, Object.freeze([...scenarioIds])])
));

function normalizeSequence(value) {
  const sequence = typeof value === "number" ? value : Number(String(value ?? "").trim());
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new TypeError("sequence must be a non-negative safe integer");
  return sequence;
}

function selectScenario({ scenarioId = "", profile = "quick", sequence = 0 }) {
  const normalizedSequence = normalizeSequence(sequence);
  if (scenarioId) {
    const selected = scenariosById.get(String(scenarioId).trim());
    if (!selected) throw new TypeError(`unknown validation scenario: ${scenarioId}`);
    return { scenario: selected, sequence: normalizedSequence };
  }
  const normalizedProfile = String(profile).trim();
  const scenarioIds = profiles[normalizedProfile];
  if (!scenarioIds) throw new TypeError(`unknown validation profile: ${profile}`);
  return {
    scenario: scenariosById.get(scenarioIds[normalizedSequence % scenarioIds.length]),
    sequence: normalizedSequence
  };
}

export function listScenarios(profile = "quick") {
  const normalizedProfile = String(profile).trim();
  const scenarioIds = profiles[normalizedProfile];
  if (!scenarioIds) throw new TypeError(`unknown validation profile: ${profile}`);
  return scenarioIds.map((scenarioId) => ({ ...scenariosById.get(scenarioId) }));
}

export function buildEvent({ sequence = 0, scenarioId = "", profile = "quick", now = new Date(), eventIdFactory = randomUUID } = {}) {
  const selected = selectScenario({ scenarioId, profile, sequence });
  const scenario = selected.scenario;
  return {
    ...scenario.data,
    security_program: "triage_event_injector",
    event_version: "1",
    event_id: `triage-event-${eventIdFactory()}`,
    scenario_id: scenario.scenarioId,
    knowledge_id: scenario.knowledgeId,
    occurred_at: now.toISOString(),
    authorized: false,
    domain_id: scenario.domainId,
    attack_type_id: scenario.attackTypeId,
    asset_id: scenario.assetId,
    protocol: scenario.protocol,
    srcip: scenario.sourceIp,
    dstuser: scenario.destinationUser,
    outcome: scenario.outcome,
    observed_evidence: [...scenario.observedEvidence]
  };
}

export function sendEvent(event, { host, port, socketFactory = () => dgram.createSocket("udp4") }) {
  if (!host) return Promise.reject(new TypeError("WAZUH_SYSLOG_HOST is required"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return Promise.reject(new TypeError("WAZUH_SYSLOG_PORT is invalid"));
  const payload = Buffer.from(JSON.stringify(event));
  const socket = socketFactory();
  return new Promise((resolve, reject) => {
    socket.send(payload, port, host, (error) => {
      socket.close();
      if (error) reject(error);
      else resolve({ bytes: payload.length, eventId: event.event_id });
    });
  });
}

export async function run({
  host = process.env.WAZUH_SYSLOG_HOST,
  port = Number(process.env.WAZUH_SYSLOG_PORT ?? 514),
  intervalMs = Number(process.env.INJECT_INTERVAL_MS ?? 300_000),
  enabled = String(process.env.INJECT_ENABLED ?? "false").toLowerCase() === "true",
  once = String(process.env.INJECT_ONCE ?? "false").toLowerCase() === "true",
  stayAlive = String(process.env.INJECT_STAY_ALIVE ?? "false").toLowerCase() === "true",
  profile = process.env.INJECT_PROFILE ?? "quick",
  scenarioId = process.env.INJECT_SCENARIO_ID ?? "",
  initialSequence = process.env.INJECT_SEQUENCE ?? 0,
  socketFactory,
  waitForShutdown = () => new Promise((resolve) => {
    const timer = setInterval(() => {}, 3_600_000);
    const stop = () => {
      clearInterval(timer);
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      resolve();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  })
} = {}) {
  if (!enabled) {
    console.log(JSON.stringify({ status: "disabled" }));
    if (stayAlive) await waitForShutdown();
    return;
  }
  if (!Number.isInteger(intervalMs) || intervalMs < 60_000 || intervalMs > 86_400_000) {
    throw new TypeError("INJECT_INTERVAL_MS must be between 60000 and 86400000");
  }
  let sequence = normalizeSequence(initialSequence);
  const emit = async () => {
    const event = buildEvent({ sequence: sequence++, scenarioId, profile });
    const result = await sendEvent(event, { host, port, ...(socketFactory ? { socketFactory } : {}) });
    console.log(JSON.stringify({
      status: "sent",
      eventId: result.eventId,
      scenarioId: event.scenario_id,
      domainId: event.domain_id,
      attackTypeId: event.attack_type_id,
      bytes: result.bytes
    }));
  };
  await emit();
  if (once) return () => {};
  const timer = setInterval(() => emit().catch((error) => console.error(JSON.stringify({ status: "failed", message: error.message }))), intervalMs);
  return () => clearInterval(timer);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch((error) => {
    console.error(JSON.stringify({ status: "failed", message: error.message }));
    process.exitCode = 1;
  });
}
