#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function parseObject(text, label) {
  let value;
  try {
    value = JSON.parse(String(text ?? "").trim());
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object`);
  return value;
}

function requireIdentifier(value, label) {
  const normalized = String(value ?? "").trim();
  if (!identifierPattern.test(normalized)) throw new Error(`${label} is missing or invalid`);
  return normalized;
}

export function parseInjectionOutput(text) {
  const receipt = parseObject(text, "injector receipt");
  if (receipt.status !== "sent") throw new Error("injector did not confirm delivery");
  return {
    eventId: requireIdentifier(receipt.eventId, "source event id"),
    scenarioId: requireIdentifier(receipt.scenarioId, "scenario id"),
    domainId: requireIdentifier(receipt.domainId, "domain id"),
    attackTypeId: requireIdentifier(receipt.attackTypeId, "attack type id")
  };
}

export function findSourceAlert(envelope, { sourceEventId, scenarioId }) {
  const expectedEventId = requireIdentifier(sourceEventId, "source event id");
  const expectedScenarioId = requireIdentifier(scenarioId, "scenario id");
  const alerts = Array.isArray(envelope?.alerts) ? envelope.alerts : [];
  for (const alert of alerts) {
    let source;
    try {
      source = JSON.parse(String(alert?.alertJson ?? ""));
    } catch {
      continue;
    }
    const data = source?.data && typeof source.data === "object" && !Array.isArray(source.data)
      ? source.data
      : source;
    if (data?.event_id === expectedEventId && data?.scenario_id === expectedScenarioId) {
      return { alertId: requireIdentifier(alert.alertId, "Wazuh alert id") };
    }
  }
  return null;
}

export function validateIntakeInvocation(text) {
  const invocation = parseObject(text, "intake invocation");
  if (invocation.status !== "succeeded") throw new Error(`intake invocation status is ${invocation.status ?? "missing"}`);
  const result = parseObject(invocation.result_json, "intake result");
  if (result.success !== true) throw new Error("deterministic intake reported failure");
  for (const field of ["polled", "ingested", "duplicates", "requeued", "manualized", "durationMs"]) {
    if (!Number.isInteger(result[field]) || result[field] < 0) throw new Error(`intake counter is invalid: ${field}`);
  }
  if (result.ingested + result.duplicates !== result.polled) throw new Error("intake counters are inconsistent");
  const outerDuration = Number(invocation.duration_ms ?? result.durationMs);
  if (!Number.isFinite(outerDuration) || outerDuration < 0 || outerDuration > 30_000 || result.durationMs > 30_000) {
    throw new Error("intake exceeded the 30 second boundary");
  }
  return result;
}

function containsEventId(value, expectedEventId) {
  if (!value || typeof value !== "object") return false;
  if (!Array.isArray(value) && value.eventId === expectedEventId) return true;
  return Object.values(value).some((nested) => containsEventId(nested, expectedEventId));
}

export function findMatchingRun(text, expectedEventId) {
  const expected = requireIdentifier(expectedEventId, "expected business event id");
  const envelope = parseObject(text, "scheduler runs");
  const runs = Array.isArray(envelope.runs) ? envelope.runs : [];
  const matching = runs.filter((run) => {
    try {
      return containsEventId(JSON.parse(String(run?.payload_json ?? "")), expected);
    } catch {
      return false;
    }
  });
  if (matching.length === 0) return { status: "pending" };
  if (matching.length > 1) throw new Error(`multiple Agent runs reference the same event: ${expected}`);
  const run = matching[0];
  const runId = requireIdentifier(run.run_id, "Agent run id");
  if (run.status === "running") return { status: "pending", runId };
  if (run.status !== "succeeded") {
    throw new Error(`matching Agent run failed: run=${runId} status=${run.status ?? "missing"} error=${String(run.error ?? "").slice(0, 256)}`);
  }
  const result = parseObject(run.result_json, "Agent run result");
  if (result.success !== true || result.mode !== "event" || result.polled !== 0 || result.ingested !== 0) {
    throw new Error("matching Agent run returned an invalid event result");
  }
  if (result.processed !== 1 || !Array.isArray(result.traceIds) || result.traceIds.length !== 1
      || !Array.isArray(result.terminalStates) || result.terminalStates.length !== 1
      || result.terminalStates[0] !== "completed") {
    throw new Error("matching Agent run did not complete exactly one trace");
  }
  return {
    status: "completed",
    runId,
    traceId: requireIdentifier(result.traceIds[0], "trace id"),
    durationMs: Number(run.duration_ms ?? 0)
  };
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function boundedTimeoutSeconds(value) {
  const normalized = Number(value ?? 90);
  if (!Number.isInteger(normalized) || normalized < 10 || normalized > 300) {
    throw new Error("E2E_TIMEOUT_SECONDS must be between 10 and 300");
  }
  return normalized;
}

async function resolveAlert() {
  const sourceEventId = requireIdentifier(process.env.EXPECTED_SOURCE_EVENT_ID, "source event id");
  const scenarioId = requireIdentifier(process.env.EXPECTED_SCENARIO_ID, "scenario id");
  const timeoutSeconds = boundedTimeoutSeconds(process.env.E2E_TIMEOUT_SECONDS);
  const token = readFileSync("/run/secrets/wazuh-ingress-token", "utf8").trim();
  if (token.length < 24) throw new Error("Wazuh ingress token is missing or invalid");
  const endpoint = "http://octobus:9000/capsets/wazuh-ingress/connect/wazuh-indexer/wazuh.connector.v1.WazuhConnectorService/ListAlerts";
  const deadline = Date.now() + timeoutSeconds * 1000;
  do {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ lookbackSeconds: 900, limit: 100 }),
      signal: AbortSignal.timeout(10_000)
    });
    const body = await response.text();
    if (response.status === 401 || response.status === 403) throw new Error(`Wazuh lookup authorization failed with HTTP ${response.status}`);
    if (response.ok) {
      const found = findSourceAlert(parseObject(body, "Wazuh lookup response"), { sourceEventId, scenarioId });
      if (found) {
        process.stdout.write(`${found.alertId}\n`);
        return;
      }
    }
    if (Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 2000));
  } while (Date.now() < deadline);
  throw new Error(`Wazuh did not index source event ${sourceEventId} within ${timeoutSeconds} seconds`);
}

async function main() {
  const command = process.argv[2];
  if (command === "parse-injection") {
    const receipt = parseInjectionOutput(await readStdin());
    process.stdout.write(`${receipt.eventId} ${receipt.scenarioId} ${receipt.domainId} ${receipt.attackTypeId}\n`);
    return;
  }
  if (command === "resolve-alert") {
    await resolveAlert();
    return;
  }
  if (command === "validate-intake") {
    process.stdout.write(`${JSON.stringify(validateIntakeInvocation(await readStdin()))}\n`);
    return;
  }
  if (command === "find-run") {
    const result = findMatchingRun(await readStdin(), process.env.EXPECTED_BUSINESS_EVENT_ID);
    if (result.status === "pending") {
      process.exitCode = 75;
      return;
    }
    process.stdout.write(`${result.runId} ${result.traceId} ${result.durationMs}\n`);
    return;
  }
  throw new Error("usage: verify-e2e.mjs parse-injection|resolve-alert|validate-intake|find-run");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
