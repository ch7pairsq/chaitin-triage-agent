#!/usr/bin/env node
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const completedMethodChain = Object.freeze([
  "ClaimAlert",
  "GetAlertContext",
  "EnrichAlert",
  "MatchKnowledge",
  "EvaluatePolicy",
  "RecordTriageResult",
  "CreateManualTicket",
  "QueueFeishuNotification",
  "FinalizeTriage"
]);

function hasOrderedMethodChain(steps, requiredMethods) {
  let requiredIndex = 0;
  for (const step of steps) {
    if (step?.method === requiredMethods[requiredIndex]) requiredIndex += 1;
    if (requiredIndex === requiredMethods.length) return true;
  }
  return false;
}

export function validateTrace(trace, { traceId, expectedState }) {
  if (trace.traceId !== traceId) throw new Error("trace id mismatch");
  if (trace.state !== expectedState) throw new Error(`trace state is ${trace.state}, expected ${expectedState}`);
  if (!trace.policy || trace.policy.autoCloseAllowed !== false || trace.policy.ticketRequired !== true) throw new Error("policy boundary is incomplete");
  if (!trace.result?.resultId) throw new Error("triage result is missing");
  if (!Array.isArray(trace.result.evidenceRefs) || trace.result.evidenceRefs.length === 0) throw new Error("triage evidence is missing");
  if (!trace.ticket?.ticketId || trace.ticket.status !== "open") throw new Error("open manual ticket is missing");
  if (!trace.delivery?.deliveryId || !["pending", "processing", "delivered", "manual"].includes(trace.delivery.status)) throw new Error("Feishu delivery state is missing");
  if (expectedState === "completed" && trace.delivery.status !== "delivered") throw new Error("delivered Feishu record is missing");
  if (!Array.isArray(trace.steps) || trace.steps.length === 0) throw new Error("trace steps are incomplete");
  if (expectedState === "completed" && !hasOrderedMethodChain(trace.steps, completedMethodChain)) {
    throw new Error("OctoBus business method chain is incomplete or out of order");
  }
  if (expectedState === "manual" && (trace.result.decision !== "manual_review" || trace.result.action !== "request_additional_evidence")) {
    throw new Error("safe-degradation result is not manual_review/request_additional_evidence");
  }
  return trace;
}

async function fetchTrace({ endpoint, token, traceId }) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ traceId }),
    signal: AbortSignal.timeout(10000)
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`OctoBus trace request returned HTTP ${response.status}: ${text.slice(0, 512)}`);
  const envelope = JSON.parse(text);
  return JSON.parse(envelope.traceJson);
}

async function main() {
  const traceId = String(process.env.TRACE_ID ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(traceId)) throw new Error("TRACE_ID is missing or invalid");
  const expectedState = String(process.env.TRACE_EXPECTED_STATE ?? "completed").trim();
  if (!["completed", "manual"].includes(expectedState)) throw new Error("TRACE_EXPECTED_STATE must be completed or manual");
  const token = fs.readFileSync("/run/secrets/triage-ops-token", "utf8").trim();
  if (!token) throw new Error("triage operations token is empty");
  const endpoint = "http://octobus:9000/capsets/triage-ops/connect/security-ops-main/security.ops.v1.SecurityOpsService/GetTriageTrace";
  let trace = null;
  for (let attempt = 1; attempt <= 46; attempt += 1) {
    trace = await fetchTrace({ endpoint, token, traceId });
    if (expectedState === "completed") {
      if (trace.state === "manual" || trace.delivery?.status === "manual") {
        throw new Error(`normal trace entered manual recovery: state=${trace.state}, delivery=${trace.delivery?.status ?? "missing"}`);
      }
      if (trace.state === "completed" && trace.delivery?.status === "delivered") break;
    } else {
      if (trace.state === "completed") throw new Error("safe-degradation trace completed unexpectedly");
      if (trace.state === "manual" && trace.delivery?.status) break;
    }
    if (attempt === 46) throw new Error(`trace did not reach ${expectedState} verification state within 90 seconds`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  validateTrace(trace, { traceId, expectedState });
  console.log(JSON.stringify(trace, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
