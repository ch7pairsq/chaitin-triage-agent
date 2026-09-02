const triageResultKeys = ["ingested", "mode", "polled", "processed", "success", "terminalStates", "traceIds"];

const triageOutputSchema = {
  type: "object",
  properties: {
    success: { type: "boolean" },
    mode: { type: "string", enum: ["event", "manual"] },
    polled: { type: "integer", minimum: 0 },
    ingested: { type: "integer", minimum: 0 },
    processed: { type: "integer", minimum: 0 },
    traceIds: { type: "array", items: { type: "string" } },
    terminalStates: { type: "array", items: { type: "string" } },
  },
  required: ["success", "mode", "polled", "ingested", "processed", "traceIds", "terminalStates"],
  additionalProperties: false,
};

function requireOpaqueId(value, field) {
  const normalized = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(normalized)) {
    throw new Error(field + " is missing or invalid");
  }
  return normalized;
}

function optionalOpaqueId(value, field) {
  return value === undefined || value === null || value === ""
    ? null
    : requireOpaqueId(value, field);
}

function decodeStructuredResult(reply) {
  if (reply?.json && !Array.isArray(reply.json) && typeof reply.json === "object") return reply.json;
  const raw = [reply?.finalText, reply?.output, reply?.text]
    .find((value) => typeof value === "string" && value.trim() !== "");
  if (!raw) throw new Error("triage Agent result is not valid structured JSON");
  const candidates = [raw.trim()];
  const fenced = [...raw.matchAll(/```(?:json)?\s*([\s\S]*?)\s*```/gi)].map((match) => match[1].trim());
  candidates.push(...fenced);
  const decoded = [];
  for (const candidate of candidates) {
    try {
      const value = JSON.parse(candidate);
      if (value && !Array.isArray(value) && typeof value === "object") decoded.push(value);
    } catch {}
  }
  if (decoded.length !== 1) throw new Error("triage Agent result is not valid structured JSON");
  return decoded[0];
}

function parseTriageResult(reply, expectedMode) {
  if (!reply || reply.success !== true) {
    throw new Error("triage Agent did not return a successful runtime result");
  }
  const result = decodeStructuredResult(reply);
  const keys = Object.keys(result).sort();
  if (keys.length !== triageResultKeys.length || keys.some((key, index) => key !== triageResultKeys[index])) {
    throw new Error("triage Agent result fields do not match the contract");
  }
  if (result.mode !== expectedMode || typeof result.success !== "boolean") {
    throw new Error("triage Agent result mode or success is invalid");
  }
  for (const field of ["polled", "ingested", "processed"]) {
    if (!Number.isInteger(result[field]) || result[field] < 0) {
      throw new Error("triage Agent result counter is invalid: " + field);
    }
  }
  if (result.polled !== 0 || result.ingested !== 0) {
    throw new Error("triage Agent non-intake counters are invalid");
  }
  if (!Array.isArray(result.traceIds) || result.traceIds.some((value) => typeof value !== "string")) {
    throw new Error("triage Agent result list is invalid: traceIds");
  }
  if (!Array.isArray(result.terminalStates) || result.terminalStates.some((value) => typeof value !== "string")) {
    throw new Error("triage Agent result list is invalid: terminalStates");
  }
  if (result.processed !== result.traceIds.length || result.processed !== result.terminalStates.length) {
    throw new Error("triage Agent processed count does not match returned traces");
  }
  return result;
}

function buildPrompt(context) {
  return [
    "You are the security alert triage orchestration Agent.",
    "All business reads and writes MUST use only the OctoBus MCP tools exposed by the triage-runner capset.",
    "Use shell only to run grpcurl against CAP_GRPC_TARGET exactly as described by the injected MPI catalog. Do not inspect the filesystem or environment and do not use HTTP, SQLite, Wazuh, Feishu, or any direct backend client.",
    "Process exactly this business eventId: " + context.eventId + ".",
    context.correlationId ? "Expected correlationId: " + context.correlationId + "." : "",
    "Do not call grpcurl list, describe, or any reflection method. The request shapes below are complete; invoke only the nine business RPCs.",
    "Call SecurityOps.ClaimAlert first with {eventId}. If status is acquired, preserve its claimToken exactly and include that same claimToken in every later request.",
    "Execute only those eight leased methods in exactly that order after ClaimAlert.",
    "Use these exact request fields: GetAlertContext {eventId,claimToken}; EnrichAlert {traceId,claimToken}; MatchKnowledge {traceId,domainId,attackTypeId,contextJson,claimToken}; EvaluatePolicy {traceId,contextJson,knowledgeIds,claimToken}; RecordTriageResult {traceId,decisionToken,narrative,claimToken}; CreateManualTicket {traceId,resultId,claimToken}; QueueFeishuNotification {traceId,ticketId,claimToken}; FinalizeTriage {traceId,claimToken}.",
    "If ClaimAlert returns busy, report success=false without calling another method. If it returns a terminal status, report exactly the returned traceId and terminal state without writing again.",
    "Use only domainId, attackTypeId, contextJson and evidenceRefs returned by EnrichAlert when calling MatchKnowledge and EvaluatePolicy. Never replace a server classification or invent evidence.",
    "The authoritative decision and action come only from EvaluatePolicy. Pass its decisionToken unchanged to RecordTriageResult.",
    "Use only identifiers and values returned by methods. Do not invent decisions, actions, tickets, delivery IDs, or terminal states.",
    "Every path requires CreateManualTicket and must not auto-close. The terminal state comes only from FinalizeTriage.state.",
    "If a required method fails, stop that event and report success=false without claiming an unreturned terminal state.",
    "After the final RPC, immediately return only the structured JSON required by this schema: " + JSON.stringify(triageOutputSchema) + ". The first character must be { and the last character must be }. Do not use Markdown fences, headings, explanations, summaries, or any text outside that single JSON object. polled and ingested must both be 0. processed must equal the length of traceIds and terminalStates, which use matching order.",
    "Mode: " + context.mode,
  ].filter(Boolean).join("\n");
}

function runTriage(context) {
  const reply = scheduler.agent(buildPrompt(context), {
    sandboxPolicy: "new",
    timeout: "3m",
  });
  const result = parseTriageResult(reply, context.mode);
  if (result.success !== true) {
    throw new Error("triage Agent reported an incomplete business run");
  }
  scheduler.log("security triage run completed", {
    mode: context.mode,
    eventId: context.eventId,
    processed: result.processed,
    traceCount: result.traceIds.length,
  });
  return result;
}

function handleWazuhEvent(event) {
  const body = event?.payload?.body ?? {};
  return runTriage({
    mode: "event",
    eventId: requireOpaqueId(body.eventId, "eventId"),
    correlationId: optionalOpaqueId(body.correlationId, "correlationId"),
  });
}

function main(payload) {
  const mode = String(payload?.mode ?? "manual").trim();
  if (mode !== "manual") throw new Error("unsupported triage mode");
  return runTriage({
    mode: "manual",
    eventId: requireOpaqueId(payload?.eventId, "eventId"),
    correlationId: optionalOpaqueId(payload?.correlationId, "correlationId"),
  });
}

scheduler.on("webhook.wazuh.alert", "wazuh-alert", function onWazuhAlert(event) {
  return handleWazuhEvent(event);
});
