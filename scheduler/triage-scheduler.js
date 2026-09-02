const triageResultKeys = ["ingested", "mode", "polled", "processed", "success", "terminalStates", "traceIds"];

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

function parseObject(value) {
  try {
    const parsed = JSON.parse(value);
    return parsed && !Array.isArray(parsed) && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function extractJsonObjects(text) {
  const objects = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (start < 0) {
      if (character === "{") {
        start = index;
        depth = 1;
        inString = false;
        escaped = false;
      }
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) {
        const parsed = parseObject(text.slice(start, index + 1));
        if (parsed) objects.push(parsed);
        start = -1;
      }
    }
  }
  return objects;
}

function uniqueObjects(objects) {
  const unique = new Map();
  for (const object of objects) unique.set(JSON.stringify(object), object);
  return [...unique.values()];
}

function extractTriageObject(raw, expectedMode) {
  const text = String(raw ?? "").trim();
  const direct = parseObject(text);
  if (direct) return direct;

  const fenced = [];
  const fencePattern = /```(?:json)?\s*([\s\S]*?)```/gi;
  for (const match of text.matchAll(fencePattern)) {
    const parsed = parseObject(match[1].trim());
    if (parsed) fenced.push(parsed);
  }
  const uniqueFenced = uniqueObjects(fenced);
  if (uniqueFenced.length === 1) return uniqueFenced[0];

  const completeLines = text
    .split(/\r?\n/)
    .map((line) => parseObject(line.trim()))
    .filter(Boolean);
  const matchingCompleteLines = completeLines.filter((candidate) =>
    candidate.mode === expectedMode && typeof candidate.success === "boolean"
  );
  if (matchingCompleteLines.length >= 2) {
    const last = matchingCompleteLines.at(-1);
    const previous = matchingCompleteLines.at(-2);
    if (JSON.stringify(last) === JSON.stringify(previous)) return last;
  }
  const candidates = uniqueObjects([
    ...uniqueFenced,
    ...completeLines,
    ...extractJsonObjects(text),
  ]);
  const matching = candidates.filter((candidate) =>
    candidate.mode === expectedMode && typeof candidate.success === "boolean"
  );
  if (matching.length === 1) return matching[0];
  if (matching.length > 1) throw new Error("triage Agent final message contains ambiguous JSON results");
  throw new Error("triage Agent final message does not contain a JSON result");
}

function parseTriageResult(reply, expectedMode) {
  if (!reply || reply.success !== true) {
    throw new Error("triage Agent did not return a successful result");
  }
  const raw = [reply.finalText, reply.output, reply.text]
    .find((value) => typeof value === "string" && value.trim() !== "");
  const result = extractTriageObject(raw, expectedMode);
  if (!result || Array.isArray(result) || typeof result !== "object") {
    throw new Error("triage Agent result must be an object");
  }
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
  if (!Array.isArray(result.traceIds) || result.traceIds.some((value) => typeof value !== "string")) {
    throw new Error("triage Agent result list is invalid: traceIds");
  }
  let terminalStates = result.terminalStates;
  if (terminalStates && !Array.isArray(terminalStates) && typeof terminalStates === "object") {
    const stateTraceIds = Object.keys(terminalStates);
    const exactTraceMapping = stateTraceIds.length === result.traceIds.length
      && stateTraceIds.every((traceId) => result.traceIds.includes(traceId));
    if (exactTraceMapping) terminalStates = result.traceIds.map((traceId) => terminalStates[traceId]);
  }
  if (!Array.isArray(terminalStates) || terminalStates.some((value) => typeof value !== "string")) {
    throw new Error("triage Agent result list is invalid: terminalStates");
  }
  return { ...result, terminalStates };
}

function buildPrompt(context) {
  const eventLine = context.mode === "poll"
    ? "Call WazuhConnector.ListAlerts with lookbackSeconds=900 and limit=20. For each returned alert, call SecurityOps.IngestAlertEvent exactly once using eventId='wazuh:' + alertId and the returned alertId, occurredAt, correlationId and alertJson unchanged."
    : context.eventId
      ? "Process exactly this business eventId: " + context.eventId + "."
      : "List pending alerts through SecurityOps and process each returned eventId, up to 20 alerts.";
  const triageSequence = context.mode === "poll"
    ? "Do not run any triage method in this poll run; accepted events are handled by the webhook event trigger."
    : "For every event, call SecurityOps methods in this exact order: ClaimAlert; GetAlertContext; EnrichAlert; MatchKnowledge; EvaluatePolicy; RecordTriageResult; CreateManualTicket; QueueFeishuNotification; FinalizeTriage; GetTriageTrace.";
  const executionRules = context.mode === "poll"
    ? [
        "Use the alert fields returned by ListAlerts unchanged when calling IngestAlertEvent; do not invent or enrich alert content.",
        "Count an IngestAlertEvent response with status=pending or duplicate=true as ingested. Do not retry an accepted or duplicate event.",
        "If ListAlerts or any IngestAlertEvent call fails, report success=false and stop this poll run.",
      ]
    : [
        "Use only domainId, attackTypeId, contextJson and evidenceRefs returned by EnrichAlert when calling MatchKnowledge and EvaluatePolicy. These server classifications may be unclassified/other_attack; never replace them with an invented value.",
        "Use only identifiers and evidence returned by those tools. Do not invent evidence, knowledge IDs, decisions, actions, tickets, delivery IDs, or terminal states.",
        "The authoritative decision and action come only from EvaluatePolicy. Use the returned decisionToken unchanged when calling RecordTriageResult.",
        "Your narrative may summarize tool-returned evidence, but it must not change the authoritative decision.",
        "If a required method fails, stop that event, report success=false, and do not claim a terminal state that was not returned by GetTriageTrace.",
      ];

  return [
    "You are the security triage orchestration Agent.",
    context.mode === "poll"
      ? "All Wazuh reads and ingress writes MUST use the OctoBus MCP tools exposed by the wazuh-ingress capset."
      : "All triage reads and writes MUST use the OctoBus MCP tools exposed by the triage-runner capset.",
    "Use shell only to run grpcurl against CAP_GRPC_TARGET exactly as described by the injected MPI catalog. Do not inspect the filesystem or environment and do not use exec, HTTP, SQLite, Wazuh, Feishu, or any direct backend client.",
    eventLine,
    context.correlationId ? "Expected correlationId: " + context.correlationId + "." : "",
    triageSequence,
    ...executionRules,
    "Return only one JSON object with exactly these keys: success, mode, polled, ingested, processed, traceIds, terminalStates. Do not use a Markdown fence or add explanation. traceIds and terminalStates MUST both be JSON arrays of strings, with terminalStates in the same order as traceIds. polled is the number returned by Wazuh, ingested is the number accepted or already present, and processed is the number that reached a returned terminal state.",
    "Mode: " + context.mode,
  ].filter(Boolean).join("\n");
}

function runTriage(context) {
  const reply = scheduler.agent(buildPrompt(context), {
    sandboxPolicy: "new",
  });

  const result = parseTriageResult(reply, context.mode);
  if (result.success !== true) {
    throw new Error("triage Agent reported an incomplete business run");
  }
  scheduler.log("security triage run completed", {
    mode: context.mode,
    eventId: context.eventId ?? null,
    processed: result.processed,
    success: result.success,
    traceCount: Array.isArray(result.traceIds) ? result.traceIds.length : 0,
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

function runHourlyCompensation() {
  return runTriage({ mode: "hourly", eventId: null, correlationId: null });
}

function runWazuhPoll() {
  return runTriage({ mode: "poll", eventId: null, correlationId: null });
}

function main(payload) {
  const mode = String(payload?.mode ?? "manual").trim();
  if (mode === "poll") return runWazuhPoll();
  if (mode === "hourly") return runHourlyCompensation();
  return runTriage({
    mode: "manual",
    eventId: requireOpaqueId(payload?.eventId, "eventId"),
    correlationId: optionalOpaqueId(payload?.correlationId, "correlationId"),
  });
}

scheduler.on("webhook.wazuh.alert", "wazuh-alert", function onWazuhAlert(event) {
  return handleWazuhEvent(event);
});

scheduler.cron("wazuh-alert-poll", "* * * * *", function wazuhAlertPoll() {
  return runWazuhPoll();
}, { timezone: "Asia/Shanghai" });

scheduler.cron("hourly-security-triage", "0 * * * *", function hourlySecurityTriage() {
  return runHourlyCompensation();
}, { timezone: "Asia/Shanghai" });
