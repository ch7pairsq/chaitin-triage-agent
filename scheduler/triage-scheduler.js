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

function parseTriageResult(reply, expectedMode) {
  if (!reply || reply.success !== true) {
    throw new Error("triage Agent did not return a successful result");
  }
  const raw = [reply.finalText, reply.output, reply.text]
    .find((value) => typeof value === "string" && value.trim() !== "");
  let result;
  try {
    result = JSON.parse(String(raw ?? ""));
  } catch {
    throw new Error("triage Agent final message is not valid JSON");
  }
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
  for (const field of ["traceIds", "terminalStates"]) {
    if (!Array.isArray(result[field]) || result[field].some((value) => typeof value !== "string")) {
      throw new Error("triage Agent result list is invalid: " + field);
    }
  }
  return result;
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
    "Do not use shell, exec, HTTP, filesystem, SQLite, Wazuh, Feishu, or any direct backend client.",
    eventLine,
    context.correlationId ? "Expected correlationId: " + context.correlationId + "." : "",
    triageSequence,
    ...executionRules,
    "Return only JSON matching the supplied output schema. polled is the number returned by Wazuh, ingested is the number accepted or already present, and processed is the number that reached a returned terminal state.",
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
