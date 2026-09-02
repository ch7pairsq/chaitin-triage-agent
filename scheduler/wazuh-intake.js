const intakeResultKeys = ["duplicates", "durationMs", "ingested", "manualized", "polled", "requeued", "success"];

const deterministicIntakeProgram = String.raw`
const { spawnSync } = require("node:child_process");

const startedAt = Date.now();
const target = String(process.env.CAP_GRPC_TARGET || "").trim();
const token = String(process.env.CAP_TOKEN || "").trim();
const capset = "wazuh/wazuh-ingress";

function fail(message) {
  throw new Error(message);
}

function callCapability(instance, method, payload) {
  if (!target || !token) fail("capability gateway variables are unavailable");
  const remainingMs = Math.max(1000, 24000 - (Date.now() - startedAt));
  const response = spawnSync("grpcurl", [
    "-plaintext",
    "-H", "x-capability-sandbox-token: " + token,
    "-H", "x-octobus-capset: " + capset,
    "-H", "x-octobus-instance: " + instance,
    "-d", JSON.stringify(payload),
    target,
    method,
  ], {
    encoding: "utf8",
    timeout: remainingMs,
    maxBuffer: 1024 * 1024,
  });
  if (response.error) fail(method + " execution failed: " + response.error.message);
  if (response.status !== 0) {
    fail(method + " returned exit code " + response.status + ": " + String(response.stderr || "").trim());
  }
  try {
    return JSON.parse(String(response.stdout || "").trim() || "{}");
  } catch {
    fail(method + " returned invalid JSON");
  }
}

try {
  const listed = callCapability(
    "wazuh-indexer",
    "wazuh.connector.v1.WazuhConnectorService/ListAlerts",
    { lookbackSeconds: 900, limit: 20 }
  );
  const alerts = Array.isArray(listed.alerts) ? listed.alerts : [];
  let ingested = 0;
  let duplicates = 0;
  for (const alert of alerts) {
    const alertId = String(alert.alertId || "").trim();
    if (!alertId) fail("ListAlerts returned an alert without alertId");
    const accepted = callCapability(
      "security-ops-main",
      "security.ops.v1.SecurityOpsService/IngestAlertEvent",
      {
        eventId: "wazuh:" + alertId,
        wazuhAlertId: alertId,
        correlationId: String(alert.correlationId || ""),
        occurredAt: String(alert.occurredAt || ""),
        alertJson: String(alert.alertJson || ""),
      }
    );
    if (accepted.duplicate === true) duplicates += 1;
    else if (accepted.status === "pending") ingested += 1;
    else fail("IngestAlertEvent returned an unexpected status");
  }
  const recovery = callCapability(
    "security-ops-main",
    "security.ops.v1.SecurityOpsService/RequeueStalledAlerts",
    {}
  );
  process.stdout.write(JSON.stringify({
    success: true,
    polled: alerts.length,
    ingested,
    duplicates,
    requeued: Number(recovery.requeued || 0),
    manualized: Number(recovery.manualized || 0),
    durationMs: Date.now() - startedAt,
  }));
} catch (error) {
  process.stderr.write(String(error && error.message ? error.message : error));
  process.exitCode = 1;
}
`;

function parseIntakeResult(commandResult) {
  if (!commandResult || commandResult.success !== true || commandResult.exitCode !== 0) {
    throw new Error("deterministic intake command failed");
  }
  let result;
  try {
    result = JSON.parse(String(commandResult.stdout ?? "").trim());
  } catch {
    throw new Error("deterministic intake result is not valid JSON");
  }
  if (!result || Array.isArray(result) || typeof result !== "object") {
    throw new Error("deterministic intake result must be an object");
  }
  const keys = Object.keys(result).sort();
  if (keys.length !== intakeResultKeys.length || keys.some((key, index) => key !== intakeResultKeys[index])) {
    throw new Error("deterministic intake result fields do not match the contract");
  }
  if (result.success !== true) throw new Error("deterministic intake reported failure");
  for (const field of ["polled", "ingested", "duplicates", "requeued", "manualized", "durationMs"]) {
    if (!Number.isInteger(result[field]) || result[field] < 0) {
      throw new Error("deterministic intake counter is invalid: " + field);
    }
  }
  if (result.ingested + result.duplicates !== result.polled) {
    throw new Error("deterministic intake counters are inconsistent");
  }
  return result;
}

function runIntake() {
  const commandResult = scheduler.exec({
    command: "node",
    args: ["-e", deterministicIntakeProgram],
    timeoutMs: 25000,
    maxOutputBytes: 1024 * 1024,
    sandboxPolicy: "sticky",
    title: "Wazuh deterministic intake",
  });
  const result = parseIntakeResult(commandResult);
  scheduler.log("Wazuh deterministic intake completed", result);
  return result;
}

function main(payload) {
  if (!payload || Array.isArray(payload) || typeof payload !== "object") {
    throw new Error("unsupported intake payload");
  }
  const keys = Object.keys(payload);
  if (keys.length !== 1 || keys[0] !== "mode" || payload.mode !== "cycle") {
    throw new Error("unsupported intake payload");
  }
  return runIntake();
}

scheduler.cron("wazuh-intake", "* * * * *", function wazuhIntake() {
  return runIntake();
}, { timezone: "Asia/Shanghai" });
