#!/usr/bin/env node
import fs from "node:fs";

const token = fs.readFileSync("/run/secrets/triage-ops-token", "utf8").trim();
if (!token) throw new Error("triage operations token is empty");

const endpoint = "http://octobus:9000/capsets/triage-ops/connect/security-ops-main/security.ops.v1.SecurityOpsService/GetWorkerReadiness";
const response = await fetch(endpoint, {
  method: "POST",
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  body: "{}",
  signal: AbortSignal.timeout(10_000)
});
const text = await response.text();
if (!response.ok) throw new Error(`OctoBus readiness request returned HTTP ${response.status}: ${text.slice(0, 512)}`);
const readiness = JSON.parse(text);
if (readiness.ready !== true || readiness.acceptingWork !== true) {
  throw new Error(`SecurityOps worker is not ready: ${text.slice(0, 512)}`);
}
const normalized = { ...readiness };
for (const field of ["backlog", "manual", "oldestPendingAgeMs"]) {
  const value = Number(readiness[field] ?? 0);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`invalid readiness field: ${field}`);
  normalized[field] = value;
}
normalized.activeBatch = readiness.activeBatch ?? false;
if (typeof normalized.activeBatch !== "boolean") throw new Error("invalid readiness field: activeBatch");
if (readiness.lastErrorJson) JSON.parse(readiness.lastErrorJson);
console.log(JSON.stringify(normalized));
