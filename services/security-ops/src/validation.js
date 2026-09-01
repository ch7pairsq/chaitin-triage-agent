import { invalidArgument } from "./errors.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_ALERT_BYTES = 512 * 1024;

function requiredIdentifier(value, field) {
  const normalized = String(value ?? "").trim();
  if (!SAFE_IDENTIFIER.test(normalized)) {
    throw invalidArgument(`${field} must be a safe non-empty identifier`, { field });
  }
  return normalized;
}

function optionalIdentifier(value, field, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  return requiredIdentifier(value, field);
}

function requiredIsoTimestamp(value, field) {
  const normalized = String(value ?? "").trim();
  if (!normalized || Number.isNaN(Date.parse(normalized))) {
    throw invalidArgument(`${field} must be an ISO-8601 timestamp`, { field });
  }
  return new Date(normalized).toISOString();
}

function normalizeAlertPayload(value) {
  let payload = value;
  if (typeof payload === "string") {
    try {
      payload = JSON.parse(payload);
    } catch {
      throw invalidArgument("alertJson must contain valid JSON", { field: "alertJson" });
    }
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw invalidArgument("alertJson must describe a JSON object", { field: "alertJson" });
  }
  const json = JSON.stringify(payload);
  if (Buffer.byteLength(json, "utf8") > MAX_ALERT_BYTES) {
    throw invalidArgument("alertJson exceeds the 512 KiB limit", { field: "alertJson" });
  }
  return { payload, json };
}

export function normalizeIngestAlertEvent(input, { eventIdFactory, now = new Date() } = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw invalidArgument("IngestAlertEvent request must be an object");
  }
  const wazuhAlertId = requiredIdentifier(input.wazuhAlertId, "wazuhAlertId");
  const eventId = optionalIdentifier(input.eventId, "eventId", eventIdFactory?.());
  if (!eventId) throw invalidArgument("eventId is required when no eventIdFactory is configured", { field: "eventId" });
  const correlationId = optionalIdentifier(input.correlationId, "correlationId", wazuhAlertId);
  const occurredAt = input.occurredAt
    ? requiredIsoTimestamp(input.occurredAt, "occurredAt")
    : now.toISOString();
  const { payload, json } = normalizeAlertPayload(input.alertJson ?? input.alert);
  return { eventId, wazuhAlertId, correlationId, occurredAt, alert: payload, alertJson: json };
}

export function normalizeLimit(value, { fallback = 20, maximum = 100 } = {}) {
  if (value === undefined || value === null || value === "") return fallback;
  const limit = Number(value);
  if (!Number.isInteger(limit) || limit < 1 || limit > maximum) {
    throw invalidArgument(`limit must be an integer between 1 and ${maximum}`, { field: "limit" });
  }
  return limit;
}
