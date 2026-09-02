import { invalidArgument } from "./errors.js";

const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CLAIM_TOKEN = /^[A-Za-z0-9_-]{43,128}$/;
const MAX_ALERT_BYTES = 512 * 1024;
const AUTHORIZATION_STATUSES = new Set(["active", "revoked"]);
const AUTHORIZATION_SCOPES = new Set(["asset", "account", "rule", "change_window"]);

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

export function normalizeClaimToken(value) {
  const token = String(value ?? "").trim();
  if (!CLAIM_TOKEN.test(token)) {
    throw invalidArgument("claimToken must be a base64url value between 43 and 128 characters", { field: "claimToken" });
  }
  return token;
}

export function normalizeRequeueStalledAlerts(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw invalidArgument("RequeueStalledAlerts request must be an object");
  }
  if (Object.keys(input).length > 0) {
    throw invalidArgument("RequeueStalledAlerts does not accept caller policy overrides");
  }
  return {};
}

export function normalizePutAuthorizationRecord(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw invalidArgument("PutAuthorizationRecord request must be an object");
  }
  const authorizationId = requiredIdentifier(input.authorizationId, "authorizationId");
  const status = String(input.status ?? "").trim();
  if (!AUTHORIZATION_STATUSES.has(status)) {
    throw invalidArgument("status must be active or revoked", { field: "status" });
  }
  const scopeType = String(input.scopeType ?? "").trim();
  if (!AUTHORIZATION_SCOPES.has(scopeType)) {
    throw invalidArgument("scopeType is invalid", { field: "scopeType" });
  }
  const scopeValue = String(input.scopeValue ?? "").trim();
  if (!scopeValue || scopeValue.length > 256) {
    throw invalidArgument("scopeValue must contain between 1 and 256 characters", { field: "scopeValue" });
  }
  const validFrom = requiredIsoTimestamp(input.validFrom, "validFrom");
  const validUntil = requiredIsoTimestamp(input.validUntil, "validUntil");
  if (Date.parse(validFrom) >= Date.parse(validUntil)) {
    throw invalidArgument("validUntil must be later than validFrom", { field: "validUntil" });
  }
  if (!Array.isArray(input.evidenceRefs)) {
    throw invalidArgument("evidenceRefs must be an array", { field: "evidenceRefs" });
  }
  const evidenceRefs = [...new Set(input.evidenceRefs.map((value) => String(value ?? "").trim()).filter(Boolean))];
  if (evidenceRefs.length === 0 || evidenceRefs.length > 50 || evidenceRefs.some((value) => value.length > 256)) {
    throw invalidArgument("evidenceRefs must contain between 1 and 50 bounded values", { field: "evidenceRefs" });
  }
  return { authorizationId, status, scopeType, scopeValue, validFrom, validUntil, evidenceRefs };
}
