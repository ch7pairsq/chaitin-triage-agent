import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export class WazuhConnectorError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "WazuhConnectorError";
    this.code = code;
    this.details = details;
  }
}

export class WazuhIndexerClient {
  constructor({
    indexerUrl,
    username,
    password,
    indexPattern = "wazuh-alerts-*",
    minimumRuleLevel = 3,
    requestTimeoutMs = 10_000,
    caPath = "",
    maxAlertBytes = 262_144,
    now = () => new Date()
  }) {
    this.baseUrl = normalizeBaseUrl(indexerUrl);
    this.username = requiredSecret(username, "indexer_username");
    this.password = requiredSecret(password, "indexer_password");
    this.indexPattern = normalizeIndexPattern(indexPattern);
    this.minimumRuleLevel = boundedInteger(minimumRuleLevel, 0, 16, "minimum_rule_level");
    this.requestTimeoutMs = boundedInteger(requestTimeoutMs, 1000, 30_000, "request_timeout_ms");
    this.maxAlertBytes = boundedInteger(maxAlertBytes, 1024, 524_288, "max_alert_bytes");
    this.ca = caPath ? readFileSync(caPath) : undefined;
    this.now = now;
  }

  async listAlerts(request = {}) {
    const lookbackSeconds = boundedInteger(request.lookbackSeconds ?? 900, 60, 86_400, "lookbackSeconds");
    const limit = boundedInteger(request.limit ?? 20, 1, 100, "limit");
    const queriedAt = this.now();
    const start = new Date(queriedAt.getTime() - lookbackSeconds * 1000).toISOString();
    const body = {
      size: limit,
      track_total_hits: false,
      query: {
        bool: {
          filter: [
            { range: { timestamp: { gte: start, lte: queriedAt.toISOString() } } },
            { range: { "rule.level": { gte: this.minimumRuleLevel } } }
          ]
        }
      },
      sort: [{ timestamp: { order: "desc", unmapped_type: "date" } }]
    };
    const payload = await this.#requestJson(`/${this.indexPattern}/_search`, body);
    const hits = payload?.hits?.hits;
    if (!Array.isArray(hits)) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer returned an invalid search response");
    }
    return {
      alerts: hits.map((hit) => this.#normalizeHit(hit)),
      queriedAt: queriedAt.toISOString()
    };
  }

  #normalizeHit(hit) {
    const alertId = String(hit?._id ?? "").trim();
    if (!ID_PATTERN.test(alertId)) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert has an invalid _id");
    }
    const source = hit?._source;
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert is missing _source", { alertId });
    }
    const occurredAt = new Date(source.timestamp);
    if (Number.isNaN(occurredAt.getTime())) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert timestamp is invalid", { alertId });
    }
    const alertJson = JSON.stringify(source);
    if (Buffer.byteLength(alertJson) > this.maxAlertBytes) {
      throw new WazuhConnectorError("RESOURCE_EXHAUSTED", "Wazuh alert exceeds the configured size limit", { alertId });
    }
    return {
      alertId,
      occurredAt: occurredAt.toISOString(),
      correlationId: alertId,
      alertJson
    };
  }

  async #requestJson(pathname, body) {
    const url = new URL(pathname, this.baseUrl);
    const payload = JSON.stringify(body);
    const transport = url.protocol === "https:" ? https : http;
    const options = {
      method: "POST",
      hostname: url.hostname,
      port: url.port || undefined,
      path: url.pathname + url.search,
      timeout: this.requestTimeoutMs,
      headers: {
        accept: "application/json",
        authorization: `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload)
      },
      ca: this.ca,
      rejectUnauthorized: true
    };
    return new Promise((resolve, reject) => {
      const req = transport.request(options, (res) => {
        const chunks = [];
        let bytes = 0;
        res.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 2_097_152) {
            req.destroy(new WazuhConnectorError("RESOURCE_EXHAUSTED", "Wazuh response exceeds 2 MiB"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if ((res.statusCode ?? 500) < 200 || (res.statusCode ?? 500) >= 300) {
            reject(new WazuhConnectorError(
              res.statusCode === 401 || res.statusCode === 403 ? "UNAUTHENTICATED" : "UNAVAILABLE",
              `Wazuh Indexer request failed with HTTP ${res.statusCode}`
            ));
            return;
          }
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer returned invalid JSON"));
          }
        });
      });
      req.on("timeout", () => req.destroy(new WazuhConnectorError("DEADLINE_EXCEEDED", "Wazuh Indexer request timed out")));
      req.on("error", (error) => reject(error instanceof WazuhConnectorError
        ? error
        : new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer request failed", { cause: error.message })));
      req.end(payload);
    });
  }
}

function normalizeBaseUrl(value) {
  let url;
  try {
    url = new URL(String(value ?? ""));
  } catch {
    throw new WazuhConnectorError("INVALID_ARGUMENT", "indexer_url must be an absolute HTTP(S) URL");
  }
  if (!new Set(["http:", "https:"]).has(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new WazuhConnectorError("INVALID_ARGUMENT", "indexer_url must contain only scheme, host and optional port");
  }
  return url;
}

function normalizeIndexPattern(value) {
  const normalized = String(value ?? "").trim();
  if (!/^[A-Za-z0-9._*-]{1,128}$/.test(normalized) || normalized.includes("..")) {
    throw new WazuhConnectorError("INVALID_ARGUMENT", "index_pattern is invalid");
  }
  return normalized;
}

function requiredSecret(value, field) {
  const normalized = String(value ?? "");
  if (!normalized) throw new WazuhConnectorError("UNAUTHENTICATED", `${field} is required`);
  return normalized;
}

function boundedInteger(value, minimum, maximum, field) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw new WazuhConnectorError("INVALID_ARGUMENT", `${field} must be an integer between ${minimum} and ${maximum}`);
  }
  return number;
}
