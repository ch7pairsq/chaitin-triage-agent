import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_WAZUH_DOCUMENT_ID_BYTES = 512;

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
    minimumRuleLevel = 0,
    requiredRuleGroup = "triage_input",
    requestTimeoutMs = 8_000,
    caPath = "",
    maxAlertBytes = 262_144,
    now = () => new Date(),
    requestImpl = nodeRequestJson,
    sleepImpl = (delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)),
    random = Math.random
  }) {
    this.baseUrl = normalizeBaseUrl(indexerUrl);
    this.username = requiredSecret(username, "indexer_username");
    this.password = requiredSecret(password, "indexer_password");
    this.indexPattern = normalizeIndexPattern(indexPattern);
    this.minimumRuleLevel = boundedInteger(minimumRuleLevel, 0, 16, "minimum_rule_level");
    this.requiredRuleGroup = normalizeRuleGroup(requiredRuleGroup);
    this.requestTimeoutMs = boundedInteger(requestTimeoutMs, 1000, 8_000, "request_timeout_ms");
    this.maxAlertBytes = boundedInteger(maxAlertBytes, 1024, 524_288, "max_alert_bytes");
    this.ca = caPath ? readFileSync(caPath) : undefined;
    this.now = now;
    this.requestImpl = requestImpl;
    this.sleepImpl = sleepImpl;
    this.random = random;
    this.lastSuccessfulQueryAt = null;
  }

  async listAlerts(request = {}) {
    const lookbackSeconds = boundedInteger(request.lookbackSeconds ?? 900, 60, 86_400, "lookbackSeconds");
    const limit = boundedInteger(request.limit ?? 20, 1, 100, "limit");
    const queriedAt = this.now();
    const start = new Date(queriedAt.getTime() - lookbackSeconds * 1000).toISOString();
    const filters = [
      { range: { timestamp: { gte: start, lte: queriedAt.toISOString() } } },
      { range: { "rule.level": { gte: this.minimumRuleLevel } } }
    ];
    if (this.requiredRuleGroup) filters.push({ term: { "rule.groups": this.requiredRuleGroup } });
    const body = {
      size: limit,
      track_total_hits: false,
      query: {
        bool: {
          filter: filters
        }
      },
      sort: [{ timestamp: { order: "desc", unmapped_type: "date" } }]
    };
    const payload = await this.#requestJson(`/${this.indexPattern}/_search`, body);
    const hits = payload?.hits?.hits;
    if (!Array.isArray(hits)) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer returned an invalid search response");
    }
    const alerts = hits.map((hit) => this.#normalizeHit(hit));
    this.lastSuccessfulQueryAt = queriedAt.toISOString();
    return {
      alerts,
      queriedAt: queriedAt.toISOString()
    };
  }

  #normalizeHit(hit) {
    const documentId = String(hit?._id ?? "");
    if (!documentId || Buffer.byteLength(documentId) > MAX_WAZUH_DOCUMENT_ID_BYTES) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert has a missing or oversized _id");
    }
    const alertId = normalizeAlertId(documentId);
    const source = hit?._source;
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert is missing _source", { alertId });
    }
    const occurredAt = new Date(source.timestamp);
    if (Number.isNaN(occurredAt.getTime())) {
      throw new WazuhConnectorError("UNAVAILABLE", "Wazuh alert timestamp is invalid", { alertId });
    }
    const alertJson = JSON.stringify(alertId === documentId ? source : {
      ...source,
      _triage_source: {
        wazuh_document_id: documentId,
        wazuh_index: String(hit?._index ?? "")
      }
    });
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
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        return await this.requestImpl({
          url,
          body: payload,
          timeoutMs: this.requestTimeoutMs,
          username: this.username,
          password: this.password,
          ca: this.ca
        });
      } catch (error) {
        const normalized = error instanceof WazuhConnectorError
          ? error
          : new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer request failed", { cause: error?.message ?? "unknown error" });
        if (attempt === 2 || !isRetryable(normalized)) throw normalized;
        const delayMs = 100 + Math.floor(Math.max(0, Math.min(1, this.random())) * 150);
        await this.sleepImpl(delayMs);
      }
    }
    throw new WazuhConnectorError("UNAVAILABLE", "Wazuh Indexer request exhausted retries");
  }
}

function normalizeAlertId(documentId) {
  if (ID_PATTERN.test(documentId)) return documentId;
  return `wazuh-${createHash("sha256").update(documentId, "utf8").digest("hex")}`;
}

function nodeRequestJson({ url, body, timeoutMs, username, password, ca }) {
  const transport = url.protocol === "https:" ? https : http;
  const options = {
    method: "POST",
    hostname: url.hostname,
    port: url.port || undefined,
    path: url.pathname + url.search,
    timeout: timeoutMs,
    headers: {
      accept: "application/json",
      authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body)
    },
    ca,
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
        const status = res.statusCode ?? 500;
        if (status < 200 || status >= 300) {
          const code = status === 401 || status === 403
            ? "UNAUTHENTICATED"
            : status >= 400 && status < 500 && status !== 429
              ? "INVALID_ARGUMENT"
              : "UNAVAILABLE";
          reject(new WazuhConnectorError(code, `Wazuh Indexer request failed with HTTP ${status}`, { httpStatus: status }));
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
    req.end(body);
  });
}

function isRetryable(error) {
  const status = Number(error.details?.httpStatus ?? 0);
  return error.code === "DEADLINE_EXCEEDED" || status === 429 || status >= 500;
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

function normalizeRuleGroup(value) {
  const normalized = String(value ?? "").trim();
  if (normalized && !/^[A-Za-z0-9_.-]{1,128}$/.test(normalized)) {
    throw new WazuhConnectorError("INVALID_ARGUMENT", "required_rule_group is invalid");
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
