import { readFileSync } from "node:fs";

import { invalidArgument } from "./errors.js";

export class KnowledgeRepository {
  constructor(records) {
    if (!Array.isArray(records)) throw new TypeError("knowledge records must be an array");
    this.records = records.filter((record) => record.reviewStatus === "approved");
    this.byId = new Map(this.records.map((record) => [record.knowledgeId, record]));
    if (this.byId.size !== this.records.length) throw new TypeError("knowledgeId values must be unique");
  }

  static fromJsonLines(filePath) {
    const body = readFileSync(filePath, "utf8");
    const records = body.split(/\r?\n/).filter(Boolean).map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new TypeError(`runtime knowledge line ${index + 1} is invalid JSON`);
      }
    });
    return new KnowledgeRepository(records);
  }

  get(knowledgeId) {
    return this.byId.get(knowledgeId) ?? null;
  }

  match({ domainId, attackTypeId, context = {} }) {
    const candidates = this.records.filter((record) =>
      record.domainId === domainId &&
      (record.attackTypeId === attackTypeId || record.aliases?.includes(attackTypeId))
    );
    const observed = new Set(normalizeStringArray(context.observedEvidence));
    return candidates.map((record) => {
      const missingEvidence = record.evidenceRequired.filter((item) => !observed.has(item));
      const evidenceRefs = normalizeStringArray(context.evidenceRefs);
      return {
        knowledgeId: record.knowledgeId,
        applicability: record.applicability,
        evidenceRefs,
        missingEvidence,
        wazuhObservability: record.wazuhMapping?.wazuhObservability ?? "partial",
        additionalTelemetryRequired: record.wazuhMapping?.additionalTelemetryRequired ?? [],
        ticketRequired: true,
        autoCloseAllowed: false
      };
    });
  }
}

export function parseContextJson(value, field = "contextJson") {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value ?? "{}"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    throw invalidArgument(`${field} must contain a JSON object`, { field });
  }
}

export function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
}
