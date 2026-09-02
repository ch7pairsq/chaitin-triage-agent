import { readFileSync } from "node:fs";

import { invalidArgument } from "./errors.js";
import { evaluateKnowledgeRule, validateKnowledgeRule } from "./knowledge-rule-engine.js";

export class KnowledgeRepository {
  constructor(records) {
    if (!Array.isArray(records)) throw new TypeError("knowledge records must be an array");
    this.records = records.filter((record) => record.reviewStatus === "approved");
    for (const record of this.records) {
      try {
        validateKnowledgeRule(record.executableRule);
      } catch (error) {
        throw new TypeError(`${record.knowledgeId ?? "unknown knowledge"}: ${error.message}`, { cause: error });
      }
    }
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
    const candidates = this.records.filter((record) => record.domainId === domainId);
    const evaluated = candidates.map((record) => ({
      record,
      hinted: record.attackTypeId === attackTypeId || record.aliases?.includes(attackTypeId),
      evaluation: evaluateKnowledgeRule(record.executableRule, context)
    }));
    const confirmed = evaluated.filter((item) => item.evaluation.outcome === "confirmed");
    const selected = confirmed.length > 0 ? confirmed : evaluated.filter((item) => item.hinted);
    return selected
      .sort((left, right) => Number(right.hinted) - Number(left.hinted) || left.record.knowledgeId.localeCompare(right.record.knowledgeId))
      .map(({ record, evaluation }) => {
        const evidenceRefs = normalizeStringArray(context.evidenceRefs);
        return {
          knowledgeId: record.knowledgeId,
          applicability: record.applicability,
          evidenceRefs,
          missingEvidence: evaluation.missingFacts,
          evaluation,
          evaluationJson: JSON.stringify(evaluation),
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
