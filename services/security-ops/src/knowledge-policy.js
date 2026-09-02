export function decideKnowledgePolicy({ records, evaluation, authorization = null, insufficientEvidence = false }) {
  if (!Array.isArray(records) || !Array.isArray(evaluation)) throw new TypeError("records and evaluation must be arrays");
  if (records.length === 0) return { decision: "manual_review", action: "manual_classification" };
  if (insufficientEvidence || evaluation.some((item) => item.outcome === "insufficient")) {
    return { decision: "manual_review", action: "request_additional_evidence" };
  }
  if (records.some((record) => record.attackTypeId === "other_attack")) {
    return { decision: "manual_review", action: "manual_classification" };
  }
  if (authorization || evaluation.some((item) => item.outcome === "excluded")) {
    return { decision: "needs_review", action: "suppress_with_manual_review" };
  }
  if (evaluation.some((item) => item.outcome === "confirmed")) {
    return { decision: "escalate", action: "escalate_with_manual_review" };
  }
  return { decision: "manual_review", action: "manual_classification" };
}
