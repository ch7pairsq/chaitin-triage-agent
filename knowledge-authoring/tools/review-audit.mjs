import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reviewPath = path.join(ROOT, "reviews.json");

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function expectedComment(knowledge) {
  return `结构、分类映射、Wazuh 可观察性和证据门检查完成；人工批准前重点确认：${knowledge.reviewFocus}；领域范围：${knowledge.domainFocus}。`;
}

export function auditReviews({ write = false } = {}) {
  const knowledge = readdirSync(path.join(ROOT, "knowledge"))
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => readJson(path.join(ROOT, "knowledge", file)));
  const document = readJson(reviewPath);
  const existing = new Map((document.reviews ?? []).map((review) => [review.knowledgeId, review]));
  const errors = [];
  const reviews = knowledge.map((item) => {
    const review = existing.get(item.knowledgeId);
    if (!review) errors.push(`${item.knowledgeId}: review record missing`);
    const expected = expectedComment(item);
    if (!write && review?.reviewComment !== expected) errors.push(`${item.knowledgeId}: review comment is stale or missing`);
    return {
      knowledgeId: item.knowledgeId,
      reviewStatus: review?.reviewStatus ?? "draft",
      reviewedBy: review?.reviewedBy ?? null,
      reviewedAt: review?.reviewedAt ?? null,
      reviewMarker: review?.reviewMarker ?? null,
      reviewComment: expected,
      checkedFields: [
        "domain_and_attack_mapping",
        "asset_protocol_scope",
        "wazuh_observability",
        "independent_evidence_gate",
        "counterexample_and_failure_boundaries"
      ]
    };
  });
  for (const id of existing.keys()) {
    if (!knowledge.some((item) => item.knowledgeId === id)) errors.push(`${id}: orphan review record`);
  }
  if (write) {
    writeFileSync(reviewPath, `${JSON.stringify({ version: document.version, reviews }, null, 2)}\n`);
  }
  return { count: reviews.length, errors };
}

const write = process.argv.includes("--write");
const result = auditReviews({ write });
if (result.errors.length) {
  for (const error of result.errors) process.stderr.write(`${error}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`${JSON.stringify({ reviews: result.count, mode: write ? "write" : "check" })}\n`);
}
