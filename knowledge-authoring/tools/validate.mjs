import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const taxonomy = JSON.parse(readFileSync(path.join(ROOT, "taxonomy.json"), "utf8"));

function readJsonFiles(directory) {
  return readdirSync(directory).filter((file) => file.endsWith(".json"))
    .sort().map((file) => JSON.parse(readFileSync(path.join(directory, file), "utf8")));
}

export function validateKnowledgeRepository() {
  const knowledge = readJsonFiles(path.join(ROOT, "knowledge"));
  const fixtureGroups = readJsonFiles(path.join(ROOT, "test-fixtures"));
  const fixtures = fixtureGroups.flat();
  const reviews = JSON.parse(readFileSync(path.join(ROOT, "reviews.json"), "utf8")).reviews ?? [];
  const errors = [];
  if (taxonomy.domains.length !== 3) errors.push(`expected 3 domains, got ${taxonomy.domains.length}`);
  if (taxonomy.attackTypes.length !== 33) errors.push(`expected 33 attack types, got ${taxonomy.attackTypes.length}`);
  if (knowledge.length !== 99) errors.push(`expected 99 knowledge records, got ${knowledge.length}`);
  if (fixtures.length !== 396) errors.push(`expected 396 test fixtures, got ${fixtures.length}`);
  if (reviews.length !== 99) errors.push(`expected 99 review records, got ${reviews.length}`);
  if (new Set(knowledge.map((item) => item.knowledgeId)).size !== knowledge.length) errors.push("knowledgeId values must be unique");
  if (new Set(fixtures.map((item) => item.fixtureId)).size !== fixtures.length) errors.push("fixtureId values must be unique");
  if (new Set(reviews.map((item) => item.knowledgeId)).size !== reviews.length) errors.push("review knowledgeId values must be unique");
  const domains = new Map(taxonomy.domains.map((domain) => [domain.domainId, domain]));
  const attackTypes = new Map(taxonomy.attackTypes.map((attack) => [attack.attackTypeId, attack]));
  const expectedPairs = new Set(taxonomy.domains.flatMap((domain) => taxonomy.attackTypes.map((attack) => `${domain.domainId}:${attack.attackTypeId}`)));
  const actualPairs = new Set(knowledge.map((item) => `${item.domainId}:${item.attackTypeId}`));
  if (actualPairs.size !== expectedPairs.size || [...expectedPairs].some((pair) => !actualPairs.has(pair))) errors.push("domain and attack type matrix is incomplete");
  for (const item of knowledge) {
    const domain = domains.get(item.domainId);
    const attack = attackTypes.get(item.attackTypeId);
    if (!domain || item.domainName !== domain.name) errors.push(`${item.knowledgeId}: invalid domain mapping`);
    if (!attack || item.attackTypeName !== attack.name) errors.push(`${item.knowledgeId}: invalid attack mapping`);
    if (!Array.isArray(item.assets) || item.assets.length < 2 || item.assets.some((asset) => !domain?.assets.includes(asset))) errors.push(`${item.knowledgeId}: invalid asset scope`);
    if (!Array.isArray(item.protocols) || item.protocols.length < 2 || item.protocols.some((protocol) => !domain?.protocols.includes(protocol))) errors.push(`${item.knowledgeId}: invalid protocol scope`);
    if (!item.domainFocus || !item.reviewFocus) errors.push(`${item.knowledgeId}: review focus missing`);
    if (item.provenance?.sourceClass !== "internal_security_operations_experience") errors.push(`${item.knowledgeId}: invalid provenance`);
    if (item.autoCloseAllowed !== false || item.ticketRequired !== true) errors.push(`${item.knowledgeId}: unsafe policy flags`);
    if (!Array.isArray(item.evidenceRequired) || item.evidenceRequired.length < 2) errors.push(`${item.knowledgeId}: insufficient evidence requirements`);
    if (item.evidencePolicy?.kind !== "minimum_independent_evidence" || item.evidencePolicy?.minimumIndependentEvidence !== 2 || item.evidencePolicy?.statisticalThreshold !== false) {
      errors.push(`${item.knowledgeId}: invalid evidence policy`);
    }
    if (!Array.isArray(item.counterexamples) || item.counterexamples.length < 2) errors.push(`${item.knowledgeId}: counterexamples missing`);
    if (!Array.isArray(item.bypassPoints) || item.bypassPoints.length < 2) errors.push(`${item.knowledgeId}: bypass points missing`);
    if (!["draft", "approved"].includes(item.reviewStatus)) errors.push(`${item.knowledgeId}: invalid review status`);
    const review = reviews.find((candidate) => candidate.knowledgeId === item.knowledgeId);
    if (!review || review.reviewStatus !== item.reviewStatus) errors.push(`${item.knowledgeId}: review registry mismatch`);
    if (item.reviewStatus === "approved" && (!item.reviewedBy || !item.reviewedAt || !item.reviewMarker)) errors.push(`${item.knowledgeId}: approval metadata missing`);
    if (review?.reviewStatus === "approved" && (!review.reviewedBy || !review.reviewedAt || !review.reviewMarker)) errors.push(`${item.knowledgeId}: review approval metadata missing`);
    if (review?.reviewStatus === "draft" && (review.reviewedBy || review.reviewedAt || review.reviewMarker)) errors.push(`${item.knowledgeId}: draft review must not carry approval identity`);
    if (!Array.isArray(review?.checkedFields) || review.checkedFields.length < 5) errors.push(`${item.knowledgeId}: review checks missing`);
  }
  for (const domain of taxonomy.domains) {
    const records = knowledge.filter((item) => item.domainId === domain.domainId);
    const signatures = new Set(records.map((item) => JSON.stringify({
      signal: item.observableSignals?.[0],
      evidence: item.evidenceRequired?.[0],
      counterexample: item.counterexamples?.[0],
      reviewFocus: item.reviewFocus
    })));
    if (signatures.size !== taxonomy.attackTypes.length) errors.push(`${domain.domainId}: attack-specific operational content is not unique`);
  }
  const grouped = Map.groupBy(fixtures, (item) => item.knowledgeId);
  for (const item of knowledge) {
    const group = grouped.get(item.knowledgeId) ?? [];
    if (group.length !== 4) errors.push(`${item.knowledgeId}: expected four fixtures`);
    if (group.some((entry) => entry.expected?.autoCloseAllowed !== false || entry.expected?.ticketRequired !== true)) {
      errors.push(`${item.knowledgeId}: unsafe fixture expectation`);
    }
  }
  return { errors, counts: { domains: taxonomy.domains.length, attackTypes: taxonomy.attackTypes.length, knowledge: knowledge.length, fixtures: fixtures.length } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = validateKnowledgeRepository();
  if (result.errors.length) {
    for (const error of result.errors) process.stderr.write(`${error}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`${JSON.stringify(result.counts)}\n`);
  }
}
