import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { validateKnowledgeRepository } from "../tools/validate.mjs";
import { buildRuntimeKnowledge } from "../tools/build-runtime.mjs";
import { KnowledgeRepository } from "../../services/security-ops/src/knowledge-repository.js";
import { decideKnowledgePolicy } from "../../services/security-ops/src/knowledge-policy.js";
import { evaluateKnowledgeRule } from "../../services/security-ops/src/knowledge-rule-engine.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readJsonFiles(directory) {
  return readdirSync(path.join(ROOT, directory)).filter((file) => file.endsWith(".json"))
    .sort().map((file) => JSON.parse(readFileSync(path.join(ROOT, directory, file), "utf8")));
}

test("three-domain knowledge and test fixtures satisfy the publication contract", () => {
  const result = validateKnowledgeRepository();
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, { domains: 3, attackTypes: 33, knowledge: 99, fixtures: 396, sources: 12 });
});

test("all 396 boundary cases execute the same rules that SecurityOps publishes", () => {
  const knowledge = readJsonFiles("knowledge");
  const fixtures = readJsonFiles("test-fixtures").flat();
  const byId = new Map(knowledge.map((item) => [item.knowledgeId, item]));
  for (const fixture of fixtures) {
    const record = byId.get(fixture.knowledgeId);
    const evaluation = evaluateKnowledgeRule(record.executableRule, fixture.input.context);
    assert.equal(evaluation.outcome, fixture.expected.outcome, fixture.fixtureId);
    const policy = decideKnowledgePolicy({ records: [record], evaluation: [{ knowledgeId: record.knowledgeId, ...evaluation }] });
    assert.equal(policy.action, fixture.expected.action, fixture.fixtureId);
  }
});

test("removing operational knowledge measurably removes the confirmed match", () => {
  const record = readJsonFiles("knowledge").find((item) => item.knowledgeId === "kb-vehicle_platform-brute_force");
  const fixture = readJsonFiles("test-fixtures").flat().find((item) => item.fixtureId === `${record.knowledgeId}-confirmed-attack`);
  const withKnowledge = new KnowledgeRepository([record]).match({
    domainId: record.domainId,
    attackTypeId: record.attackTypeId,
    context: fixture.input.context
  });
  const withoutKnowledge = new KnowledgeRepository([]).match({
    domainId: record.domainId,
    attackTypeId: record.attackTypeId,
    context: fixture.input.context
  });
  assert.equal(withKnowledge[0].evaluation.outcome, "confirmed");
  assert.deepEqual(withoutKnowledge, []);
});

test("event facts override an incorrect attack type hint", () => {
  const knowledge = readJsonFiles("knowledge").filter((item) => item.domainId === "vehicle_platform");
  const bruteForce = knowledge.find((item) => item.attackTypeId === "brute_force");
  const fixture = readJsonFiles("test-fixtures").flat().find((item) => item.fixtureId === `${bruteForce.knowledgeId}-confirmed-attack`);
  const matches = new KnowledgeRepository(knowledge).match({
    domainId: "vehicle_platform",
    attackTypeId: "xss",
    context: fixture.input.context
  });
  assert.equal(matches[0].knowledgeId, bruteForce.knowledgeId);
  assert.equal(matches[0].evaluation.outcome, "confirmed");
});

test("exclusion and threshold boundaries prevent false positive escalation", () => {
  const record = readJsonFiles("knowledge").find((item) => item.knowledgeId === "kb-vehicle_platform-brute_force");
  const fixtures = readJsonFiles("test-fixtures").flat().filter((item) => item.knowledgeId === record.knowledgeId);
  const benign = fixtures.find((item) => item.scenarioType === "authorized_or_benign");
  assert.equal(evaluateKnowledgeRule(record.executableRule, benign.input.context).outcome, "excluded");
  const ruleWithoutExclusion = structuredClone(record.executableRule);
  ruleWithoutExclusion.excludeWhen.any = [];
  assert.equal(evaluateKnowledgeRule(ruleWithoutExclusion, benign.input.context).outcome, "confirmed");

  const belowBoundary = structuredClone(fixtures.find((item) => item.scenarioType === "confirmed_attack").input.context);
  const threshold = record.executableRule.confirmWhen.all.find((item) => item.predicateId === "failure-burst").value;
  belowBoundary.data.auth_failures = threshold - 1;
  assert.equal(evaluateKnowledgeRule(record.executableRule, belowBoundary).outcome, "not_matched");
});

test("runtime publication accepts exactly 99 approved records and rejects an incomplete approval set", () => {
  const published = buildRuntimeKnowledge();
  assert.equal(published.approved, 99);
  assert.doesNotMatch(published.body, /fixtureId|scenarioType/);
  assert.throws(
    () => buildRuntimeKnowledge({ requiredApproved: 100 }),
    /requires 100 approved records; found 99/
  );
});
