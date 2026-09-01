import test from "node:test";
import assert from "node:assert/strict";

import { validateKnowledgeRepository } from "../tools/validate.mjs";
import { buildRuntimeKnowledge } from "../tools/build-runtime.mjs";

test("three-domain knowledge and test fixtures satisfy the publication contract", () => {
  const result = validateKnowledgeRepository();
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.counts, { domains: 3, attackTypes: 33, knowledge: 99, fixtures: 396 });
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
