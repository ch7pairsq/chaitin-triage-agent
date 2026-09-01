import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { normalizeDelivery, verifySignature, WebhookError } from "../src/github.js";

const secret = "github-webhook-secret-with-at-least-32-characters";
const payload = Buffer.from(JSON.stringify({
  ref: "refs/heads/develop",
  after: "a".repeat(40),
  deleted: false,
  repository: { full_name: "owner/chaitin-triage-agent" }
}));
const signature = `sha256=${crypto.createHmac("sha256", secret).update(payload).digest("hex")}`;

test("validates the raw body signature and creates a bounded deployment request", () => {
  const result = normalizeDelivery({
    rawBody: payload,
    headers: { "x-hub-signature-256": signature, "x-github-delivery": "delivery-1", "x-github-event": "push" },
    secret,
    repository: "owner/chaitin-triage-agent",
    branch: "develop"
  });
  assert.equal(result.kind, "deployment");
  assert.equal(result.commitSha, "a".repeat(40));
  assert.equal(result.phase, "queued");
  assert.equal("payload" in result, false);
});

test("rejects body mutation and an unexpected repository", () => {
  assert.equal(verifySignature(Buffer.from(`${payload} `), signature, secret), false);
  assert.throws(() => normalizeDelivery({
    rawBody: payload,
    headers: { "x-hub-signature-256": signature, "x-github-delivery": "delivery-2", "x-github-event": "push" },
    secret,
    repository: "other/repository",
    branch: "develop"
  }), (error) => error instanceof WebhookError && error.statusCode === 403);
});

test("ignores other branches and rejects a deleted branch", () => {
  const other = Buffer.from(JSON.stringify({ ...JSON.parse(payload), ref: "refs/heads/main" }));
  const otherSignature = `sha256=${crypto.createHmac("sha256", secret).update(other).digest("hex")}`;
  assert.equal(normalizeDelivery({ rawBody: other, headers: { "x-hub-signature-256": otherSignature, "x-github-delivery": "delivery-3", "x-github-event": "push" }, secret, repository: "owner/chaitin-triage-agent", branch: "develop" }).kind, "ignored");

  const deleted = Buffer.from(JSON.stringify({ ...JSON.parse(payload), deleted: true }));
  const deletedSignature = `sha256=${crypto.createHmac("sha256", secret).update(deleted).digest("hex")}`;
  assert.throws(() => normalizeDelivery({ rawBody: deleted, headers: { "x-hub-signature-256": deletedSignature, "x-github-delivery": "delivery-4", "x-github-event": "push" }, secret, repository: "owner/chaitin-triage-agent", branch: "develop" }), WebhookError);
});
