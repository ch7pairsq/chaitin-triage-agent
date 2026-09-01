import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import { allowedRemote, loadWorkerConfig, validateRequest } from "../src/worker.js";

const config = {
  queueRoot: "/queue",
  workspace: "/workspace",
  envFile: "/run/secrets/deploy.env",
  repository: "owner/chaitin-triage-agent",
  branch: "develop"
};

test("worker accepts only the configured GitHub origin", () => {
  assert.equal(allowedRemote("https://github.com/owner/chaitin-triage-agent.git", config.repository), true);
  assert.equal(allowedRemote("git@github.com:owner/chaitin-triage-agent.git", config.repository), true);
  assert.equal(allowedRemote("https://github.com/other/chaitin-triage-agent.git", config.repository), false);
  assert.equal(allowedRemote("https://example.test/owner/chaitin-triage-agent.git", config.repository), false);
});

test("worker configuration is explicit and side-effect free when imported", () => {
  const loaded = loadWorkerConfig({
    RELEASE_QUEUE_ROOT: "/data/queue",
    RELEASE_WORKSPACE: "/data/workspace",
    RELEASE_ENV_FILE: "/run/deploy.env",
    GITHUB_REPOSITORY: config.repository,
    RELEASE_DEPLOY_BRANCH: config.branch
  });
  assert.deepEqual(loaded, {
    queueRoot: path.resolve("/data/queue"),
    workspace: path.resolve("/data/workspace"),
    envFile: path.resolve("/run/deploy.env"),
    repository: config.repository,
    branch: config.branch
  });
});

test("worker rejects cross-repository, cross-branch and invalid phase requests", () => {
  const valid = {
    repository: config.repository,
    branch: config.branch,
    ref: "refs/heads/develop",
    commitSha: "a".repeat(40),
    phase: "queued"
  };
  assert.doesNotThrow(() => validateRequest(valid, config));
  assert.throws(() => validateRequest({ ...valid, repository: "other/repository" }, config), /scope mismatch/);
  assert.throws(() => validateRequest({ ...valid, branch: "main", ref: "refs/heads/main" }, config), /scope mismatch/);
  assert.throws(() => validateRequest({ ...valid, phase: "verified" }, config), /phase is invalid/);
  assert.throws(() => validateRequest({ ...valid, commitSha: "not-a-sha" }, config), /SHA is invalid/);
});
