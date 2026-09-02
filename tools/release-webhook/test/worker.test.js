import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { allowedRemote, deploy, loadWorkerConfig, validateRequest } from "../src/worker.js";

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

test("worker delegates all deployment phases to the shared update script", async (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "release-worker-test-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const requestPath = path.join(temporary, "request.json");
  const request = {
    repository: config.repository,
    branch: config.branch,
    ref: "refs/heads/develop",
    commitSha: "a".repeat(40),
    phase: "checked-out",
  };
  fs.writeFileSync(requestPath, JSON.stringify(request));
  const calls = [];
  const execute = async (command, args) => {
    calls.push({ command, args });
    const joined = args.join(" ");
    if (joined.includes("branch --show-current")) return { stdout: "develop\n", stderr: "" };
    if (joined.includes("status --porcelain")) return { stdout: "", stderr: "" };
    if (joined.includes("remote get-url origin")) return { stdout: "https://github.com/owner/chaitin-triage-agent.git\n", stderr: "" };
    return { stdout: "", stderr: "" };
  };
  const result = await deploy(request, requestPath, { ...config, workspace: temporary }, execute);
  assert.equal(result.status, "deployed");
  const deploymentCalls = calls.filter((call) => call.command === "/bin/sh");
  assert.deepEqual(deploymentCalls.map((call) => call.args.slice(1, 5)), [
    ["--mode", "release-worker", "--phase", "platform"],
    ["--mode", "release-worker", "--phase", "release"],
    ["--mode", "release-worker", "--phase", "verify"],
  ]);
  assert.equal(calls.some((call) => call.command === "docker"), false);
  assert.equal(calls.some((call) => call.args.some((arg) => /prepare-config|bootstrap|verify\.sh/.test(arg))), false);
});
