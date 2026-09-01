import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createReleaseServer, loadServerConfig } from "../src/server.js";

const repository = "owner/chaitin-triage-agent";
const branch = "develop";
const secret = "github-webhook-secret-with-at-least-32-characters";

test("server loads its HMAC secret from a file", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-server-config-"));
  try {
    const secretFile = path.join(directory, "secret");
    fs.writeFileSync(secretFile, `${secret}\n`, { mode: 0o600 });
    const config = loadServerConfig({
      PORT: "9080",
      RELEASE_QUEUE_ROOT: path.join(directory, "queue"),
      GITHUB_WEBHOOK_SECRET_FILE: secretFile,
      GITHUB_REPOSITORY: repository,
      RELEASE_DEPLOY_BRANCH: branch
    });
    assert.equal(config.secret, secret);
    assert.equal(config.repository, repository);
    assert.equal(config.branch, branch);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("HTTP receiver verifies the raw body, queues once and deduplicates delivery id", async () => {
  const queueRoot = fs.mkdtempSync(path.join(os.tmpdir(), "release-server-queue-"));
  const server = createReleaseServer({ port: 0, queueRoot, secret, repository, branch });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    const rawBody = Buffer.from(JSON.stringify({
      ref: "refs/heads/develop",
      after: "b".repeat(40),
      deleted: false,
      repository: { full_name: repository }
    }));
    const signature = `sha256=${crypto.createHmac("sha256", secret).update(rawBody).digest("hex")}`;
    const send = () => fetch(`http://127.0.0.1:${address.port}/webhooks/github`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "push",
        "x-github-delivery": "delivery-http-1",
        "x-hub-signature-256": signature
      },
      body: rawBody
    });

    const first = await send();
    assert.equal(first.status, 202);
    assert.equal((await first.json()).status, "queued");
    const queued = JSON.parse(fs.readFileSync(path.join(queueRoot, "inbox", "delivery-http-1.json"), "utf8"));
    assert.equal(queued.commitSha, "b".repeat(40));
    assert.equal("payload" in queued, false);

    const duplicate = await send();
    assert.equal(duplicate.status, 200);
    assert.equal((await duplicate.json()).status, "duplicate");
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(queueRoot, { recursive: true, force: true });
  }
});
