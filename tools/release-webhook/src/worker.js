#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

const pollMs = 2000;

export function loadWorkerConfig(environment = process.env) {
  return {
    queueRoot: path.resolve(environment.RELEASE_QUEUE_ROOT ?? "/queue"),
    workspace: path.resolve(environment.RELEASE_WORKSPACE ?? "/workspace"),
    envFile: path.resolve(environment.RELEASE_ENV_FILE ?? "/run/secrets/deploy.env"),
    repository: required(environment, "GITHUB_REPOSITORY"),
    branch: required(environment, "RELEASE_DEPLOY_BRANCH")
  };
}

export async function runWorker(config = loadWorkerConfig()) {
  for (const name of ["inbox", "processing", "completed", "failed"]) fs.mkdirSync(path.join(config.queueRoot, name), { recursive: true, mode: 0o700 });
  recoverProcessing(config.queueRoot);
  console.log("release worker started");

  while (true) {
    const filename = nextInboxFile(config.queueRoot);
    if (!filename) {
      await delay(pollMs);
      continue;
    }
    const inbox = path.join(config.queueRoot, "inbox", filename);
    const processing = path.join(config.queueRoot, "processing", filename);
    try {
      fs.renameSync(inbox, processing);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    try {
      const request = readRequest(processing, config);
      const result = await deploy(request, processing, config);
      finish(processing, "completed", { ...request, ...result, completedAt: new Date().toISOString() }, config.queueRoot);
    } catch (error) {
      const request = safeRead(processing);
      finish(processing, "failed", { ...request, status: "failed", error: String(error.message).slice(0, 2000), failedAt: new Date().toISOString() }, config.queueRoot);
    }
  }
}

export async function deploy(request, requestPath, config = loadWorkerConfig()) {
  validateRequest(request, config);
  const currentBranch = (await run("git", ["-C", config.workspace, "branch", "--show-current"])).stdout.trim();
  if (currentBranch !== config.branch) throw new Error(`workspace branch ${currentBranch} does not match ${config.branch}`);
  const dirty = (await run("git", ["-C", config.workspace, "status", "--porcelain"])).stdout.trim();
  if (dirty) throw new Error("workspace has uncommitted or untracked files");
  const remote = (await run("git", ["-C", config.workspace, "remote", "get-url", "origin"])).stdout.trim();
  if (!allowedRemote(remote, config.repository)) throw new Error("origin does not match the configured GitHub repository");

  if (request.phase === "queued") {
    await run("git", ["-C", config.workspace, "fetch", "--prune", "origin", config.branch], { timeoutMs: 120000 });
    const remoteSha = (await run("git", ["-C", config.workspace, "rev-parse", `origin/${config.branch}`])).stdout.trim().toLowerCase();
    if (remoteSha !== request.commitSha) return { status: "superseded", remoteSha };
    await run("git", ["-C", config.workspace, "merge-base", "--is-ancestor", "HEAD", request.commitSha]);
    await run("git", ["-C", config.workspace, "merge", "--ff-only", request.commitSha], { timeoutMs: 120000 });
    request.phase = "checked-out";
    atomicWrite(requestPath, request);
  }

  if (request.phase === "checked-out") {
    await run("/bin/sh", [path.join(config.workspace, "deploy/stacks/triage-platform/prepare-config.sh")], { timeoutMs: 1200000 });
    await run("/bin/sh", [path.join(config.workspace, "deploy/stacks/wazuh/prepare-config.sh"), config.envFile], { timeoutMs: 1200000 });
    await compose(["-f", stack("wazuh", config), "up", "-d", "--build"], { timeoutMs: 1200000 }, config);
    await compose(["-f", stack("triage-platform", config), "up", "-d"], { timeoutMs: 1200000 }, config);
    await run("/bin/sh", [path.join(config.workspace, "deploy/stacks/triage-platform/bootstrap.sh")], { timeoutMs: 1200000 });
    request.phase = "platform-updated";
    atomicWrite(requestPath, request);
  }

  if (request.phase === "platform-updated") {
    request.phase = "release-updating";
    atomicWrite(requestPath, request);
    await compose(["-f", stack("release-webhook", config), "up", "-d", "--build"], { timeoutMs: 1200000 }, config);
  }

  await run("/bin/sh", [path.join(config.workspace, "deploy/stacks/triage-platform/verify.sh")], { timeoutMs: 300000 });
  return { status: "deployed", phase: "verified", commitSha: request.commitSha };
}

function compose(args, options, config) {
  return run("docker", ["compose", "--env-file", config.envFile, ...args], options);
}

function stack(name, config) {
  return path.join(config.workspace, `deploy/stacks/${name}/docker-compose.yml`);
}

export function allowedRemote(remote, expectedRepository) {
  const normalized = remote.replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "").replace(/\/$/, "").toLowerCase();
  return normalized === `https://github.com/${expectedRepository}`.toLowerCase();
}

export function validateRequest(request, config) {
  if (request.repository !== config.repository || request.branch !== config.branch || request.ref !== `refs/heads/${config.branch}`) throw new Error("deployment request scope mismatch");
  if (!/^[a-f0-9]{40}$/.test(request.commitSha)) throw new Error("deployment request SHA is invalid");
  if (!/^(queued|checked-out|platform-updated|release-updating)$/.test(request.phase)) throw new Error("deployment request phase is invalid");
}

function readRequest(filename, config) {
  const request = JSON.parse(fs.readFileSync(filename, "utf8"));
  validateRequest(request, config);
  return request;
}

function safeRead(filename) {
  try { return JSON.parse(fs.readFileSync(filename, "utf8")); } catch { return {}; }
}

function atomicWrite(filename, value) {
  const temporary = `${filename}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.renameSync(temporary, filename);
}

function finish(source, state, result, queueRoot) {
  atomicWrite(source, result);
  fs.renameSync(source, path.join(queueRoot, state, path.basename(source)));
}

function nextInboxFile(queueRoot) {
  return fs.readdirSync(path.join(queueRoot, "inbox")).filter((name) => /^[A-Za-z0-9._-]{1,128}\.json$/.test(name)).sort()[0];
}

function recoverProcessing(queueRoot) {
  for (const name of fs.readdirSync(path.join(queueRoot, "processing"))) {
    if (!/^[A-Za-z0-9._-]{1,128}\.json$/.test(name)) continue;
    fs.renameSync(path.join(queueRoot, "processing", name), path.join(queueRoot, "inbox", name));
  }
}

function run(command, args, { timeoutMs = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const collect = (current, chunk) => `${current}${chunk}`.slice(-65536);
    child.stdout.on("data", (chunk) => { stdout = collect(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = collect(stderr, chunk); });
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${command} failed (${signal ?? code}): ${stderr || stdout}`));
    });
  });
}

function required(environment, name) {
  const value = String(environment[name] ?? "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runWorker().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
