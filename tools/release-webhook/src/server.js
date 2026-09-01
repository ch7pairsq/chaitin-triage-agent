#!/usr/bin/env node
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { normalizeDelivery, WebhookError } from "./github.js";

export function loadServerConfig(environment = process.env) {
  const repository = required(environment, "GITHUB_REPOSITORY", 3);
  const branch = required(environment, "RELEASE_DEPLOY_BRANCH", 1);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error("GITHUB_REPOSITORY must be owner/name");
  if (!/^[A-Za-z0-9._/-]+$/.test(branch) || branch.includes("..")) throw new Error("RELEASE_DEPLOY_BRANCH is invalid");
  return {
    port: boundedInteger(environment.PORT ?? "8080", 1, 65535, "PORT"),
    queueRoot: path.resolve(environment.RELEASE_QUEUE_ROOT ?? "/queue"),
    secret: readSecret(environment.GITHUB_WEBHOOK_SECRET_FILE ?? "/run/secrets/github-webhook-secret", 32),
    repository,
    branch
  };
}

export function createReleaseServer(config) {
  for (const name of ["inbox", "processing", "completed", "failed"]) {
    fs.mkdirSync(path.join(config.queueRoot, name), { recursive: true, mode: 0o700 });
  }
  const server = http.createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/healthz") return json(response, 200, { status: "ok" });
      if (request.method !== "POST" || request.url !== "/webhooks/github") return json(response, 404, { error: "not found" });
      if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
        return json(response, 415, { error: "application/json is required" });
      }
      const rawBody = await readBody(request, 1_048_576);
      const delivery = normalizeDelivery({
        rawBody,
        headers: request.headers,
        secret: config.secret,
        repository: config.repository,
        branch: config.branch
      });
      if (delivery.kind === "ping") return json(response, 200, { status: "pong", deliveryId: delivery.deliveryId });
      if (delivery.kind === "ignored") return json(response, 202, { status: "ignored", deliveryId: delivery.deliveryId });
      const queued = enqueue(config.queueRoot, delivery);
      return json(response, queued ? 202 : 200, { status: queued ? "queued" : "duplicate", deliveryId: delivery.deliveryId });
    } catch (error) {
      const status = error instanceof WebhookError ? error.statusCode : error?.code === "BODY_TOO_LARGE" ? 413 : 500;
      return json(response, status, { error: status === 500 ? "internal error" : error.message });
    }
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  return server;
}

export function runServer(config = loadServerConfig()) {
  const server = createReleaseServer(config);
  server.listen(config.port, "0.0.0.0", () => console.log(`release webhook listening on ${config.port}`));
  return server;
}

export function enqueue(root, delivery) {
  const filename = `${delivery.deliveryId}.json`;
  for (const state of ["inbox", "processing", "completed", "failed"]) {
    if (fs.existsSync(path.join(root, state, filename))) return false;
  }
  const target = path.join(root, "inbox", filename);
  try {
    fs.writeFileSync(target, `${JSON.stringify(delivery)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    return true;
  } catch (error) {
    if (error.code === "EEXIST") return false;
    throw error;
  }
}

async function readBody(request, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) {
      const error = new Error("request body is too large");
      error.code = "BODY_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function json(response, status, body) {
  const data = Buffer.from(JSON.stringify(body));
  response.writeHead(status, { "content-type": "application/json", "content-length": data.length, "cache-control": "no-store" });
  response.end(data);
}

function required(environment, name, minLength) {
  const value = String(environment[name] ?? "").trim();
  if (value.length < minLength) throw new Error(`${name} is missing`);
  return value;
}

function readSecret(filename, minLength) {
  const value = fs.readFileSync(path.resolve(filename), "utf8").trim();
  if (value.length < minLength || /[\r\n\0]/.test(value)) throw new Error("GitHub webhook secret file is invalid");
  return value;
}

function boundedInteger(value, minimum, maximum, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new Error(`${name} is invalid`);
  return number;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runServer();
}
