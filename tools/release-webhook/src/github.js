import crypto from "node:crypto";

export class WebhookError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

export function verifySignature(rawBody, signatureHeader, secret) {
  if (!Buffer.isBuffer(rawBody)) throw new TypeError("rawBody must be a Buffer");
  if (typeof secret !== "string" || secret.length < 32) throw new Error("webhook secret must contain at least 32 characters");
  const match = /^sha256=([a-f0-9]{64})$/i.exec(String(signatureHeader ?? "").trim());
  if (!match) return false;
  const received = Buffer.from(match[1], "hex");
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return received.length === expected.length && crypto.timingSafeEqual(received, expected);
}

export function normalizeDelivery({ rawBody, headers, secret, repository, branch }) {
  if (!verifySignature(rawBody, headers["x-hub-signature-256"], secret)) {
    throw new WebhookError(401, "invalid signature");
  }
  const deliveryId = String(headers["x-github-delivery"] ?? "").trim();
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(deliveryId)) throw new WebhookError(400, "invalid delivery id");
  const event = String(headers["x-github-event"] ?? "").trim().toLowerCase();
  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    throw new WebhookError(400, "body must be valid JSON");
  }
  if (!payload || Array.isArray(payload) || typeof payload !== "object") throw new WebhookError(400, "body must be a JSON object");
  if (payload.repository?.full_name !== repository) throw new WebhookError(403, "repository is not allowed");
  if (event === "ping") return { kind: "ping", deliveryId };
  if (event !== "push") throw new WebhookError(202, "event ignored");
  const expectedRef = `refs/heads/${branch}`;
  if (payload.ref !== expectedRef) return { kind: "ignored", deliveryId, reason: "branch" };
  const commitSha = String(payload.after ?? "").toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(commitSha) || /^0+$/.test(commitSha)) throw new WebhookError(400, "invalid commit SHA");
  if (payload.deleted === true) throw new WebhookError(400, "deleted branches cannot deploy");
  return {
    kind: "deployment",
    deliveryId,
    repository,
    branch,
    ref: expectedRef,
    commitSha,
    receivedAt: new Date().toISOString(),
    phase: "queued"
  };
}
