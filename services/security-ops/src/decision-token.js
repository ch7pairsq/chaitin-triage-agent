import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { failedPrecondition, invalidArgument } from "./errors.js";

const MINIMUM_SECRET_LENGTH = 32;

export function hashDecisionToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function issueDecisionToken(payload, { secret, now = () => new Date(), ttlMs = 15 * 60_000 } = {}) {
  assertSecret(secret);
  const issuedAt = now().toISOString();
  const expiresAt = new Date(now().getTime() + ttlMs).toISOString();
  const encoded = Buffer.from(JSON.stringify({ ...payload, issuedAt, expiresAt })).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

export function verifyDecisionToken(token, { secret, now = () => new Date() } = {}) {
  assertSecret(secret);
  const [encoded, signature, extra] = String(token ?? "").split(".");
  if (!encoded || !signature || extra) throw invalidArgument("decisionToken is malformed", { field: "decisionToken" });
  const expected = createHmac("sha256", secret).update(encoded).digest();
  let received;
  try {
    received = Buffer.from(signature, "base64url");
  } catch {
    throw invalidArgument("decisionToken signature is malformed", { field: "decisionToken" });
  }
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    throw failedPrecondition("decisionToken signature is invalid");
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw invalidArgument("decisionToken payload is invalid", { field: "decisionToken" });
  }
  if (!payload.expiresAt || Date.parse(payload.expiresAt) <= now().getTime()) {
    throw failedPrecondition("decisionToken has expired");
  }
  return payload;
}

function assertSecret(secret) {
  if (typeof secret !== "string" || secret.length < MINIMUM_SECRET_LENGTH) {
    throw new TypeError(`decision token secret must contain at least ${MINIMUM_SECRET_LENGTH} characters`);
  }
}
