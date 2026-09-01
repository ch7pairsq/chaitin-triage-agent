#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const secret = String(process.env.GITHUB_WEBHOOK_SECRET ?? "").trim();
if (secret.length < 32 || /[\r\n\0]/.test(secret)) throw new Error("GITHUB_WEBHOOK_SECRET must contain at least 32 single-line characters");
const outputDir = process.env.RELEASE_CONFIG_OUTPUT_DIR
  ? path.resolve(process.env.RELEASE_CONFIG_OUTPUT_DIR)
  : "/repo/deploy/stacks/release-webhook/generated";
fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
fs.chmodSync(outputDir, 0o700);
const target = path.join(outputDir, "github-webhook-secret");
fs.writeFileSync(target, `${secret}\n`, { encoding: "utf8", mode: 0o600 });
fs.chmodSync(target, 0o600);
console.log("release webhook private configuration rendered");
