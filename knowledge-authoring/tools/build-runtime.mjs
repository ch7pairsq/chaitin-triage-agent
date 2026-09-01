import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function buildRuntimeKnowledge({ outputPath, requiredApproved = 99 } = {}) {
  const knowledge = readdirSync(path.join(ROOT, "knowledge"))
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => JSON.parse(readFileSync(path.join(ROOT, "knowledge", file), "utf8")));
  const approved = knowledge.filter((item) => item.reviewStatus === "approved");
  if (approved.length !== requiredApproved) {
    throw new Error(`runtime knowledge requires ${requiredApproved} approved records; found ${approved.length}`);
  }
  const body = approved.map((item) => JSON.stringify(item)).join("\n") + (approved.length ? "\n" : "");
  if (/"fixtureId"|"scenarioType"/.test(body)) throw new Error("test fixture fields must not enter runtime knowledge");
  if (outputPath) {
    mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
    writeFileSync(path.resolve(outputPath), body);
  }
  return { approved: approved.length, bytes: Buffer.byteLength(body), body };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outputIndex = process.argv.indexOf("--output");
  const outputPath = outputIndex >= 0 ? process.argv[outputIndex + 1] : null;
  if (!outputPath) throw new Error("--output is required");
  const result = buildRuntimeKnowledge({ outputPath });
  process.stdout.write(`${JSON.stringify({ approved: result.approved, bytes: result.bytes, outputPath: path.resolve(outputPath) })}\n`);
}
