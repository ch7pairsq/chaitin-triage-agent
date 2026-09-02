import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
const service = JSON.parse(fs.readFileSync(path.join(packageRoot, "service.json"), "utf8"));
if (packageJson.bin?.[service.name] !== "src/runtime.js") {
  throw new Error(`package.json bin must expose service ${service.name} at src/runtime.js`);
}
const sdkCli = path.join(packageRoot, "node_modules", "@chaitin-ai", "octobus-sdk", "dist", "cli.js");
const descriptorPath = path.join(packageRoot, "proto", "descriptor.pb");
const result = spawnSync(process.execPath, [sdkCli, "validate"], {
  cwd: packageRoot,
  env: { ...process.env, OCTOBUS_DESCRIPTOR_PATH: descriptorPath },
  stdio: "inherit"
});
process.exitCode = result.status ?? 1;
