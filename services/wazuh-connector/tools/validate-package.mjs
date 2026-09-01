import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sdkCli = path.join(packageRoot, "node_modules", "@chaitin-ai", "octobus-sdk", "dist", "cli.js");
const descriptorPath = path.join(packageRoot, "proto", "descriptor.pb");
const result = spawnSync(process.execPath, [sdkCli, "validate"], {
  cwd: packageRoot,
  env: { ...process.env, OCTOBUS_DESCRIPTOR_PATH: descriptorPath },
  stdio: "inherit"
});
process.exitCode = result.status ?? 1;
