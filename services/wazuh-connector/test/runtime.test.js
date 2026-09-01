import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("runtime exposes the ListAlerts unary method through the SDK CLI", () => {
  const result = spawnSync(process.execPath, ["src/runtime.js", "--help"], {
    cwd: packageRoot,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /list-alerts/);
});
