import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const sourceScript = path.join(root, "deploy/update-stacks.sh");
const updateScript = readFileSync(sourceScript, "utf8");
const releaseCompose = readFileSync(path.join(root, "deploy/stacks/release-webhook/docker-compose.yml"), "utf8");
const readinessVerifier = readFileSync(path.join(root, "deploy/stacks/triage-platform/tools/verify-readiness.mjs"), "utf8");

test("readiness verification normalizes omitted Proto JSON defaults", () => {
  assert.match(readinessVerifier, /readiness\.activeBatch \?\? false/);
  assert.match(readinessVerifier, /readiness\[field\] \?\? 0/);
});

test("all update paths use the dedicated backup root outside business data", () => {
  assert.match(updateScript, /UPDATE_STACKS_BACKUP_ROOT:-\/data\/chaitin_backup\/chaitin-triage-agent/);
  assert.doesNotMatch(updateScript, /\/data\/chaitin\/backups/);
  assert.match(releaseCompose, /UPDATE_STACKS_BACKUP_ROOT: \/host-backup\/chaitin-triage-agent/);
  assert.match(releaseCompose, /- \/data\/chaitin_backup:\/host-backup/);
  assert.doesNotMatch(releaseCompose, /host-data\/chaitin\/backups/);
});

function shellExecutable() {
  if (process.platform !== "win32") return "/bin/sh";
  const candidates = [
    "D:/Program Files (x86)/Git/bin/bash.exe",
    "C:/Program Files/Git/bin/bash.exe",
  ];
  return candidates.find(existsSync) ?? null;
}

function toShellPath(value) {
  if (process.platform !== "win32") return value;
  const normalized = value.replaceAll("\\", "/");
  const match = normalized.match(/^([A-Za-z]):(\/.*)$/);
  return match ? `/${match[1].toLowerCase()}${match[2]}` : normalized;
}

function makeFixture() {
  const fixtureRoot = path.join(root, ".tmp");
  mkdirSync(fixtureRoot, { recursive: true });
  const fixture = mkdtempSync(path.join(fixtureRoot, "triage-update-stacks-"));
  const put = (relative, content = "placeholder\n") => {
    const target = path.join(fixture, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  };
  put(".env", "REPO_ROOT=/srv/chaitin-triage-agent\nRELEASE_DEPLOY_BRANCH=develop\n");
  put("agent-compose.yml", "name: chaitin-triage-agent\n");
  put("services/security-ops/resources/knowledge.jsonl", "{}\n");
  for (const file of [
    "deploy/stacks/wazuh/docker-compose.yml",
    "deploy/stacks/wazuh/generate-indexer-certs.yml",
    "deploy/stacks/triage-platform/docker-compose.yml",
    "deploy/stacks/release-webhook/docker-compose.yml",
  ]) put(file, "services: {}\n");
  for (const file of [
    "deploy/stacks/wazuh/prepare-config.sh",
    "deploy/stacks/triage-platform/prepare-config.sh",
    "deploy/stacks/triage-platform/bootstrap.sh",
    "deploy/stacks/triage-platform/verify.sh",
    "deploy/stacks/triage-platform/verify-e2e.sh",
    "deploy/stacks/release-webhook/prepare-config.sh",
  ]) put(file, "#!/bin/sh\nexit 0\n");
  put("deploy/stacks/triage-platform/tools/verify-e2e.mjs", "// placeholder\n");
  put("deploy/stacks/wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem", "ca\n");
  put("deploy/stacks/wazuh/generated/wazuh.yml", "generated\n");
  put("deploy/stacks/triage-platform/generated/agent-compose.env", "generated\n");
  put("deploy/stacks/release-webhook/generated/github-webhook-secret", "generated\n");
  put("state/octobus/data/triage.db", "sqlite\n");
  put("state/agent-compose/data/agent-compose.db", "sqlite\n");
  put("fake-runner.sh", `#!/bin/sh
set -eu
line=""
for argument in "$@"; do line="\${line}\${line:+ }\${argument}"; done
printf '%s\n' "$line" >> "$UPDATE_STACKS_TEST_LOG"
case "$line" in
  *" rev-parse --abbrev-ref HEAD") printf '%s\n' develop; exit 0 ;;
  *" status --porcelain") exit 0 ;;
  *" rev-parse HEAD") printf '%040d\n' 0 | tr 0 a; exit 0 ;;
esac
previous=""
for argument in "$@"; do
  if [ "$previous" = "create" ]; then printf '%s\n' bundle > "$argument"; fi
  previous="$argument"
done
if [ -n "\${UPDATE_STACKS_FAIL_MATCH:-}" ]; then
  case "$line" in *"$UPDATE_STACKS_FAIL_MATCH"*) exit 42 ;; esac
fi
exit 0
`);
  return fixture;
}

function execute(fixture, args = ["--mode", "interactive", "--phase", "all"], extraEnv = {}, roots = {}) {
  const shell = shellExecutable();
  if (!shell) return { skipped: true };
  const log = path.join(fixture, "commands.log");
  return spawnSync(shell, [toShellPath(sourceScript), ...args,
    "--env-file", toShellPath(path.join(fixture, ".env")),
    "--backup-root", toShellPath(roots.backupRoot ?? path.join(fixture, "backups")),
    "--state-root", toShellPath(roots.stateRoot ?? path.join(fixture, "state"))], {
    cwd: fixture,
    encoding: "utf8",
    env: {
      ...process.env,
      UPDATE_STACKS_REPO_ROOT: toShellPath(fixture),
      UPDATE_STACKS_COMMAND_RUNNER: toShellPath(path.join(fixture, "fake-runner.sh")),
      UPDATE_STACKS_TEST_LOG: toShellPath(log),
      ...extraEnv,
    },
  });
}

test("rejects a backup root inside the business state root", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const result = execute(fixture, undefined, {}, {
    backupRoot: path.join(fixture, "state", "backups"),
  });
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.equal(result.status, 78);
  assert.match(result.stderr, /backup root must be outside business state root/);
  assert.equal(existsSync(path.join(fixture, "state", "backups")), false);
});

test("creates timestamped commit, configuration, and SQLite backups before updates", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const result = execute(fixture);
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const backups = readdirSync(path.join(fixture, "backups")).sort();
  assert.equal(backups.length, 3);
  assert.ok(backups.some((name) => /^commit-backup-\d{8}-\d{6}\.bundle$/.test(name)));
  assert.ok(backups.some((name) => /^configuration-backup-\d{8}-\d{6}\.tar\.gz$/.test(name)));
  assert.ok(backups.some((name) => /^sqlite-backup-\d{8}-\d{6}\.tar\.gz$/.test(name)));
});

test("first deployment succeeds before generated configuration directories exist", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  for (const relative of [
    "deploy/stacks/wazuh/generated",
    "deploy/stacks/triage-platform/generated",
    "deploy/stacks/release-webhook/generated"
  ]) rmSync(path.join(fixture, relative), { recursive: true, force: true });
  const result = execute(fixture);
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.ok(readdirSync(path.join(fixture, "backups")).some((name) => /^configuration-backup-\d{8}-\d{6}\.tar\.gz$/.test(name)));
});

test("validates every compose file before creating a backup or starting an update", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const result = execute(fixture, undefined, { UPDATE_STACKS_FAIL_MATCH: "config --quiet" });
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.notEqual(result.status, 0);
  assert.equal(existsSync(path.join(fixture, "backups")), false);
});

test("updates Wazuh, triage, bootstrap, release, and verification in order", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const result = execute(fixture);
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const commands = String(result.stdout) + String(result.stderr) + readFileSync(path.join(fixture, "commands.log"), "utf8");
  const runtimeOwner = commands.indexOf("chown 999:999");
  const wazuh = commands.indexOf("deploy/stacks/wazuh/docker-compose.yml up -d --build");
  const triage = commands.indexOf("deploy/stacks/triage-platform/docker-compose.yml up -d");
  const bootstrap = commands.indexOf("deploy/stacks/triage-platform/bootstrap.sh");
  const release = commands.indexOf("deploy/stacks/release-webhook/docker-compose.yml up -d --build");
  const verify = commands.indexOf("deploy/stacks/triage-platform/verify.sh");
  assert.ok(runtimeOwner >= 0 && runtimeOwner < wazuh && wazuh < triage && triage < bootstrap && bootstrap < release && release < verify, commands);
});

test("restricted mode completes the platform before its release phase replaces the worker", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const platform = execute(fixture, ["--mode", "release-worker", "--phase", "platform"]);
  if (platform.skipped) return t.skip("POSIX shell unavailable");
  assert.equal(platform.status, 0, platform.stderr || platform.stdout);
  const platformLog = readFileSync(path.join(fixture, "commands.log"), "utf8");
  assert.match(platformLog, /triage-platform\/bootstrap\.sh/);
  assert.doesNotMatch(platformLog, /release-webhook\/docker-compose\.yml up -d/);

  writeFileSync(path.join(fixture, "commands.log"), "");
  const release = execute(fixture, ["--mode", "release-worker", "--phase", "release"]);
  assert.equal(release.status, 0, release.stderr || release.stdout);
  const releaseLog = readFileSync(path.join(fixture, "commands.log"), "utf8");
  assert.match(releaseLog, /release-webhook\/docker-compose\.yml up -d --build/);
  assert.doesNotMatch(releaseLog, /triage-platform\/docker-compose\.yml up -d/);
});

test("reports a nonzero failure with the matching rollback point", (t) => {
  const fixture = makeFixture();
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const result = execute(fixture, undefined, { UPDATE_STACKS_FAIL_MATCH: "triage-platform/docker-compose.yml up -d" });
  if (result.skipped) return t.skip("POSIX shell unavailable");
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /stage=triage-platform/);
  assert.match(result.stderr, /rollback_point=.*backup-\d{8}-\d{6}/);
});
