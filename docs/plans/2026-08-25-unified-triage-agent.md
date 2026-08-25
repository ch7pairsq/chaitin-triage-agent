# Unified Triage Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Merge the security-alert and malware-triage implementations into one deployable Agent Compose project without widening either workflow's permissions.

**Architecture:** Preserve each domain's implementation under `agent/src/security` and `agent/src/malware`, then route explicit CLI workflow flags through one entry point. The compose project supplies separate scoped OctoBus credentials and state paths to one `triage-operator`.

**Tech Stack:** Node.js 22+, Node test runner, SQLite, Agent Compose, OctoBus Connect RPC.

---

### Task 1: Preserve both workflow contracts

**Files:** `agent/src/security/**`, `agent/src/malware/**`, `agent/test/**`

1. Copy both domain modules without combining their state stores or OctoBus clients.
2. Relocate tests with their corresponding domain and update only import paths.
3. Run `npm test` and require all domain tests to pass.

### Task 2: Add an explicit unified dispatcher

**Files:** `agent/src/cli.js`, `agent/package.json`

1. Route alert/recovery flags to the security CLI and sample/conversation flags to malware.
2. Reject commands selecting both workflows.
3. Alias only the selected domain's scoped configuration to its existing internal names.
4. Run `npm run check` and `npm test`.

### Task 3: Make deployment one Agent Compose project

**Files:** `agent-compose.yml`, `.env.example`, `README.md`

1. Define one workspace, one operator, a shared private-knowledge mount, and one state volume.
2. Use separate files in that volume for the incompatible SQLite schemas.
3. Inject security and malware OctoBus credentials under distinct environment names.
4. Validate the compose YAML by inspecting the selected environment names and run Node verification.

### Task 4: Switch demonstration and release integration

**Files:** `chaitin-demo-console/server.mjs`, `trigger-bridge/agent-trigger-bridge.mjs`, `release-runner/*`, `deploy/chaitin-stack.yml`, tests and UI

1. Allow only `chaitin-triage-agent` as a release target.
2. Map every fixed live case to the unified project and `triage-operator`.
3. Update release health checks to verify both capability sets.
4. Run the console syntax and test suites.
