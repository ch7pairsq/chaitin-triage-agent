#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineService, runServiceMain, serviceError } from "@chaitin-ai/octobus-sdk";

import { WazuhConnectorError, WazuhIndexerClient } from "./client.js";

const FULL_SERVICE = "wazuh.connector.v1.WazuhConnectorService";
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.env.OCTOBUS_DESCRIPTOR_PATH ||= path.join(PACKAGE_ROOT, "proto", "descriptor.pb");

const clients = new Map();

function clientFor(context) {
  const key = path.resolve(context.workdir);
  const existing = clients.get(key);
  if (existing) return existing;
  const config = context.config ?? {};
  const secret = context.secret ?? {};
  const caPath = config.ca_path
    ? path.resolve(context.workdir, config.ca_path)
    : "";
  const client = new WazuhIndexerClient({
    indexerUrl: config.indexer_url,
    username: secret.indexer_username,
    password: secret.indexer_password,
    indexPattern: config.index_pattern ?? "wazuh-alerts-*",
    minimumRuleLevel: config.minimum_rule_level ?? 0,
    requiredRuleGroup: config.required_rule_group ?? "triage_input",
    requestTimeoutMs: config.request_timeout_ms ?? 8_000,
    caPath,
    maxAlertBytes: config.max_alert_bytes ?? 262_144
  });
  clients.set(key, client);
  return client;
}

export const octobusService = defineService({
  handlers: {
    [`${FULL_SERVICE}/ListAlerts`]: async (context) => {
      try {
        return await clientFor(context).listAlerts(context.request ?? {});
      } catch (error) {
        if (error instanceof WazuhConnectorError) {
          throw serviceError(error.code, error.message, error.details);
        }
        throw error;
      }
    }
  }
});

runServiceMain(octobusService);
