#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineService, runServiceMain, serviceError } from "@chaitin-ai/octobus-sdk";

import { SecurityOpsError } from "./errors.js";
import { KnowledgeRepository } from "./knowledge-repository.js";
import { AgentWebhookClient, FeishuWebhookClient, OutboxWorker } from "./outbox.js";
import { SecurityOpsService } from "./service.js";
import { SecurityOpsStore } from "./store.js";

const FULL_SERVICE = "security.ops.v1.SecurityOpsService";
const backends = new Map();
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.env.OCTOBUS_DESCRIPTOR_PATH ||= path.join(PACKAGE_ROOT, "proto", "descriptor.pb");

function backendFor(context) {
  const workdir = path.resolve(context.workdir);
  const existing = backends.get(workdir);
  if (existing) return existing;
  const config = context.config ?? {};
  const secret = context.secret ?? {};
  const databasePath = path.resolve(workdir, config.database_path ?? "triage.db");
  const knowledgePath = path.resolve(context.packageDir, config.knowledge_path ?? "resources/knowledge.jsonl");
  const store = new SecurityOpsStore({
    databasePath,
    maxActiveTriage: Number(config.max_active_triage ?? 2)
  });
  try {
    const knowledgeRepository = KnowledgeRepository.fromJsonLines(knowledgePath);
    const service = new SecurityOpsService({
      store,
      knowledgeRepository,
      decisionTokenSecret: secret.decision_token_secret
    });
    const worker = new OutboxWorker({
      store,
      agentWebhookClient: new AgentWebhookClient({
        url: config.agent_webhook_url,
        token: secret.agent_webhook_token
      }),
      feishuWebhookClient: new FeishuWebhookClient({
        url: secret.feishu_webhook_url,
        secret: secret.feishu_webhook_secret ?? ""
      })
    });
    const loop = createOutboxLoop(worker, {
      intervalMs: Math.min(
        Number(config.trigger_poll_interval_ms ?? 1000),
        Number(config.delivery_poll_interval_ms ?? 3000)
      )
    });
    const backend = { store, service, kick: loop.kick, close: loop.close };
    backends.set(workdir, backend);
    return backend;
  } catch (error) {
    store.close();
    throw error;
  }
}

function unary(handler) {
  return async (context) => {
    try {
      const backend = backendFor(context);
      return await handler(backend.service, context.request ?? {}, context, backend);
    } catch (error) {
      if (error instanceof SecurityOpsError) throw serviceError(error.code, error.message, error.details);
      throw error;
    }
  };
}

export const octobusService = defineService({
  handlers: {
    [`${FULL_SERVICE}/IngestAlertEvent`]: unary((service, request, _context, backend) => {
      const result = service.ingestAlertEvent(request);
      backend.kick();
      return result;
    }),
    [`${FULL_SERVICE}/ListPendingAlerts`]: unary((service, request) => service.listPendingAlerts(request)),
    [`${FULL_SERVICE}/RequeueStalledAlerts`]: unary((service, request, _context, backend) => {
      const result = service.requeueStalledAlerts(request);
      backend.kick();
      return result;
    }),
    [`${FULL_SERVICE}/ClaimAlert`]: unary((service, request) => service.claimAlert(request)),
    [`${FULL_SERVICE}/GetAlertContext`]: unary((service, request) => {
      const result = service.getAlertContext(request);
      return {
        eventId: result.eventId,
        correlationId: result.correlationId,
        wazuhAlertId: result.wazuhAlertId,
        alertJson: JSON.stringify(result.alert)
      };
    }),
    [`${FULL_SERVICE}/EnrichAlert`]: unary((service, request) => {
      const result = service.enrichAlert(request);
      return {
        traceId: result.traceId,
        contextJson: result.contextJson,
        evidenceRefs: result.evidenceRefs,
        domainId: result.domainId,
        attackTypeId: result.attackTypeId
      };
    }),
    [`${FULL_SERVICE}/MatchKnowledge`]: unary((service, request) => service.matchKnowledge(request)),
    [`${FULL_SERVICE}/EvaluatePolicy`]: unary((service, request) => service.evaluatePolicy(request)),
    [`${FULL_SERVICE}/RecordTriageResult`]: unary((service, request) => {
      const result = service.recordTriageResult(request);
      return { resultId: result.resultId, traceId: result.traceId, duplicate: result.duplicate };
    }),
    [`${FULL_SERVICE}/CreateManualTicket`]: unary((service, request) => {
      const ticket = service.createManualTicket(request);
      return { ticketId: ticket.ticketId, duplicate: ticket.duplicate };
    }),
    [`${FULL_SERVICE}/QueueFeishuNotification`]: unary((service, request, _context, backend) => {
      const delivery = service.queueFeishuNotification(request);
      backend.kick();
      return { deliveryId: delivery.deliveryId, status: delivery.status, duplicate: delivery.duplicate };
    }),
    [`${FULL_SERVICE}/FinalizeTriage`]: unary((service, request) => {
      const result = service.finalizeTriage(request);
      return { traceId: result.traceId, state: result.state };
    }),
    [`${FULL_SERVICE}/GetTriageTrace`]: unary((service, request) => {
      const trace = service.getTriageTrace(request);
      return { traceId: trace.traceId, traceJson: JSON.stringify(trace) };
    }),
    [`${FULL_SERVICE}/RecoverDelivery`]: unary((service, request) => service.recoverDelivery(request)),
    [`${FULL_SERVICE}/PutAuthorizationRecord`]: unary((service, request) => service.putAuthorizationRecord(request))
  }
});

export function closeBackends() {
  for (const backend of backends.values()) {
    backend.close();
    backend.store.close();
  }
  backends.clear();
}

export function createOutboxLoop(worker, { intervalMs = 1000 } = {}) {
  let running = null;
  let closed = false;
  const kick = () => {
    if (closed || running) return running;
    running = Promise.resolve().then(() => worker.runOnce()).catch(() => null).finally(() => { running = null; });
    return running;
  };
  const timer = setInterval(kick, Math.max(250, Math.min(intervalMs, 60_000)));
  timer.unref();
  kick();
  return {
    kick,
    close() {
      closed = true;
      clearInterval(timer);
    }
  };
}

process.once("exit", closeBackends);
runServiceMain(octobusService);
