#!/usr/bin/env node
import { realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineService, runServiceMain, serviceError } from "@chaitin-ai/octobus-sdk";

import { SecurityOpsError } from "./errors.js";
import { KnowledgeRepository } from "./knowledge-repository.js";
import { AgentWebhookClient, createOutboxLoop, FeishuWebhookClient, OutboxWorker } from "./outbox.js";
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
      knowledgeRepository
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
    const backend = { store, service, worker, loop, kick: loop.kick };
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
    [`${FULL_SERVICE}/RequeueStalledAlerts`]: unary((service, _request, _context, backend) => {
      const result = service.requeueStalledAlerts({});
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
    [`${FULL_SERVICE}/PutAuthorizationRecord`]: unary((service, request) => service.putAuthorizationRecord(request)),
    [`${FULL_SERVICE}/GetWorkerReadiness`]: unary((_service, _request, _context, backend) => {
      const readiness = backend.loop.getReadiness();
      return {
        ready: readiness.acceptingWork === true,
        backlog: readiness.backlog,
        manual: readiness.manual,
        oldestPendingAgeMs: readiness.oldestPendingAgeMs,
        activeBatch: readiness.activeBatch,
        acceptingWork: readiness.acceptingWork,
        lastErrorJson: readiness.lastError ? JSON.stringify(readiness.lastError) : ""
      };
    })
  }
});

export async function closeBackends({ graceMs = 10_000, logger = console } = {}) {
  const entries = [...backends.values()];
  const outcomes = await Promise.all(entries.map((backend) => backend.loop.close({ graceMs })));
  for (let index = 0; index < entries.length; index += 1) {
    if (outcomes[index].drained) {
      entries[index].store.close();
    } else {
      logger.error({
        message: "security operations shutdown grace expired",
        worker: "outbox_loop",
        graceMs
      });
    }
  }
  backends.clear();
  return { drained: outcomes.every((outcome) => outcome.drained) };
}

function shutdownGrpcServer(server, graceMs) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (graceful) => {
      if (settled) return;
      settled = true;
      resolve({ graceful });
    };
    const timeout = setTimeout(() => {
      server.forceShutdown();
      finish(false);
    }, graceMs);
    server.tryShutdown(() => {
      clearTimeout(timeout);
      finish(true);
    });
  });
}

export async function startRuntime() {
  const result = await runServiceMain(octobusService);
  if (result.command !== "serve") return result;
  let shutdown = null;
  const handleSignal = (signal) => {
    if (shutdown) return shutdown;
    const graceMs = 10_000;
    console.error({ message: "security operations shutdown requested", signal, graceMs });
    shutdown = Promise.all([
      closeBackends({ graceMs }),
      shutdownGrpcServer(result.server, graceMs)
    ]).then(([workers, grpc]) => {
      if (!workers.drained || !grpc.graceful) process.exitCode = 1;
      return { workers, grpc };
    });
    return shutdown;
  };
  process.once("SIGTERM", () => { void handleSignal("SIGTERM"); });
  process.once("SIGINT", () => { void handleSignal("SIGINT"); });
  return result;
}

function sameExecutablePath(left, right) {
  try {
    return realpathSync(left) === realpathSync(right);
  } catch {
    return path.resolve(left) === path.resolve(right);
  }
}

const isDirectRun = process.argv[1] !== undefined
  && sameExecutablePath(process.argv[1], fileURLToPath(import.meta.url));
if (isDirectRun) void startRuntime();
