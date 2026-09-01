import { createHmac } from "node:crypto";

export class DeliveryError extends Error {
  constructor(message, { retryable = false, status = 0 } = {}) {
    super(message);
    this.name = "DeliveryError";
    this.retryable = retryable;
    this.status = status;
  }
}

export class AgentWebhookClient {
  constructor({ url, token, fetchImpl = fetch, timeoutMs = 5000 }) {
    this.url = validateAgentWebhookUrl(url);
    if (typeof token !== "string" || token.length < 24) throw new TypeError("agent webhook token must contain at least 24 characters");
    this.token = token;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async send(delivery) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
          "idempotency-key": delivery.idempotencyKey,
          "x-correlation-id": delivery.payload.correlationId
        },
        body: JSON.stringify({ eventId: delivery.payload.eventId, correlationId: delivery.payload.correlationId }),
        signal: controller.signal
      });
      if (response.status !== 202) throw httpDeliveryError("agent webhook rejected the event", response.status);
      const body = await safeJson(response);
      if (body?.accepted !== true) throw new DeliveryError("agent webhook response did not confirm acceptance", { retryable: true, status: response.status });
      return { accepted: true, eventId: body.event_id ?? body.eventId ?? "" };
    } catch (error) {
      if (error instanceof DeliveryError) throw error;
      if (error?.name === "AbortError") throw new DeliveryError("agent webhook timed out", { retryable: true });
      throw new DeliveryError("agent webhook request failed", { retryable: true });
    } finally {
      clearTimeout(timeout);
    }
  }
}

export class FeishuWebhookClient {
  constructor({ url, secret = "", fetchImpl = fetch, timeoutMs = 5000, now = () => new Date() }) {
    this.url = validateFeishuWebhookUrl(url);
    this.secret = secret;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.now = now;
  }

  async send(delivery) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const payload = { ...delivery.payload };
      if (this.secret) {
        const timestamp = Math.floor(this.now().getTime() / 1000).toString();
        const stringToSign = `${timestamp}\n${this.secret}`;
        payload.timestamp = timestamp;
        payload.sign = createHmac("sha256", stringToSign).update("").digest("base64");
      }
      const response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      if (!response.ok) throw httpDeliveryError("Feishu webhook rejected the notification", response.status);
      const body = await safeJson(response);
      if (Number(body?.code ?? body?.StatusCode ?? -1) !== 0) {
        throw new DeliveryError("Feishu webhook returned a non-zero result", { retryable: true, status: response.status });
      }
      return { delivered: true };
    } catch (error) {
      if (error instanceof DeliveryError) throw error;
      if (error?.name === "AbortError") throw new DeliveryError("Feishu webhook timed out", { retryable: true });
      throw new DeliveryError("Feishu webhook request failed", { retryable: true });
    } finally {
      clearTimeout(timeout);
    }
  }
}

export class OutboxWorker {
  constructor({ store, agentWebhookClient, feishuWebhookClient, limit = 20 }) {
    this.store = store;
    this.agentWebhookClient = agentWebhookClient;
    this.feishuWebhookClient = feishuWebhookClient;
    this.limit = limit;
  }

  async runOnce() {
    const summary = { triggerDelivered: 0, triggerFailed: 0, feishuDelivered: 0, feishuFailed: 0 };
    for (const delivery of this.store.claimTriggerDeliveries({ limit: this.limit })) {
      try {
        await this.agentWebhookClient.send(delivery);
        this.store.markTriggerDelivered(delivery.deliveryId);
        summary.triggerDelivered += 1;
      } catch (error) {
        this.store.markTriggerFailed(delivery, { error: error.message, retryable: error.retryable === true });
        summary.triggerFailed += 1;
      }
    }
    for (const delivery of this.store.claimFeishuDeliveries({ limit: this.limit })) {
      try {
        await this.feishuWebhookClient.send(delivery);
        this.store.markFeishuDelivered(delivery.deliveryId);
        summary.feishuDelivered += 1;
      } catch (error) {
        this.store.markFeishuFailed(delivery, { error: error.message, retryable: error.retryable === true });
        summary.feishuFailed += 1;
      }
    }
    return summary;
  }
}

function validateAgentWebhookUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("agent webhook URL is invalid");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.pathname !== "/api/webhooks/webhook.wazuh.alert") {
    throw new TypeError("agent webhook URL must target /api/webhooks/webhook.wazuh.alert");
  }
  url.username = "";
  url.password = "";
  return url.toString();
}

function validateFeishuWebhookUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("Feishu webhook URL is invalid");
  }
  if (url.protocol !== "https:" || url.hostname !== "open.feishu.cn" || !/^\/open-apis\/bot\/v2\/hook\/[A-Za-z0-9_-]+$/.test(url.pathname)) {
    throw new TypeError("Feishu webhook URL must be an official custom bot endpoint");
  }
  return url.toString();
}

function httpDeliveryError(message, status) {
  return new DeliveryError(message, { retryable: status === 408 || status === 429 || status >= 500, status });
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    throw new DeliveryError("webhook response was not valid JSON", { retryable: true, status: response.status });
  }
}
