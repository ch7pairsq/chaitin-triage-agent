/**
 * 基础设施层：安全告警「模型解释」网关（规范 §5.2 infrastructure/model-gateway/）。
 *
 * 分工红线（规范 §6）：模型只解释已被规则引擎约束的结论，收不到任何
 * 工具端点，也无权覆盖 policy action。输入经过 modelSafeAlert 脱敏——
 * 私有 IOC 只以计数形式进入模型。LLM 凭据经 agent-compose Runtime
 * LLM Facade 注入（scoped token），真实 provider key 不进沙箱；
 * 模型不可达时降级为确定性叙述（DeterministicNarrator）。
 */

function fallbackNarrative(context, decision) {
  const evidence = decision.evidence
    .map((item) => `${item.label}=${item.present ? String(item.value) : "缺失"}`)
    .join("；");
  return [
    `告警 ${context.alertId}（${context.title || "未命名"}）研判结论：${decision.status}。`,
    decision.reason,
    evidence ? `关键证据：${evidence}。` : "关键证据：未命中降噪规则。",
    `建议动作：${decision.action}。`
  ].join(" ");
}

function modelSafeAlert(context) {
  return {
    alertId: context.alertId,
    title: context.title,
    severity: context.severity,
    assetCriticality: context.assetCriticality,
    // Signals may contain private IOCs. The model learns only their count.
    rawSignalCount: Array.isArray(context.rawSignals) ? context.rawSignals.length : 0,
    networkIndicatorCount: Array.isArray(context.networkIndicators) ? context.networkIndicators.length : 0,
    matchedSnortSidCount: Array.isArray(context.matchedSnortSids) ? context.matchedSnortSids.length : 0
  };
}

export class DeterministicNarrator {
  kind = "deterministic";

  async summarize(context, decision) {
    return fallbackNarrative(context, decision);
  }
}

/**
 * The model is deliberately limited to explaining an already-constrained decision.
 * It never receives a tool endpoint and cannot override the policy action.
 */
export class OpenAICompatibleNarrator {
  constructor({ apiBase, apiKey, model, timeoutMs = 8000, fetchImpl = fetch }) {
    this.kind = "llm";
    this.apiBase = apiBase.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.model = model;
    this.timeoutMs = Math.max(500, Math.min(Number(timeoutMs) || 8000, 30_000));
    this.fetchImpl = fetchImpl;
  }

  async summarize(context, decision) {
    const input = {
      alert: {
        ...modelSafeAlert(context)
      },
      policyDecision: {
        status: decision.status,
        action: decision.action,
        matchedRuleId: decision.matchedRuleId,
        reason: decision.reason,
        evidence: decision.evidence
      }
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    let body;
    try {
      response = await this.fetchImpl(`${this.apiBase}/chat/completions`, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          temperature: 0,
          messages: [
            {
              role: "system",
              content: "你是安全运营报告助手。只能基于提供的证据和既定 policyDecision 解释结论；不得更改 action、不得补造事实。输出不超过 180 个中文字符。"
            },
            { role: "user", content: JSON.stringify(input) }
          ]
        })
      });
      body = await response.text();
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      throw new Error(`LLM narration failed with HTTP ${response.status}`);
    }

    const payload = JSON.parse(body);
    const content = payload.choices?.[0]?.message?.content?.trim();
    if (!content) {
      throw new Error("LLM narration returned no content");
    }
    return content;
  }
}

export function narratorFromEnvironment(environment = process.env) {
  // Offline tests remain deterministic; deployed Agents use the configured
  // model only for explanation, never for policy selection.
  // LLM_API_ENDPOINT / LLM_API_KEY 由 agent-compose Runtime LLM Facade 注入
  // （scoped token，真实 provider key 不进入沙箱）；LLM_API_BASE 仅为本地
  // 直连覆盖项。
  const apiBase = environment.LLM_API_BASE || environment.LLM_API_ENDPOINT;
  if (apiBase && environment.LLM_API_KEY && environment.LLM_MODEL) {
    return new OpenAICompatibleNarrator({
      apiBase,
      apiKey: environment.LLM_API_KEY,
      model: environment.LLM_MODEL,
      timeoutMs: environment.LLM_TIMEOUT_MS
    });
  }
  return new DeterministicNarrator();
}
