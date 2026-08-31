/**
 * Infrastructure layer: security alert "model explanation" gateway (spec §5.2).
 *
 * Division-of-labor red line (spec §6): the model only explains decisions
 * already constrained by the rule engine. It never receives a tool endpoint
 * and cannot override policy action. Input is sanitised through modelSafeAlert
 * — private IOCs enter the model as counts only. LLM credentials are injected
 * via the agent-compose Runtime LLM Facade (scoped token), the real provider
 * key never reaches the sandbox. When the model is unreachable we fall back
 * to deterministic narration (DeterministicNarrator).
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
      alert: { ...modelSafeAlert(context) },
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
          temperature: 0.2,
          stream: false,
          messages: [
            {
              role: "system",
              content: [
                "你是安全运营分析师助理，只能对已经确定的研判结论给出简洁中文叙述，不做任何修改。",
                "输入包含：脱敏告警 + 规则引擎 policyDecision(status/action/matchedRuleId/reason/evidence)。",
                "输出必须覆盖：告警摘要、结论 status、命中规则原因、关键证据（evidence 每项说明 present/缺失/取值）、建议动作 action。",
                "禁止加入输入中不存在的 IOC、域名、IP、URL、用户名；禁止推翻 status/action/matchedRuleId。",
                "结果控制在 160 字以内。"
              ].join(" ")
            },
            {
              role: "user",
              content: `请基于以下已完成研判的安全告警给出中文叙述：\n${JSON.stringify(input, null, 2)}`
            }
          ]
        })
      });
    } catch (error) {
      if (controller.signal.aborted) throw new Error("LLM 请求超时");
      throw error;
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      const preview = await response.text().catch(() => "");
      throw new Error(`LLM 请求失败：HTTP ${response.status} ${(preview || "").slice(0, 200)}`);
    }
    try {
      body = await response.json();
    } catch (error) {
      throw new Error(`LLM 响应非 JSON：${String(error)}`);
    }
    const content = body?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) {
      throw new Error(`LLM 响应为空：${JSON.stringify(body).slice(0, 300)}`);
    }
    return content;
  }
}

export function narratorFromEnvironment(environment = process.env) {
  // Real-call switch (defaults to true, so deployments make a real external
  // /chat/completions call out-of-the-box, matching the audit requirements).
  // Disable explicitly by setting SECURITY_TRIAGE_LLM_REAL_CALL (or the
  // generic LLM_REAL_CALL) to one of: 0 | false | off (case-insensitive).
  const realCallRaw = environment.SECURITY_TRIAGE_LLM_REAL_CALL ?? environment.LLM_REAL_CALL;
  if (typeof realCallRaw === "string" && /^(0|false|off)$/i.test(realCallRaw.trim())) {
    return new DeterministicNarrator();
  }
  // SECURITY_TRIAGE_* scoped variables win over the generic facade-injected
  // ones, keeping the same priority as the CLI alias layer.
  const apiBase = environment.SECURITY_TRIAGE_LLM_API_BASE || environment.LLM_API_BASE || environment.LLM_API_ENDPOINT;
  const apiKey  = environment.SECURITY_TRIAGE_LLM_API_KEY  || environment.LLM_API_KEY;
  const model   = environment.SECURITY_TRIAGE_LLM_MODEL    || environment.LLM_MODEL;
  if (apiBase && apiKey && model) {
    return new OpenAICompatibleNarrator({
      apiBase,
      apiKey,
      model,
      timeoutMs: environment.SECURITY_TRIAGE_LLM_TIMEOUT_MS || environment.LLM_TIMEOUT_MS
    });
  }
  return new DeterministicNarrator();
}