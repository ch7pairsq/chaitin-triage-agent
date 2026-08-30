/**
 * 共享层：终态指标收集器（规范 §11.1 可观测性三件套之「指标」）。
 *
 * 指标随单次任务运行在进程内累计，任务终态时挂到 result.metrics：
 * - stage_durations：各状态阶段耗时（毫秒）。以状态迁移时间戳差值结算，
 *   同一状态多次出现（如 TOOL_RETRY 观察态）时累加，值为非负整数；
 *   无法精确计时的阶段可省略，但至少覆盖主要阶段；
 * - capability_calls / capability_failures：能力调用总数（成功+失败）与失败数；
 * - knowledge_hits：知识命中数（判定阶段命中的知识资产数，由流水线填充；
 *   security 取 IOC / 降噪规则命中，malware 取 grounded RAG 检索携带的知识 id）；
 * - narrative_source：模型来源（"llm" / "fallback" / 确定性 narrator 的 kind）；
 * - manual_escalation：终态为 manual_review / NEED_HUMAN / 升级人工时为 true。
 *
 * 收集器只随 result 暴露给接口层审计：不落库、不外发，不引入任何依赖。
 */
export function createMetricsCollector() {
  const metrics = {
    stage_durations: {},
    capability_calls: 0,
    capability_failures: 0,
    knowledge_hits: 0,
    narrative_source: null,
    manual_escalation: false
  };
  let lastMark = null;

  function accumulate(state, elapsedMs) {
    metrics.stage_durations[state] = (metrics.stage_durations[state] ?? 0) + Math.max(0, elapsedMs);
  }

  return {
    metrics,

    /** 记录一次状态迁移：上一阶段耗时在此结算，新阶段从此刻起算。 */
    markStage(state) {
      const timestamp = Date.now();
      if (lastMark) accumulate(lastMark.state, timestamp - lastMark.timestamp);
      lastMark = { state, timestamp };
    },

    /** 终态结算：最后一个阶段以调用此刻为截止。 */
    finishStages() {
      if (!lastMark) return;
      const timestamp = Date.now();
      accumulate(lastMark.state, timestamp - lastMark.timestamp);
      lastMark = null;
    },

    /** 包装一次能力调用：成功与失败均计入调用总数，失败再单独累加。 */
    async runCapability(action) {
      metrics.capability_calls += 1;
      try {
        return await action();
      } catch (error) {
        metrics.capability_failures += 1;
        throw error;
      }
    },

    /** 终态收口：结算最后阶段耗时并标记是否升级人工。 */
    finalize({ manualEscalation }) {
      this.finishStages();
      metrics.manual_escalation = Boolean(manualEscalation);
      return metrics;
    }
  };
}
