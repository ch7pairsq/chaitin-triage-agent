/**
 * 共享层：弹性执行器 —— 有界重试 + 按操作熔断（规范 §11.3 错误处理与降级）。
 *
 * 设计要点：
 * - 重试刻意局部且有界：持久化恢复交给 SQLite outbox，进程重启绝不重放无限循环；
 * - 熔断状态只存进程内存：新拉起的 guest 不继承旧故障判定，已修复的网关不会被误熔断；
 * - 非瞬态错误（配置错、4xx）直接抛出，禁止静默重试掩盖问题。
 */

export class CircuitOpenError extends Error {
  constructor(operation, retryAt) {
    super(`${operation} circuit is open until ${retryAt}`);
    this.name = "CircuitOpenError";
    this.operation = operation;
    this.retryAt = retryAt;
    this.retryable = true;
  }
}

export function isTransientError(error) {
  if (error?.retryable === true) return true;
  const status = Number(error?.status);
  return Number.isInteger(status) && (status === 408 || status === 429 || status >= 500);
}

/**
 * Keeps retries deliberately local and bounded. Durable recovery belongs to
 * the SQLite outbox, so a process restart never replays an unbounded loop.
 */
export class ResilientExecutor {
  constructor({ maxAttempts = 3, baseDelayMs = 150, circuitFailureThreshold = 3, circuitOpenMs = 30_000, sleep = delay => new Promise(resolve => setTimeout(resolve, delay)), random = Math.random, now = () => Date.now() } = {}) {
    this.maxAttempts = maxAttempts;
    this.baseDelayMs = baseDelayMs;
    this.circuitFailureThreshold = circuitFailureThreshold;
    this.circuitOpenMs = circuitOpenMs;
    this.sleep = sleep;
    this.random = random;
    this.now = now;
    this.operations = new Map();
  }

  async run(operation, action) {
    const state = this.operations.get(operation) ?? { consecutiveFailures: 0, openUntil: 0 };
    if (state.openUntil > this.now()) throw new CircuitOpenError(operation, new Date(state.openUntil).toISOString());
    if (state.openUntil) state.openUntil = 0;

    let lastError;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        const result = await action(attempt);
        this.operations.set(operation, { consecutiveFailures: 0, openUntil: 0 });
        return result;
      } catch (error) {
        lastError = error;
        if (!isTransientError(error) || attempt === this.maxAttempts) break;
        const exponentialDelay = this.baseDelayMs * (2 ** (attempt - 1));
        const jitterMs = Math.floor(this.random() * Math.max(1, Math.floor(exponentialDelay / 2)));
        await this.sleep(exponentialDelay + jitterMs);
      }
    }

    const consecutiveFailures = state.consecutiveFailures + 1;
    const openUntil = consecutiveFailures >= this.circuitFailureThreshold ? this.now() + this.circuitOpenMs : 0;
    this.operations.set(operation, { consecutiveFailures, openUntil });
    throw lastError;
  }
}
