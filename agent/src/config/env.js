/**
 * 配置层：环境变量域前缀别名与配置读取（规范 §5.2 config/）。
 *
 * agent-compose 向沙箱注入域前缀变量（SECURITY_TRIAGE_* / MALWARE_TRIAGE_*），
 * 统一入口（interfaces/cli.js）按 CLI flag 只为一个工作流做别名映射：
 * - 工作流选择只来自显式 CLI flag，不受 prompt 文本影响（权限边界）；
 * - 未显式配置的变量不猜测、不默认注入敏感值。
 */

/**
 * 将域前缀环境变量别名为通用名（仅在通用名未设置时生效）。
 * 例：aliasDomainEnvironment("SECURITY_TRIAGE_", ["OCTOBUS_BASE_URL"])
 * 把 SECURITY_TRIAGE_OCTOBUS_BASE_URL 映射为 OCTOBUS_BASE_URL。
 * @param {string} prefix 域前缀（SECURITY_TRIAGE_ / MALWARE_TRIAGE_）
 * @param {string[]} names 通用变量名列表
 */
export function aliasDomainEnvironment(prefix, names, environment = process.env) {
  for (const name of names) {
    const scoped = `${prefix}${name}`;
    if (!environment[name] && environment[scoped]) {
      environment[name] = environment[scoped];
    }
  }
}

/** 读取必填配置：缺失时抛出带变量名的错误（禁止静默回退到猜测值）。 */
export function requiredConfig(value, name) {
  if (!value) {
    throw new Error(`Missing required value: ${name}`);
  }
  return value;
}

/** 读取可选数值配置：非法值回退默认值（用于超时 / topK 等非敏感参数）。 */
export function optionalNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * 读取知识消融配置（规范 §9.4）：KNOWLEDGE_ABLATION 为逗号分隔的 knowledge_id，
 * 返回消融集合；未设置或为空串时返回空集（行为与现状完全一致）。
 * @param {object} [env] 环境变量对象（测试注入）
 * @returns {Set<string>} 被消融的 knowledge_id 集合
 */
export function knowledgeAblationFromEnvironment(env = process.env) {
  const raw = env.KNOWLEDGE_ABLATION;
  if (!raw) return new Set();
  return new Set(
    String(raw)
      .split(",")
      .map((id) => id.trim())
      .filter(Boolean)
  );
}
