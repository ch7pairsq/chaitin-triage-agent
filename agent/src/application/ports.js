/**
 * 应用层 Port 契约（依赖倒置边界）。
 *
 * 编排层（triage-agent / malware-triage-agent）只依赖下列接口形状；
 * 具体实现位于各 workflow 装配目录（security/、malware/）与基础设施模块
 * （octobus-connect-client、state-store、local-rag、wecom-notifier、narrator），
 * 由 cli.js 组合根在装配时注入。领域层（src/domains/）不 import 任何 Port。
 */

/**
 * CapabilityBusPort —— 能力总线口：所有确定性能力调用必须经 OctoBus。
 * 实现：security/octobus-connect-client.js、malware/octobus-connect-client.js
 * （Connect RPC），或经 agent-compose daemon 能力代理（capset MCP 工具）。
 */
export const CapabilityBusPort = {
  /** call(method, payload, traceId, options) -> Promise<Object> */
};

/**
 * StateStorePort —— 留痕口：业务留痕、证据链与状态快照。
 * 实现：security/state-store.js、malware/state-store.js（SQLite）。
 */
export const StateStorePort = {
  /** saveSnapshot(...) / recoverPending(...) / close() */
};

/**
 * KnowledgeRetrievalPort —— 知识库口：语义检索与判据注入（规范 §8.3）。
 * 实现：malware/local-rag.js（本地向量检索 + insufficient_evidence 分支）、
 * security 域的 threat-evidence 结构化判据。
 */
export const KnowledgeRetrievalPort = {
  /** search(query, topK) -> Promise<KnowledgeHit[]> */
};

/**
 * NotifierPort —— 处置通知口：脱敏后的出站通知。
 * 实现：security/wecom-notifier.js、malware/wecom-notifier.js。
 */
export const NotifierPort = {
  /** notify(summary) -> Promise<void> */
};

/**
 * NarratorPort —— 模型解释口：只解释已定的结论，不产生决策。
 * 实现：security/narrator.js、malware/narrator.js
 * （LLM 经 agent-compose Runtime LLM Facade，凭据不进沙箱）。
 */
export const NarratorPort = {
  /** summarize(context, decision) / analyze(report, assessment, retrieval) */
};
