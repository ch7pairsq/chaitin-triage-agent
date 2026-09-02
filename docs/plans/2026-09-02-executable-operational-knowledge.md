# Executable Operational Knowledge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 99 条三领域安全运营知识变为 SecurityOps 实际消费、可解释、可消融验证的确定性判据，同时保持 Wazuh → OctoBus → agent-compose → OctoBus → SecurityOps → SQLite/飞书主链路不变。

**Architecture:** 在 SecurityOps 内增加无动态代码执行的知识规则解释器，使用白名单字段路径、白名单操作符和有界值。知识记录保存可执行条件、排除条件、缺失字段处理、误报/漏报边界、来源与阈值依据；MatchKnowledge 和 EvaluatePolicy 都消费同一评估结果，并将评估摘要写入 trace。缺字段、规则不匹配或外部来源不可用时一律安全降级到人工复核。

**Tech Stack:** Node.js 22、JSON/JSONL、SQLite、Protocol Buffers、OctoBus SDK、agent-compose scheduler、Wazuh JSON decoder。

---

### Task 1: 建立可执行知识契约和安全规则解释器

**Files:**
- Create: `services/security-ops/src/knowledge-rule-engine.js`
- Create: `services/security-ops/test/knowledge-rule-engine.test.js`
- Modify: `services/security-ops/src/knowledge-repository.js`

**Steps:**
1. 先写操作符、缺失字段、排除条件和越界输入的失败测试。
2. 实现 `equals`、`in`、`gte`、`lte`、`contains_any`、`starts_with`、`truthy`、`exists` 白名单操作符。
3. 返回 `matchedPredicates`、`failedPredicates`、`excludedBy`、`missingFacts` 和确定性 outcome。
4. 运行 SecurityOps 单元测试。

### Task 2: 让 MatchKnowledge 和 EvaluatePolicy 真正消费规则结果

**Files:**
- Modify: `services/security-ops/src/service.js`
- Modify: `services/security-ops/src/store.js`
- Create: `services/security-ops/migrations/004_policy_rule_evaluation.sql`
- Modify: `services/security-ops/proto/security_ops.proto`
- Modify: `services/security-ops/src/runtime.js`
- Modify: `services/security-ops/test/workflow.test.js`

**Steps:**
1. 先写规则命中、排除、证据不足和无规则的服务失败测试。
2. MatchKnowledge 在同一领域内执行候选知识，不再仅信任输入的 attackTypeId。
3. EvaluatePolicy 重新执行服务端权威规则，并以结果决定升级、抑制或补证。
4. 将规则版本和评估摘要持久化到 policy decision，并通过 trace 查询返回。
5. 运行迁移、工作流、租约和恢复测试。

### Task 3: 将 99 条知识升级为可执行规则并删除知识生成器

**Files:**
- Modify: `knowledge-authoring/knowledge/*.json`
- Create: `knowledge-authoring/sources.json`
- Modify: `knowledge-authoring/tools/validate.mjs`
- Modify: `knowledge-authoring/tools/build-runtime.mjs`
- Delete: `knowledge-authoring/tools/generate.mjs`
- Modify: `knowledge-authoring/package.json`

**Steps:**
1. 为 33 类攻击定义不同事实、正向条件、排除条件、误报/漏报边界和来源依据。
2. 按三个领域增加资产、协议和业务窗口差异，形成 99 条具体知识。
3. 删除会覆盖人工复核知识的生成命令；保留校验与运行时编译。
4. 校验所有来源 ID、阈值依据、规则 ID、字段路径和操作符。
5. 运行知识发布检查。

### Task 4: 将 396 个案例变为真实执行测试并加入消融检查

**Files:**
- Modify: `knowledge-authoring/test-fixtures/*.json`
- Modify: `knowledge-authoring/test/knowledge.test.js`
- Create: `knowledge-authoring/test/executable-knowledge.test.js`
- Modify: `services/security-ops/test/workflow.test.js`

**Steps:**
1. 每条知识保留明确命中、授权排除、证据不足、复合事件四类案例。
2. 每个案例调用真实规则解释器，而不是只检查 JSON 数量。
3. 加入删除知识、删除排除条件、改变阈值和未消费字段的消融测试。
4. 输出规则覆盖率和 396 个案例的确定性通过统计，不把它表述为生产准确率。

### Task 5: 让 Wazuh 验证事件携带可判别事实

**Files:**
- Modify: `tools/wazuh-event-injector/src/index.js`
- Modify: `tools/wazuh-event-injector/test/injector.test.js`
- Modify: `deploy/stacks/wazuh/config/wazuh_rules/triage_rules.xml`
- Modify: `services/security-ops/test/ingress.test.js`

**Steps:**
1. 为三领域事件增加可执行事实，不把 attackTypeId 当作唯一判断依据。
2. Wazuh 只负责可信入口、字段完整性和分组，不在规则中复制全部业务决策。
3. 验证篡改自报类型时，SecurityOps 仍按事实匹配正确知识或安全降级。

### Task 6: 更新文档和仓库验证

**Files:**
- Modify: `README.md`
- Modify: `knowledge-authoring/README.md`
- Modify: `docs/design/2026-09-security-ops-rearchitecture.md`
- Modify: `tools/verify-repository.mjs`

**Steps:**
1. 更新洋葱架构、时序、知识执行、来源边界和故障降级说明。
2. 增加知识规则执行结果、来源引用和消融验证命令。
3. 全仓扫描已删除生成器、未消费规则、无依据阈值和旧描述。
4. 运行 `npm run verify`，再进行 Linux 容器干净验证。

### Task 7: 稳定性回归

**Files:**
- Modify only if a verified defect requires it.

**Steps:**
1. 修复 decision token 经过模型文本转写的问题，并确保日志不保留可重放令牌。
2. 运行两轮故障恢复和重复告警验证。
3. 连续执行 10 轮完整业务流程，要求首次执行 10/10 成功。
4. 核对无重复 trace、工单和飞书投递，最终 readiness 无积压。
