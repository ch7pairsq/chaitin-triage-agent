# SecurityOps 闭环重构实施计划

> 状态：该计划记录首轮实现。2026-09-02 起，触发、租约恢复、并发和统一部署的后续工作由 [`2026-09-02-deterministic-intake-recovery.md`](./2026-09-02-deterministic-intake-recovery.md) 接续；若两份计划冲突，以新计划和对应 ADR 为准。

**目标：** 在 `develop` 分支按设计文档完成可独立复现的 Wazuh、agent-compose、OctoBus、SecurityOps、人工工单与飞书闭环。

**架构：** `wazuh-connector` 独立封装 Wazuh 只读查询；SecurityOps 独占业务状态、确定性策略、人工工单和飞书投递；agent-compose 只负责事件、调度和 Agent Runtime。Agent 只通过 OctoBus MCP 调用两类能力服务，三个控制/业务 SQLite 按所有权隔离。

**技术栈：** Node.js、Proto3、OctoBus service package、agent-compose QJS scheduler、SQLite、Docker Compose/Portainer Stack、Wazuh、飞书 Webhook。

---

## 批次一：可独立运行的业务服务

1. 创建 `services/security-ops` 的 package、descriptor、Proto、schema 与测试入口。
2. 以测试先行实现 SQLite 迁移、告警幂等写入和 trigger outbox 原子事务。
3. 实现稳定业务错误码和输入边界。

完成标准：服务包可独立执行 `npm run check`、`npm test`、`npm pack --dry-run`。

## 批次二：知识与确定性决策

1. 建立三领域和 33 类攻击 taxonomy。
2. 生成 99 条 draft 知识和每条四项测试记录。
3. 加入人工批准门、运行包构建和数量/结构/隔离校验。
4. 实现 MatchKnowledge、EvaluatePolicy 与 decision token。

完成标准：99 条 approved 知识进入运行包，396 条测试记录不进入运行包；决策不能自动关闭。

## 批次三：业务闭环

1. 实现告警领取、上下文、富化、结果记录、人工工单、飞书 outbox、终态与 trace。
2. 实现幂等、租约、重试、补偿与恢复。
3. 实现 SecurityOps 长运行时适配与 OctoBus package 验证。

完成标准：重复事件不产生重复结果、工单或消息；GetTriageTrace 返回完整链。

## 批次四：agent-compose 与 OctoBus 主链

1. 改为 agent-compose 原生 webhook event 和 QJS hourly scheduler。
2. 配置 wazuh-ingress、triage-runner、triage-ops 三个 capset。
3. Agent 使用 MCP 工具编排多个 SecurityOps 方法，删除固定 CLI 和业务直连。

完成标准：事件与小时任务均由 Agent Runtime 执行，业务方法全部经过 OctoBus。

## 批次五：基础设施、清理与文档

1. 加入 Wazuh、测试日志注入器、release-webhook HMAC 服务和三个 Stack。
2. 删除旧能力包、旧业务 CLI/SQLite/模型直连和无关模块。
3. 更新 README、架构图、时序图、ADR、部署与验证脚本。
4. 从干净 clone 验证两次事件和两次小时补偿。

完成标准：一台新服务器可由仓库独立复现，所有静态检查、测试、打包和流程验证通过。

## 当前实施状态

- 已完成：两套独立 OctoBus service package、业务 SQLite、确定性决策、人工工单、飞书 outbox、三类 capset、分钟轮询、事件触发、小时补偿、三套 Stack、GitHub HMAC 接收器与全仓验证入口。
- 已完成：3 个领域、33 类攻击、99 条知识和 396 条边界记录的生成、结构校验、逐条检查批注及运行发布门控；33 类攻击分别具备独立首要信号、证据、反例、可观察性与复核重点。
- 已完成：逐条批注确认和批准登记，99 条知识均为 `approved`；批准数量不完整时运行知识构建仍必须失败。
- 已完成：删除旧业务目录、旧知识目录、旧能力包、旧 Stack 与旧交付文件，并完成残留引用扫描。
- 待最终环境完成：提交并推送 `develop` 后，从干净 clone 执行容器验证、两次事件流程和两次小时补偿。
