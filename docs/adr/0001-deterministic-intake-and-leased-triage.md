# ADR-0001：确定性分钟采集与租约化事件研判

- 状态：Accepted
- 日期：2026-09-02
- 适用分支：`develop`

## 背景

原设计同时运行分钟级采集 Agent、事件研判 Agent 和小时级补偿 Agent。分钟任务需要完成固定的 API 调用和入库动作，却承担了不必要的 LLM 启动成本；小时任务与分钟任务在整点可能碰撞，并形成第二套业务状态推进路径。Agent 超时后仅依靠重复事件也无法可靠区分旧运行和恢复运行。

系统还必须保证 agent-compose 和 OctoBus 位于主链路：agent-compose 负责触发与运行隔离，OctoBus 负责所有业务能力路由和授权，业务数据由 SecurityOps 独占。

## 决策

1. 在同一 agent-compose 项目中使用两个职责分离的 agent：
   - `wazuh-intake` 每分钟通过一次受限 `scheduler.exec` 执行确定性采集程序，不使用 LLM；
   - `triage-operator` 由 `webhook.wazuh.alert` 触发，是唯一使用 LLM 的研判 Agent。
2. 删除小时级完整 Agent 调度，把补偿收敛到 SecurityOps 的 `RequeueStalledAlerts`，由每分钟周期调用。
3. 所有业务接口调用必须经过 OctoBus；采集程序与 Agent 均不得直连 Wazuh、SQLite、飞书或 SecurityOps。
4. 使用 claim token、租约、attempt 和围栏校验，阻止超时旧运行覆盖恢复后的状态。
5. `max_active_triage=2` 由 SecurityOps 强制执行，outbox 仅按可用槽位投递。
6. 最多恢复 3 次；仍无法完成时创建人工工单并排队飞书通知，不自动关闭事件。
7. 分钟任务硬超时 25 秒，空轮询连续验证目标小于 30 秒；完整事件研判上限为 3 分钟。

## 备选方案

### 保留小时级补偿 Agent

未采用。它会增加整点竞争、LLM 成本和重复状态推进路径，恢复粒度也只能达到小时级。

### 分钟采集继续使用 LLM Agent

未采用。采集动作完全确定，LLM 不增加决策价值，却显著增加启动时间和失败面。

### 直接由采集脚本请求 Wazuh 和写入 SQLite

未采用。这会绕过 OctoBus 的能力授权和调用审计，并破坏 SecurityOps 的数据所有权。

### 仅依赖 webhook 重试，不引入租约

未采用。旧 Agent 可能在恢复任务之后迟到写入，无法保证状态不会被覆盖。

## 结果

正向结果：

- 分钟采集耗时可预测，不再与小时级 Agent 碰撞；
- agent-compose 明确承担定时和事件两类编排；
- OctoBus 成为每次业务调用的强制边界；
- 超时、重试和迟到写入具有可证明的幂等与围栏语义；
- 研判逻辑、知识、工单和飞书投递仍由同一个业务状态机闭环。

代价与后续工作：

- SecurityOps 需要新增租约、恢复、授权记录和 ordered migration；
- agent-compose 项目需要增加确定性 intake 定义并删除小时任务；
- webhook outbox 需要区分 initial 与 recovery attempt；
- 部署和验证文档必须同步新触发模型。

## 不变量

- Wazuh 是唯一告警入口；
- agent-compose 是唯一调度和 Agent Runtime；
- OctoBus 是所有业务接口调用的唯一入口；
- SecurityOps 是业务状态唯一事实源；
- 每条终态必须能从 `event_id` 追溯到 Agent 运行、OctoBus 审计、SQLite、工单和飞书投递。
