# develop 分支独立复现、能力服务拆分与三领域安全运营知识方案（确定性采集修订版）

## 1. 目标与约束

本方案把安全告警研判建设为可在一台新 Linux 服务器上由单个 Git 仓库独立复现的业务闭环。Wazuh 是唯一告警入口，agent-compose 负责确定性定时采集和事件驱动的 Agent Runtime，OctoBus 是所有业务接口调用的唯一能力网关。`wazuh-connector` 独立封装 Wazuh 只读查询，`security-ops` 独占业务状态、知识匹配、确定性策略、人工工单和飞书投递。

必须满足以下约束：

- 一次 clone 可取得构建、配置、迁移、知识、测试和部署所需的全部非敏感资产；
- Agent 和定时采集程序不直接连接 Wazuh、SQLite、飞书或其他业务后端；
- agent-compose 内的业务动作只通过 OctoBus 注入的能力完成；
- 所有业务接口均通过 OctoBus 的 `capset -> service -> instance -> method` 路由；
- 业务服务与 Agent 位于同一仓库，但可独立构建、测试、打包、升级和回滚；
- 只使用 SQLite，不引入 PostgreSQL；控制面数据库与业务数据库按所有权分离；
- 所有研判结论均需证据引用，所有处置路径均创建人工工单并进入飞书投递队列；
- 知识记录可执行条件、反例、失效边界和可核验来源；仓库用例不宣称生产历史数量或准确率；
- 不执行服务器重启验证。

## 2. 最终架构与组件所有权

```text
agent-compose scheduler: wazuh-intake（每分钟、确定性程序）
  -> OctoBus / wazuh-ingress
    -> WazuhConnector.ListAlerts
    -> SecurityOps.IngestAlertEvent
    -> SecurityOps.RequeueStalledAlerts
      -> triage.db + trigger_outbox
        -> agent-compose webhook: webhook.wazuh.alert
          -> triage-operator（真正的 LLM Agent）
            -> OctoBus / triage-runner
              -> ClaimAlert / GetAlertContext / EnrichAlert
              -> MatchKnowledge / EvaluatePolicy / RecordTriageResult
              -> CreateManualTicket / QueueFeishuNotification / FinalizeTriage
                -> triage.db + 人工工单 + 飞书

运维与审计
  -> OctoBus / triage-ops
    -> GetTriageTrace / RecoverDelivery / PutAuthorizationRecord
```

### 2.1 agent-compose

同一项目内定义两个职责分离的 agent：

| agent | 触发方式 | 是否使用 LLM | 并发策略 | 沙箱 | 超时 | 职责 |
|---|---|---:|---|---|---:|---|
| `wazuh-intake` | `* * * * *` | 否 | `skip` | `sticky` | 25 秒 | 每分钟执行一次固定采集周期 |
| `triage-operator` | `webhook.wazuh.alert` | 是 | `parallel` | `new` | 3 分钟 | 消费单条告警事件并完成研判闭环 |

`wazuh-intake` 只允许一次 `scheduler.exec`，执行仓库内固定入口，不接收可拼接的任意命令。它的输出固定为：

```json
{
  "success": true,
  "polled": 0,
  "ingested": 0,
  "duplicates": 0,
  "requeued": 0,
  "manualized": 0,
  "durationMs": 0
}
```

`triage-operator` 是唯一执行开放式研判的 Agent。提示词必须携带结构化输出 schema，scheduler 对纯 JSON 或唯一 JSON 代码块执行相同的严格字段、类型、计数和模式校验，以兼容不原生支持结构化输出的 `chat_completions` 服务；多份 JSON、缺字段或额外字段都必须失败。它不能直接访问数据库、HTTP 接口或宿主机文件，只能使用 `triage-runner` capset 暴露的方法。

不再保留小时级完整 Agent 调度。分钟级任务负责实时采集，停滞任务由每分钟周期中的确定性恢复步骤处理，避免整点并发碰撞、重复成本和双重状态机。

### 2.2 OctoBus

OctoBus 是业务能力的唯一入口，不是旁路审计组件。所有 Agent 与定时采集程序的业务调用都必须经过 OctoBus；服务发现、方法授权、参数校验、超时和调用审计均在此边界生效。

服务包必须携带 Proto、descriptor、配置 schema 和运行入口。部署时先注册 service，再创建 instance，最后按精确 method 绑定 capset；服务升级后新增方法不会自动继承旧权限。OctoBus 访问日志用于证明路由、capset、instance、method、状态和耗时，精确业务状态仍以 `GetTriageTrace` 和 `triage.db` 为准。

禁止以下旁路：

- Agent 直接请求 Wazuh API；
- Agent 直接读写 SQLite；
- Agent 或脚本直接调用飞书 Webhook；
- Agent 直接调用 SecurityOps gRPC 地址；
- 用宿主机脚本复制 SecurityOps 的业务判断。

### 2.3 WazuhConnector

`wazuh-connector` 只拥有 Wazuh API 凭据和游标状态，提供只读、分页、可重试的告警查询。默认筛选 `rule.groups=triage_input`，`minimum_rule_level` 设置为 `0`，不再使用缺乏依据的固定等级门槛。

Indexer 使用固定 CA、专用 `triage_reader` 账号和只允许读取 `wazuh-alerts-*` 的最小权限角色，不使用全局只读或管理角色。

Wazuh 请求超时为 8 秒，最多执行 2 次尝试，只对超时、HTTP 429 和 5xx 使用带抖动的短退避；单次采集中的 Wazuh 调用总预算不得超过 17 秒。

### 2.4 SecurityOps

SecurityOps 是业务事实源，独占：

- 告警幂等入库与事件 outbox；
- 领取租约、恢复次数、步骤状态和 trace；
- 证据富化、白名单规则解释、知识匹配和确定性策略；
- 研判结果、人工工单和飞书投递 outbox；
- 授权记录的有效期、范围和撤销状态；
- 投递 backlog、manual 数、最老待处理时长、当前批次和最近错误等 readiness 状态。

SecurityOps 不运行 LLM，不直接承担 agent-compose 的触发和编排职责。

### 2.5 SQLite 所有权

仅使用 SQLite，但不同所有者不得共享数据库文件：

- agent-compose 控制面数据库：调度、运行记录、webhook 事件；
- OctoBus 控制面数据库：服务、实例、capset 与调用审计；
- `triage.db`：SecurityOps 业务状态、工单、outbox 和授权记录；
- Wazuh 自有索引和状态不计入业务 SQLite。

## 3. 主链路设计

### 3.1 分钟级确定性采集

每分钟由 `wazuh-intake` 执行一个有界周期：

1. 通过 `wazuh-ingress` 调用 `WazuhConnector.ListAlerts`；
2. 对返回告警逐条调用 `SecurityOps.IngestAlertEvent`；
3. 调用 `SecurityOps.RequeueStalledAlerts` 扫描停滞任务；
4. 输出固定统计 JSON 后退出。

告警入库和初始触发 outbox 必须处于同一事务。相同 `source + external_alert_id` 只产生一个 `event_id`，重复采集只累计重复计数，不创建重复研判和工单。

无告警周期目标为 5 至 10 秒，硬超时为 25 秒。连续 10 次空轮询必须全部在 30 秒内完成。完整 Agent 研判不承诺 30 秒内结束，其独立运行上限为 3 分钟。

手工验证分钟任务使用：

```bash
agent-compose -p chaitin-triage-agent scheduler invoke wazuh-intake \
  --payload '{"mode":"cycle"}' --timeout 30s
```

不使用 `scheduler trigger` 作为手工入口。

### 3.2 事件投递与 Agent 编排

SecurityOps outbox worker 把待投递事件发送到 agent-compose 原生 webhook，事件名固定为 `webhook.wazuh.alert`。事件 payload 只携带定位和幂等所需字段，不携带可被信任的研判结论。

webhook 返回 HTTP 202 只表示 agent-compose 控制面接受了事件，不代表业务完成。业务完成必须以后续 Agent 终态、OctoBus 调用审计和 SecurityOps trace 共同确认。

`triage-operator` 按以下受控步骤编排：

1. `ClaimAlert` 获取 `claimToken`、`attempt` 和 `leaseUntil`；
2. `GetAlertContext` 获取规范化上下文和证据引用；
3. `EnrichAlert` 生成补充证据；
4. `MatchKnowledge` 在同领域执行已批准知识，事件类型仅作候选提示；
5. `EvaluatePolicy` 在服务端重新执行规则并持久化确定性门控；
6. Agent 基于证据生成结构化叙事；
7. `RecordTriageResult` 在 `claimToken + traceId` 围栏内把叙述绑定到已保存策略；
8. `CreateManualTicket` 创建人工工单；
9. `QueueFeishuNotification` 进入投递队列；
10. `FinalizeTriage` 完成业务终态。

任何步骤失败都不得越过后续校验，也不得直接关闭事件。

### 3.3 领取租约与围栏

`ClaimAlert` 返回以下状态之一：`acquired`、`busy`、`completed`、`manual`。只有 `acquired` 返回新的随机 `claimToken`。

- 数据库只保存 token 哈希；
- `GetAlertContext`、`EnrichAlert`、`MatchKnowledge`、`EvaluatePolicy`、`RecordTriageResult`、`CreateManualTicket`、`QueueFeishuNotification` 和 `FinalizeTriage` 都必须校验 token；
- 每次成功的方法调用刷新 `last_activity_at` 和 `lease_until`；
- 租约过期且被恢复后生成新 token，旧 Agent 的后续写入因围栏校验失败；
- 同一时刻 `claimed + processing` 的总数不得超过 `max_active_triage=2`；
- 事件 outbox 只按可用槽位投递，避免无界并发。

### 3.4 停滞恢复与安全降级

`RequeueStalledAlerts` 使用服务端固定参数，不接受调用方覆盖：

- 每周期最多处理 5 条；
- 连续 3 分钟没有进展视为停滞；
- 每个事件最多恢复 3 次；
- 恢复投递幂等键为 `triage:<eventId>:recovery:<attempt>`。

第一次和第二次恢复会旋转 claim token、增加恢复次数并生成新的 recovery outbox。第三次仍失败时，SecurityOps 进入安全人工态：

- 状态为 `manual`；
- 动作为 `manual_review/request_additional_evidence`；
- 保留失败步骤、错误分类和已有证据；
- 创建人工工单并排队飞书通知；
- 不伪造 Agent 已完成，不自动关闭告警。

### 3.5 飞书与工单

所有正常和降级路径都创建人工工单。飞书失败不能回滚已经保存的研判结果和工单；业务终态与外部投递确认是两个独立状态。投递采用独立 outbox、有限重试和最终人工投递状态。所有 worker 错误必须输出结构化日志，禁止静默吞错。进程关闭时停止领取新批次，并在最长 10 秒宽限期内等待当前批次完成。

## 4. 能力契约与 capset

### 4.1 `wazuh-ingress`

只授予确定性采集程序：

- `WazuhConnector.ListAlerts`
- `SecurityOps.IngestAlertEvent`
- `SecurityOps.RequeueStalledAlerts`

### 4.2 `triage-runner`

只授予 `triage-operator`：

- `SecurityOps.ClaimAlert`
- `SecurityOps.GetAlertContext`
- `SecurityOps.EnrichAlert`
- `SecurityOps.MatchKnowledge`
- `SecurityOps.EvaluatePolicy`
- `SecurityOps.RecordTriageResult`
- `SecurityOps.CreateManualTicket`
- `SecurityOps.QueueFeishuNotification`
- `SecurityOps.FinalizeTriage`

不再暴露小时级扫描所需的 `ListPendingAlerts`。

### 4.3 `triage-ops`

仅供受控运维入口：

- `SecurityOps.GetTriageTrace`
- `SecurityOps.RecoverDelivery`
- `SecurityOps.PutAuthorizationRecord`
- `SecurityOps.GetWorkerReadiness`

`PutAuthorizationRecord` 写入或撤销带有效期和作用域的授权记录。`GetWorkerReadiness` 只返回队列运行状态，不暴露业务载荷或密钥。Agent 无权调用这两类运维方法。

### 4.4 关键返回结构

`ClaimAlert` 至少返回：

```json
{
  "status": "acquired",
  "eventId": "...",
  "claimToken": "...",
  "attempt": 1,
  "leaseUntil": "..."
}
```

`RequeueStalledAlerts` 至少返回：

```json
{
  "scanned": 0,
  "requeued": 0,
  "manualized": 0,
  "eventIds": []
}
```

稳定业务错误码至少包括：`NOT_FOUND`、`ALREADY_EXISTS`、`LEASE_BUSY`、`LEASE_EXPIRED`、`CLAIM_FENCED`、`INVALID_STATE`、`EVIDENCE_REQUIRED`、`AUTHORIZATION_INVALID` 和 `DELIVERY_PENDING`。

## 5. 数据迁移与幂等

保留 `001_initial.sql`，新增 `002_recovery_and_leases.sql`、`003_policy_rule_evaluation.sql` 与 `004_remove_decision_tokens.sql`，服务启动逻辑按文件名顺序执行所有尚未应用的迁移。`004` 在保留既有策略和结果记录的同时移除历史决策令牌列，避免可重放材料进入数据库、Agent 输出或诊断日志。

`002` 至少包括：

- `triage_runs` 增加 `claim_token_hash`、`attempt`、`lease_until`、`last_activity_at`；
- 告警事件增加 `recovery_count`、`next_recovery_at`、`last_recovery_error`；
- 重建 `trigger_outbox`，支持 initial 和 recovery 两类投递；
- 唯一约束 `(event_id, delivery_kind, recovery_attempt)`；
- `idempotency_key` 全局唯一；
- 新增 `authorization_records`，保存状态、作用域、起止时间和证据引用；
- 为停滞扫描、可用槽位和投递重试建立必要索引。

`003` 为 `policy_decisions` 增加 `evaluation_json`，保存规则版本、命中条件、失败条件、排除条件、缺失事实和阈值来源。策略与叙述在同一 SecurityOps 服务内按 `traceId` 和当前租约直接绑定，不再生成需要 LLM 原样转抄的第二套令牌。

部署前必须创建 SQLite 一致性备份；迁移失败时服务不得带着半迁移 schema 启动。

## 6. 事件研判、告警降噪与知识

原有研判和告警降噪逻辑继续保留，但明确边界：

- 领域：车联网平台安全、物联网平台安全、工业互联网平台安全；
- 类型：33 类攻击；
- 每个“领域 × 攻击类型”一条知识，共 99 条；
- 每条知识具有可执行条件、正向边界、反向边界、决策约束、所需证据、人工建议和来源说明；
- 知识只有在审批记录完整、签名校验通过且状态为 approved 时才能进入运行包；
- 运行包只包含运行所需字段，不携带边界测试记录；
- 不保留通用模板批量生成器，知识 JSON 是逐条复核的唯一编写源。

SecurityOps 使用无动态代码执行的规则解释器，只允许限定字段路径和 `equals`、`in`、`gte`、`lte`、`contains_any`、`starts_with`、`truthy`、`exists` 操作。每条 `executableRule` 必须声明：

- `requiredFacts`：缺少任一关键事实即进入补证；
- `confirmWhen`：全部条件和最少任选条件；
- `excludeWhen`：授权、受控测试、签名发布或良性活动条件；
- `thresholdBasis`：来源 ID、明确边界和部署后校准方法。

知识来源登记在 `sources.json`，覆盖 Wazuh 文档、MITRE ATT&CK/ICS、CAPEC、CWE、OWASP、CISA KEV、CNVD 工控、CNNVD、NISTIR 8259 与 UNECE R155。公开条目只用于语义、观察点和外部核验，不能单独触发结论。数值阈值是面向人工复核的保守初始边界，不是准确率或风险评分；部署后按已完成人工复核的 Wazuh 告警和工单滚动校准。

396 条边界用例直接调用生产规则解释器，覆盖 `confirmed`、`excluded`、`insufficient` 和复合场景。测试还必须证明：删除知识后确认匹配消失；删除排除条件会使良性场景误入确认；阈值差一个单位时结果变化；声明字段均被实际消费。若证据不足、来源冲突、事实完整但未命中或缺少关键上下文，必须转为补证或人工分类。

### 6.1 授权降噪

告警中的 `authorizationRecord=true` 只是未经信任的输入，不能单独触发抑制。只有 SecurityOps 能确认以下条件同时成立时，策略才可把活动识别为已授权行为：

- 提供 `authorization_record_id`；
- 数据库中记录为 active；
- 当前时间在有效期内；
- 资产、账号、规则或变更窗口的作用域与告警匹配；
- 授权记录具有非空证据引用。

记录缺失、过期、撤销或范围不匹配时，按普通告警继续研判，不得降噪。

## 7. 故障与降级矩阵

| 故障 | 处理 | 业务结果 |
|---|---|---|
| Wazuh 超时、429、5xx | 8 秒超时，最多 2 次尝试，短退避 | 本轮失败但不推进游标，下轮继续 |
| Wazuh 鉴权或参数错误 | 不重试，结构化记录 | 本轮失败并触发运维告警 |
| 重复告警 | 入库唯一键拦截 | 不重复触发、不重复建单 |
| webhook 暂时失败 | outbox 重试，幂等键保持唯一 | 业务事件不丢失 |
| Agent 超时或崩溃 | 3 分钟停滞后恢复，旋转 token | 最多 3 次后转人工态 |
| 旧 Agent 迟到写入 | claim token 围栏拒绝 | 新运行状态不被覆盖 |
| 知识或证据不足 | 确定性安全门控 | 人工复核并补充证据 |
| 飞书失败 | 独立 outbox 有界重试，第 9 次或不可重试错误转人工 | 研判和工单不回滚，delivery 状态可见 |
| SQLite 迁移失败 | 启动失败并保留备份 | 不运行半迁移版本 |
| 进程终止 | 停止新领取，等待当前批次 | 降低重复和中间态 |

## 8. 部署与独立复现

### 8.1 仓库必须包含

- 根目录依赖锁文件与 workspace 定义；
- agent-compose 项目、两个 agent 定义和 system prompt；
- 两个能力服务的 Proto、descriptor、schema、实现和测试；
- OctoBus 服务、实例和 capset 注册配置；
- Wazuh、业务服务和控制面的 Compose/Stack 文件；
- 全部 SQLite 迁移、99 条运行知识及其批准材料；
- 初始化、部署、更新、验证、备份与回滚脚本；
- `.env.example`，但不包含真实密钥。

### 8.2 两条更新路径与自动更新入口

仓库提供唯一编排源和统一脚本 `deploy/update-stacks.sh`：

- Portainer 手工路径：操作者按同一组 compose 文件更新 Stack；
- 服务器脚本路径：在已 clone 的仓库执行受限更新脚本；
- GitHub webhook 路径：签名验证通过后由 release worker 调用同一脚本的受限模式。

三条入口不得维护不同的部署逻辑。release worker 更新时避免在任务中途先重启自身，待其他服务完成并验证后再切换 release worker。

GitHub webhook 接收器必须基于原始请求体校验 `X-Hub-Signature-256`，采用常量时间比较，并以 delivery ID 持久化去重；随后校验仓库、`develop` ref 和精确 commit SHA。接收器不挂载代码目录和 Docker Socket。无监听端口的 release worker 再校验工作树、分支、origin 与远端 SHA，只允许 `fetch` 和 `merge --ff-only` 后调用统一更新脚本。

所有备份名称统一为：

```text
<purpose>-backup-YYYYMMDD-HHMMSS
```

更新顺序为：配置预检、备份当前提交/配置/SQLite、更新 Wazuh、更新业务服务、执行 bootstrap、更新 release worker、运行验证。失败时按备份记录回滚。

### 8.3 Wazuh 组件

默认保留 manager、indexer、dashboard 和初始化组件。dashboard 仅提供可视化与故障排查，不属于告警研判业务链路；资源紧张时可以通过精简 profile 不启动 dashboard，但默认独立复现路径保留它，便于确认索引、规则和告警状态。

## 9. README 同步要求

实现完成后，README 必须同步修改：

- 架构图改为“确定性分钟采集 + 事件 Agent + 租约恢复”；
- 时序图加入 claim token、租约刷新、恢复 attempt 和旧运行围栏；
- 触发表删除小时级完整 Agent，仅保留分钟调度、webhook 事件和手工 invoke；
- 部署章节同时说明 Portainer、服务器脚本和签名 webhook 三条入口共享同一编排源；
- 验证章节区分空轮询性能、正常事件闭环、恢复闭环、并发上限和重复幂等；
- Wazuh dashboard 明确为可视化组件而非业务依赖；
- 故障章节覆盖 Wazuh、webhook、Agent、SQLite 和飞书的降级与恢复。

## 10. 完成标准

### 10.1 静态与测试

- 两个能力服务独立执行 `npm run check`、`npm test`、`npm pack --dry-run`；
- 根目录测试覆盖契约、迁移、幂等、租约、围栏、恢复、并发和知识完整性；
- 99 条 approved 知识进入运行包，结构和签名验证通过；
- 静态扫描不存在 Agent 直连 Wazuh、SQLite 或飞书的旁路。

### 10.2 干净 clone

在一台无旧数据的新 Linux/Docker 环境中：

1. 只 clone 仓库并填写 `.env`；
2. 执行初始化与部署脚本；
3. 注册 agent-compose 项目和 OctoBus 服务/capset；
4. 验证连续 10 次空轮询均少于 30 秒；
5. 验证至少 2 条正常事件完整闭环；
6. 验证 1 条 Agent 超时事件经过恢复后完成或安全转人工；
7. 验证并发运行不超过 2，重复告警和重复 webhook 不重复建单；
8. 验证飞书失败不回滚工单，恢复投递后 trace 可追溯；
9. 验证 Portainer 与服务器脚本引用同一组编排文件；
10. 验证所有备份名称包含 `backup` 和时间戳。

每次闭环均以 `event_id -> agent run -> OctoBus 调用审计 -> triage.db -> ticket -> Feishu outbox` 为证据链。两轮完整验证通过后才进入最终交付状态。
