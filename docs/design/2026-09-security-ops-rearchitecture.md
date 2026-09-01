# develop 分支独立复现、能力服务拆分与三领域安全运营知识方案（最终修订版）

## 1. 目标与约束

本方案把安全告警研判改造为可在一台新服务器上由单个 Git 仓库独立复现的业务闭环。Wazuh 是唯一告警入口，agent-compose 负责原生事件触发、小时级调度与 Agent Runtime，OctoBus 是所有业务接口调用的唯一能力网关。`wazuh-connector` 独立封装 Wazuh 只读查询，`security-ops` 独占业务状态、确定性策略、人工工单和飞书投递。

必须满足以下约束：

- 一次 clone 可取得构建、配置、迁移、知识、测试和部署所需的全部非敏感资产；
- Agent 不直接连接 Wazuh、SQLite、飞书、GitHub 或模型之外的业务后端；
- Agent 的业务动作只通过 agent-compose 注入的 OctoBus MCP 工具完成；
- 所有业务接口均通过 OctoBus 的 `capset -> service -> instance -> method` 路由；
- 业务服务与 Agent 位于同一仓库，但可独立构建、测试、打包、升级和回滚；
- 只使用 SQLite，不引入 PostgreSQL；控制面数据库与业务数据库按所有权分离；
- 所有结论均需证据引用，所有路径均创建人工工单并进入飞书投递队列；
- 知识按内部安全运营经验整理，不宣称历史发生数量、准确率或线上验证结果；
- 不执行服务器重启验证。

## 2. 组件与所有权

```text
agent-compose minute scheduler
  -> Agent Runtime
    -> OctoBus / wazuh-ingress capset
      -> WazuhConnector.ListAlerts
      -> SecurityOps.IngestAlertEvent
      -> triage.db + trigger_outbox
        -> agent-compose webhook event
          -> scheduler.on("webhook.wazuh.alert")
            -> Agent Runtime
              -> OctoBus MCP / triage-runner capset
                -> SecurityOps methods
                  -> triage result + manual ticket + Feishu outbox

hourly scheduler
  -> Agent Runtime
    -> OctoBus MCP / triage-runner capset
      -> ListPendingAlerts / triage methods / GetTriageTrace
```

数据库所有权固定为：

1. agent-compose 控制数据库：项目、事件、调度、Run 与 sandbox 状态；
2. OctoBus 控制数据库：service、instance、capset 与路由注册；
3. SecurityOps 业务数据库 `triage.db`：告警、研判、工单、投递与业务 trace。

三类数据库不得互相承担对方职责。业务 `triage.db` 位于 SecurityOps instance workdir，不挂载进 Agent guest。

## 3. SecurityOps 独立服务

目录固定为 `services/security-ops/`，服务名为 `security-ops`，运行实例名为 `security-ops-main`，Proto 服务为 `security.ops.v1.SecurityOpsService`。服务包必须具备独立的 `package.json`、`service.json`、Proto、配置与密钥 schema、运行入口、迁移、测试和打包白名单。

全部接口采用 unary RPC：

- `IngestAlertEvent`
- `ListPendingAlerts`
- `ClaimAlert`
- `GetAlertContext`
- `EnrichAlert`
- `MatchKnowledge`
- `EvaluatePolicy`
- `RecordTriageResult`
- `CreateManualTicket`
- `QueueFeishuNotification`
- `FinalizeTriage`
- `GetTriageTrace`
- `RecoverDelivery`

Proto3 字段仍在运行时做强制校验。服务使用稳定错误码分支：`INVALID_ARGUMENT`、`NOT_FOUND`、`FAILED_PRECONDITION`、`UNAUTHENTICATED`、`PERMISSION_DENIED`、`UNAVAILABLE`、`DEADLINE_EXCEEDED`、`RESOURCE_EXHAUSTED`、`INTERNAL`。

`EvaluatePolicy` 返回确定性 `decision`、`action`、`evidenceRefs`、`knowledgeRefs`、`ticketRequired`、`policyStatus`、`autoCloseAllowed` 和与当前 trace 绑定的签名 `decisionToken`。`RecordTriageResult` 只接受 `decisionToken` 与模型说明文本，服务端根据 token 重建权威结论，Agent 不能改写判定；相同请求可安全重试，但 token 不能跨 trace 使用或被修改。

告警领域、攻击类型、上下文和证据由 SecurityOps 从 Wazuh 告警字段提取并返回，Agent 只能消费服务端结果。缺少可信分类时，服务端固定回退为 `domainId=unclassified`、`attackTypeId=other_attack` 并转人工分类，不允许 Agent 自行补全领域或攻击类型。

Wazuh 查询能力独立位于 `services/wazuh-connector/`，运行实例名为 `wazuh-indexer`，只提供 `wazuh.connector.v1.WazuhConnectorService/ListAlerts`。该实例使用 TLS、固定 CA、`triage_reader` 账号和仅允许 `wazuh-alerts-*` read 的 `triage_alert_reader` 角色；不得使用 `readall`。

## 4. 入口、事件与补偿

agent-compose 每分钟创建 poll Agent。该 Agent 先经 `wazuh-ingress` 调用 `ListAlerts`，再对返回告警调用 `IngestAlertEvent`。SecurityOps 在同一事务中写入 `ingress_events` 与 `trigger_outbox`，随后后台投递器仅向 agent-compose 发送 `{eventId, correlationId}`：

```text
POST /api/webhooks/webhook.wazuh.alert
Idempotency-Key: <eventId>
X-Correlation-ID: <wazuhAlertId>
Authorization: <internal source token>
```

HTTP `202` 只代表控制面接收事件，不代表业务完成。SecurityOps 负责业务幂等、触发重试和小时级补偿。`ListPendingAlerts` 同时返回尚未领取的 `pending` 事件，以及业务 run 仍为 `processing` 的未完成事件，使事件触发中断后可由小时任务重新进入幂等主链。事件触发与小时级任务都使用 `sandboxPolicy: new`，不得使用 `scheduler.exec`、`scheduler.shell` 或固定 Node CLI。

GitHub 发布 webhook 独立为接收器和 worker。接收器校验原始请求体的 `X-Hub-Signature-256`、使用常量时间比较、按 delivery ID 持久化去重，并限制仓库、`develop` 分支和精确 commit SHA；它没有代码目录和 Docker Socket。worker 不监听端口，只接受最小发布请求，校验工作树、分支、origin 与远端 SHA，使用 `fetch` 和 `merge --ff-only` 更新。agent-compose 不负责部署或重启自身。

## 5. 权限与 capset

采用三个显式最小权限 capset，并分别配置 token：

| capset | 使用方 | 方法范围 |
| --- | --- | --- |
| `wazuh-ingress` | 分钟轮询 Agent | `ListAlerts`、`IngestAlertEvent` |
| `triage-runner` | 事件/小时 Agent | 研判主链业务方法与只读 trace |
| `triage-ops` | 运维验证与补偿 | `GetTriageTrace`、`RecoverDelivery` |

OctoBus 管理 token 与三类业务 token 分离。新增方法不会自动进入已有 capset；服务升级后必须显式校验和重绑方法。

## 6. 业务 SQLite

`triage.db` 使用 WAL、外键、busy timeout、版本迁移、事务和唯一幂等键。首版表如下：

- `schema_migrations`
- `ingress_events`
- `trigger_outbox`
- `alert_claims`
- `triage_runs`
- `triage_steps`
- `policy_decisions`
- `triage_results`
- `manual_tickets`
- `delivery_outbox`
- `knowledge_versions`

关联链固定为：

`Wazuh alertId -> business eventId -> agent-compose eventId -> schedulerRunId -> sandboxId -> business traceId -> ticketId / feishuDeliveryId`。

OctoBus access log 只证明路由、capset、instance、method、状态与耗时；精确业务审计以 `GetTriageTrace` 和 `triage.db` 为准。

## 7. 三领域安全运营知识

知识覆盖三个领域：

- 车联网平台：T-Box、车载网关、OTA、车云平台、设备管理、GB/T 32960、JT/T 808、MQTT、HTTP；
- 物联网平台：IoT 网关、设备管理、消息代理、OTA、设备身份、MQTT、CoAP、HTTP；
- 工业互联网平台：工业网关、PLC、工程站、SCADA、MES、OPC UA、Modbus/TCP、S7。

统一为 33 类攻击，三领域各一条基础运营知识，共 99 条。重复的暴力破解名称归一为一个 canonical ID 和别名。请求伪造、文件包含、XSS、拒绝服务等保留明确子类型；命令执行、代码执行与系统代码执行保持独立边界。`other_attack` 始终转人工。

每条知识至少包含：领域、攻击类型、别名与子类、适用性、按领域收敛的资产与协议、领域关注点、33 类攻击各自独立的首要可观察信号与证据、Wazuh 映射、所需遥测、正反证据、失效条件、误报与漏报条件、绕过点、不可单独使用字段、建议动作、版本、来源、消费方和复核状态。

知识初始为 `reviewStatus=draft`，只有人工改为 `approved` 后才进入运行包。`reviews.json` 保存逐条检查项和针对攻击类型、领域范围的复核批注，自动检查不代替批准人签署。来源标记为 `internal_security_operations_experience`，说明为“内部安全运营经验整理”。所有知识固定：

- `policyStatus=operational_knowledge`
- `autoCloseAllowed=false`
- `ticketRequired=true`
- `evidencePolicy.kind=minimum_independent_evidence`
- `evidencePolicy.minimumIndependentEvidence=2`
- `evidencePolicy.statisticalThreshold=false`

这里的“至少两项独立证据”是保守的运营证据门槛，不是从历史事件统计得到的概率阈值。任何频率、比例、风险分数或自动化阈值只有在引用已完成人工复核的 Wazuh 告警与工单记录后才能校准；当前知识不得据此声称准确率或生产统计结论。

每条知识配四条结构化测试记录：攻击证据充分、授权或良性活动、证据不足、复合或重复活动，共 396 条。这些记录只位于 `knowledge-authoring/test-fixtures/`，不进入运行知识包，不计为历史事件，不出现在知识查询或飞书消息中。

Wazuh 可观察性使用 `full`、`partial`、`false`。`partial` 或 `false` 必须列出额外遥测并转人工，不能把 Wazuh 不具备的数据源写成已可见证据。

## 8. 决策、工单与飞书

当前策略不自动关闭：

- 证据充分：`escalate_with_manual_review`
- 授权或良性特征充分：`suppress_with_manual_review`
- 证据缺失：`request_additional_evidence`
- 未匹配或其他攻击：`manual_classification`

四条路径均记录研判结果、创建人工工单、进入飞书 outbox 并最终落终态。飞书凭据只存在 SecurityOps instance secret。飞书超时、429、5xx 采用可审计重试，超过上限进入人工恢复。

## 9. 独立复现与发布

部署分为三个 Stack：Wazuh、triage-platform、release-webhook。所有 Stack 使用 `${REPO_ROOT}` 指向同一份宿主机 `develop` 工作树，适用于 Docker Compose 与 Portainer。新服务器流程为：clone `develop`、校验锁定版本、构建两个 OctoBus service package、校验 99 条已批准知识和 396 条测试记录、启动 Wazuh、创建最小权限 Indexer 角色、导入 service/instance/capset、检查 descriptor/catalog/MCP、启动 agent-compose、配置独立 webhook source、验证两次事件触发和两次小时补偿、核验 trace/工单/飞书。

两个 service package 使用锁定依赖、pack dry-run 和 descriptor 校验。`bootstrap.sh` 每次先清除旧 instance binding，再按精确 method 重建；服务或 descriptor 更新失败时不扩大 capset 权限。Portainer 容器回滚不能替代 service package 与 method binding 的一致性检查。

## 10. 完成标准

- SecurityOps 可独立 install、check、test、pack；
- Agent 与 SecurityOps 源码无相互 import；
- 3 个领域、33 类攻击、99 条 approved 知识、396 条测试记录全部通过结构校验；
- 运行知识包不包含测试记录，且所有知识 `autoCloseAllowed=false`；
- Wazuh 测试日志注入后产生真实 Wazuh alert；
- Agent 一次运行调用多个 OctoBus MCP 方法，且无业务外部直连；
- 任一结果均产生唯一工单和唯一飞书 outbox，完整流程验证只接受 delivery=`delivered`；
- 重复事件不重复创建结果、工单或通知；
- 两次事件触发和两次小时补偿完成；
- `GetTriageTrace` 可证明完整业务链；
- README 命令可在新服务器按顺序执行；
- 文档不包含无证据的历史数量、准确率、线上验证或自动关闭声明。
