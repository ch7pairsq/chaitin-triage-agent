# SecurityOps OctoBus Service

该目录是独立的 OctoBus 业务服务包，负责 Wazuh 告警接入、可执行知识、业务 SQLite、确定性策略、人工工单、飞书投递和 trace 查询。它不导入 Agent 源码，Agent 也不得导入本目录源码。

```powershell
cd services/security-ops
npm run check
npm test
npm run pack:check
```

运行配置由 OctoBus instance 注入。真实密钥只能进入 instance secret，禁止写入仓库、命令行或日志。

服务提供 16 个 unary methods。`wazuh-ingress` 仅获得接入和停滞恢复方法，`triage-runner` 仅获得 `ClaimAlert` 及后续 8 个租约化研判方法，`triage-ops` 独占 trace、人工投递恢复、授权记录和 `GetWorkerReadiness`。所有业务调用由 OctoBus 完成路由、最小权限授权与审计，Agent 不直接访问本服务、SQLite 或飞书。

研判结果、人工工单和飞书 `delivery_outbox` 分开持久化：业务完成不等于通知已送达，飞书失败不会回滚结果或工单。可重试错误使用有界指数退避，第 9 次仍失败或不可重试错误进入 `manual`；readiness 返回 backlog、manual 数、oldest pending age、active batch 和 last error。进程收到停止信号后不再领取新投递，并在最长 10 秒内等待当前批次结束。

授权降噪只认可通过 `triage-ops` capset 写入的授权记录。记录必须处于 active 状态、在有效期内、与告警资产/账号/规则/变更窗口精确匹配并包含证据引用。告警负载中的布尔标记不具备授权效力，缺失、过期、撤销或范围不匹配时按普通告警继续研判。

`knowledge-rule-engine.js` 只执行白名单路径和有限操作符。`MatchKnowledge` 和 `EvaluatePolicy` 根据当前 `claimToken + traceId` 从已接入告警重建权威上下文，不接收 Agent 转抄的领域、事件类型、上下文或知识候选；前者在同领域执行规则且事件类型只作提示，后者再次执行并把评估摘要写入 `policy_decisions.evaluation_json`。缺事实、排除命中、确认命中和事实完整但未匹配分别进入补证、带人工复核的降噪、升级和人工分类。`RecordTriageResult` 在同一租约围栏内直接绑定已持久化策略，不生成或记录需要 Agent 转抄的第二套决策令牌。
