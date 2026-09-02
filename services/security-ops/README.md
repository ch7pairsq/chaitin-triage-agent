# SecurityOps OctoBus Service

该目录是独立的 OctoBus 业务服务包，负责 Wazuh 告警接入、业务 SQLite、确定性策略、人工工单、飞书投递和 trace 查询。它不导入 Agent 源码，Agent 也不得导入本目录源码。

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
