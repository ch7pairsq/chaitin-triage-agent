# Wazuh Connector

该目录是独立的 OctoBus service package。它使用最小权限只读账号查询 Wazuh Indexer 的 `wazuh-alerts-*` 索引，并通过 `ListAlerts` unary 方法向获授权的 Agent 提供告警。部署可用 `required_rule_group` 限定安全运营入口；本仓库固定为 `triage_input`，避免把 Wazuh 自身运维事件误送入研判队列。

运行时强制 TLS 校验；使用自签名证书时，将 CA 文件放入 instance workdir 并设置 `ca_path`，不得关闭证书校验。账号密码只写入 OctoBus instance secret。

分钟采集程序只能通过 OctoBus `wazuh-ingress` 调用该服务，不能直连 Indexer。查询默认 `minimum_rule_level=0`，真正的入口约束是 `required_rule_group=triage_input`，避免使用缺乏数据依据的单一等级阈值。单次请求最长 8 秒，仅对超时、HTTP 429 和 5xx 再尝试一次，包含退避的总预算小于 17 秒，从而受分钟任务 25 秒硬超时约束。

```bash
npm ci
npm run check
npm test
npm run validate:package
npm pack --dry-run
```
