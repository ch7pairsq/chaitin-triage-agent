# Wazuh Connector

该目录是独立的 OctoBus service package。它使用最小权限只读账号查询 Wazuh Indexer 的 `wazuh-alerts-*` 索引，并通过 `ListAlerts` unary 方法向获授权的 Agent 提供告警。部署可用 `required_rule_group` 限定安全运营入口；本仓库固定为 `triage_input`，避免把 Wazuh 自身运维事件误送入研判队列。

运行时强制 TLS 校验；使用自签名证书时，将 CA 文件放入 instance workdir 并设置 `ca_path`，不得关闭证书校验。账号密码只写入 OctoBus instance secret。

```bash
npm ci
npm run check
npm test
npm run validate:package
npm pack --dry-run
```
