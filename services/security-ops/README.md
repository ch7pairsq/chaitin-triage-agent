# SecurityOps OctoBus Service

该目录是独立的 OctoBus 业务服务包，负责 Wazuh 告警接入、业务 SQLite、确定性策略、人工工单、飞书投递和 trace 查询。它不导入 Agent 源码，Agent 也不得导入本目录源码。

```powershell
cd services/security-ops
npm run check
npm test
npm run pack:check
```

运行配置由 OctoBus instance 注入。真实密钥只能进入 instance secret，禁止写入仓库、命令行或日志。
