# Triage Platform Stack

该 Stack 运行 OctoBus、agent-compose daemon 和本机 UI。Wazuh 与 GitHub 发布 webhook 使用各自独立的 Stack；三者只通过固定的 `chaitin-net` 内网和明确接口通信。

从仓库根目录复制 `.env.example` 为 `.env`，填写全部必填项并将权限设为 `0600`。推荐从仓库根目录执行统一入口，它会先完成配置与 Compose 预检，在 `/data/chaitin_backup/chaitin-triage-agent` 创建带时间戳的 commit、配置和 SQLite 备份，然后按固定顺序更新三个 Stack、执行 bootstrap 并验证：

```sh
/bin/sh deploy/update-stacks.sh --mode interactive --phase all
```

`bootstrap.sh` 可重复执行。它会重新导入两个独立 OctoBus service package、更新实例配置、清除旧方法绑定后按最小权限重建三个 capset、轮换各自 token、配置 Wazuh webhook source，并注册 agent-compose 项目。分钟采集仅获得 `wazuh-ingress`，事件研判仅获得 `triage-runner`，人工运维使用独立的 `triage-ops`。

Portainer 手工更新仍受支持，且必须直接选择仓库中的以下文件，不复制或另存 YAML：

- `deploy/stacks/wazuh/docker-compose.yml`
- `deploy/stacks/triage-platform/docker-compose.yml`
- `deploy/stacks/release-webhook/docker-compose.yml`

在 Portainer 更新前，仍需从服务器仓库执行对应的 `prepare-config.sh`；更新 Wazuh 与 triage platform 后执行本目录的 `bootstrap.sh` 和 `verify.sh`。`REPO_ROOT` 必须填写服务器上的当前 clone 绝对路径。

平台状态通过后，执行统一闭环验证：

```sh
/bin/sh deploy/stacks/triage-platform/verify-e2e.sh --empty-cycles 10 --rounds 2 --profile acceptance
```

该入口通过 Wazuh 告警内容、业务 event ID 和 agent-compose run 逐级关联本轮 trace，再调用 `verify-trace.sh` 检查按顺序完成的 OctoBus 方法链、人工工单和飞书投递。分步骤命令和批量限制见仓库根 README 第 9 章。

若已批准的 `services/security-ops/resources/knowledge.jsonl` 不存在，初始化会明确停止，避免未完成审阅的知识进入运行路径。
