# Triage Platform Stack

该 Stack 只运行 OctoBus、agent-compose daemon 和本机 UI。Wazuh 使用独立 Stack；GitHub 发布 webhook 使用另一个独立 Stack。三者仅通过固定的 `chaitin-net` 内网和明确接口通信。

从仓库根目录复制 `.env.example` 为 `.env`，填写全部必填项并将权限设为 `0600`。随后依次执行：

```sh
/bin/sh deploy/stacks/triage-platform/prepare-config.sh
docker compose --env-file .env -f deploy/stacks/wazuh/generate-indexer-certs.yml run --rm generator
/bin/sh deploy/stacks/wazuh/prepare-config.sh
docker compose --env-file .env -f deploy/stacks/wazuh/docker-compose.yml up -d
docker compose --env-file .env -f deploy/stacks/triage-platform/docker-compose.yml up -d
/bin/sh deploy/stacks/triage-platform/bootstrap.sh
```

`bootstrap.sh` 可重复执行。它会重新导入两个独立 OctoBus service package、更新实例配置、清除旧方法绑定后按最小权限重建三个 capset、轮换 capset token、登记 agent-compose 读取受保护目录所需的两个服务端 token、配置 Wazuh webhook source，并注册 agent-compose 项目。目录 token 与对应 capset token 使用同一值，以符合 agent-compose 每个 OctoBus server 只有一个 token 的契约；token 只保存在 daemon 侧，不进入 Agent 沙箱。

若已批准的 `services/security-ops/resources/knowledge.jsonl` 不存在，初始化会明确停止。该检查用于避免草稿知识进入运行路径。
