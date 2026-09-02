# Wazuh Stack

该目录基于 Wazuh 官方 `wazuh-docker` v4.14.7 single-node 配置整理，保留其 GPLv2 许可边界，并增加本项目所需的 syslog 入口、三领域测试事件规则、只读告警账号和 Portainer 绝对路径挂载。

所有密钥来自仓库根目录 `.env`。证书和 `generated/` 文件在宿主机生成，不提交到 Git。

```sh
cd /data/chaitin/chaitin-triage-agent
sudo sysctl -w vm.max_map_count=262144

docker compose --env-file .env \
  -f deploy/stacks/wazuh/generate-indexer-certs.yml run --rm generator

/bin/sh deploy/stacks/wazuh/prepare-config.sh .env

docker compose --env-file .env \
  -f deploy/stacks/wazuh/docker-compose.yml up -d --build
```

`prepare-config.sh` 会把公开的 `root-ca.pem` 设为 `0444`，供 uid 1000 的 Wazuh 组件和 uid 999 的 OctoBus Wazuh connector 共同只读使用。生成配置仍为 `0600`，私钥权限不会放宽。

`wazuh-role-bootstrap` 会等待 Indexer 可用，然后幂等创建 `triage_alert_reader`：集群权限仅为 `cluster_composite_ops_ro`，索引权限仅为 `wazuh-alerts-*` 的 `read`，并映射到 `triage_reader`。该容器应以 0 退出。

```sh
docker wait wazuh-role-bootstrap
test "$(docker inspect --format '{{.State.ExitCode}}' wazuh-role-bootstrap)" = 0
```

Stack 固定使用 `chaitin-net` 的 `172.30.0.0/24`。Wazuh syslog UDP 514 只在该 Docker 网络内开放；manager、Indexer 和 dashboard 的宿主机端口均绑定 `127.0.0.1`。

Portainer 使用本文件 `docker-compose.yml` 新建 Stack，并设置与根 `.env` 一致的变量。`REPO_ROOT` 必须是宿主机 clone 的绝对路径，例如 `/data/chaitin/chaitin-triage-agent`。
