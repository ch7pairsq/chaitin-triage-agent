# Wazuh Stack

该目录基于 Wazuh 官方 `wazuh-docker` v4.14.7 single-node 配置整理，保留其 GPLv2 许可边界，并增加本项目所需的 syslog 入口、三领域告警规则、只读告警账号和 Portainer 绝对路径挂载。

所有密钥来自仓库根目录 `.env`。证书和 `generated/` 文件在宿主机生成，不提交到 Git。完整初始化或更新推荐使用统一入口：

```sh
cd /data/chaitin/chaitin-triage-agent
sudo sysctl -w vm.max_map_count=262144
/bin/sh deploy/update-stacks.sh --mode interactive --phase all
```

统一入口在根 CA 不存在时先运行仓库中的 `generate-indexer-certs.yml`，再执行 `prepare-config.sh`。准备脚本把公开的 `root-ca.pem` 设为 `0444`，供 Wazuh 组件和 OctoBus connector 共同只读使用；凭据配置保持 `0600`，私钥权限不放宽。

`wazuh-role-bootstrap` 会等待 Indexer 可用，然后幂等创建 `triage_alert_reader`：集群权限仅为 `cluster_composite_ops_ro`，索引权限仅为 `wazuh-alerts-*` 的 `read`，并映射到 `triage_reader`。该容器应以 0 退出：

```sh
docker wait wazuh-role-bootstrap
test "$(docker inspect --format '{{.State.ExitCode}}' wazuh-role-bootstrap)" = 0
```

Stack 固定使用 `chaitin-net` 的 `172.30.0.0/24`。Wazuh syslog UDP 514 只在该 Docker 网络内开放；manager、Indexer 和 dashboard 的宿主机端口均绑定 `127.0.0.1`。

Portainer 使用本目录的 `docker-compose.yml` 新建或更新 Stack，并设置与根 `.env` 一致的变量。`REPO_ROOT` 必须是宿主机 clone 的绝对路径；Portainer 和统一脚本使用的是同一份已提交 Compose 文件。

`wazuh-event-injector` 默认不自动发送。它提供 `quick`、`acceptance`、`coverage` 三组共 99 条可显式选择的验证事件；执行时使用 `INJECT_SCENARIO_ID`，或同时指定 `INJECT_PROFILE` 与 `INJECT_SEQUENCE`。每次单次执行都由输入参数确定事件，不依赖容器或 Node 进程中的历史计数。
