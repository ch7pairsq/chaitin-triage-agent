# Release Webhook Stack

该 Stack 与业务运行面隔离。`release-webhook` 只校验 GitHub 原始请求体 HMAC、仓库、`develop` 分支、commit SHA 和 delivery ID，并将最小更新请求写入持久卷；它不挂载代码目录或 Docker Socket。

`release-worker` 不监听端口。它在仓库、分支、提交祖先关系、origin 和工作树状态全部通过校验后，只调用仓库根目录的 `deploy/update-stacks.sh`。脚本先更新 Wazuh 和 triage platform、执行 bootstrap，再进入独立的 release 阶段替换发布组件；若 worker 因自身替换而结束，新 worker 会根据持久化阶段继续最终验证，不会重复合并提交。

默认端口仅绑定 `127.0.0.1:9080`。对 GitHub 发布时必须通过 HTTPS 反向代理转发 `/webhooks/github`。GitHub Webhook 事件只选择 `push`，Content type 使用 `application/json`，Secret 与根目录 `.env` 的 `GITHUB_WEBHOOK_SECRET` 相同。

服务器手工更新与 webhook 更新共用同一组 Compose 文件和同一个更新脚本：

```sh
/bin/sh deploy/update-stacks.sh --mode interactive --phase all
```

若只需首次单独启动接收端，可先生成密钥文件，再使用本目录中已提交的 Compose 文件：

```sh
/bin/sh deploy/stacks/release-webhook/prepare-config.sh .env
docker compose --env-file .env -f deploy/stacks/release-webhook/docker-compose.yml up -d --build
```

每次完整更新都会在 `/data/chaitin/backups/chaitin-triage-agent` 生成 commit、配置和 SQLite 三类备份；每个备份文件名均包含 `backup-YYYYMMDD-HHMMSS`。
