# Release Webhook Stack

该 Stack 与 Agent 业务运行面隔离。`release-webhook` 只校验 GitHub 原始请求体 HMAC、仓库、`develop` 分支、commit SHA 和 delivery ID，并将最小部署请求写入持久卷；它没有代码目录和 Docker Socket。

`release-worker` 不监听端口，独占代码目录和 Docker Socket。它只接受接收器生成的固定结构请求，要求工作树干净、当前分支正确、origin 与允许仓库一致，并只执行 `fetch` 与 `merge --ff-only`。部署阶段使用仓库中的固定 Stack 和验证脚本；失败结果持久化，不强制覆盖本地状态。

默认端口仅绑定 `127.0.0.1:9080`。对 GitHub 发布时必须通过已有 HTTPS 反向代理转发 `/webhooks/github`，不得直接暴露明文公网端口。GitHub Webhook 事件只选择 `push`，Content type 使用 `application/json`，Secret 与根目录 `.env` 的 `GITHUB_WEBHOOK_SECRET` 相同。

```sh
/bin/sh deploy/stacks/release-webhook/prepare-config.sh .env
docker compose --env-file .env -f deploy/stacks/release-webhook/docker-compose.yml up -d --build
```
