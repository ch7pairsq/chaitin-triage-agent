# `chaitin` Portainer Stack 使用说明

仓库根的 [`chaitin-stack.yml`](./chaitin-stack.yml) 是唯一 Stack 模板。本文件不再复制 YAML，避免两份配置发生漂移。

## 更新方式

1. 先把服务器项目目录同步到 GitHub `main` 的目标 commit，并保留原有 root-only `.env`。
2. 通过 SSH 隧道访问服务器回环地址上的 Portainer。
3. 进入 **Stacks → chaitin → Editor**，使用 `chaitin-stack.yml` 核对内容。
4. 保留 Portainer 中既有的 `AUTH_USERNAME`、`AUTH_PASSWORD`、`AUTH_SECRET`、`AGENT_COMPOSE_UI_HTTP_PORT` 环境变量；不得把真实值写入仓库、截图或日志。
5. 点击 **Update the stack**，启用重新拉取镜像的选项并确认更新。
6. 等待 `agent-compose`、`octobus`、`agent-compose-ui` 三个容器运行正常，然后执行：

```sh
cd /data/chaitin/deploy-manifests/chaitin-triage-agent
bash deploy/deploy-and-verify.sh fast-verify
bash deploy/deploy-and-verify.sh smoke
```

## 前置文件与目录

- `/data/chaitin/deploy-manifests/chaitin-triage-agent/.env`：`600 root:root`，包含项目实际配置，禁止输出。
- `/data/chaitin/deploy-manifests/chaitin-triage-agent/deploy/_daemon_entry.sh`：daemon 入口，容器内路径为 `/deploy/chaitin-triage-agent/deploy/_daemon_entry.sh`。
- `/data/chaitin/agent-compose/data/`：daemon 工作区和运行数据。
- `/data/chaitin/octobus/data/`：OctoBus 状态和日志。
- `/data/chaitin/private-knowledge-base/`：私有知识源目录，只读挂载。
- `/data/chaitin/secrets/agent-compose-ui-script-token`：`600 root:root`，UI 本地脚本服务 token。

## 固定边界

- `agent-compose` 与 UI 只绑定服务器 `127.0.0.1`；OctoBus 不发布宿主端口。
- Stack 只维护三个常驻容器；guest 由 daemon 按运行请求创建。
- Stack 更新由 Portainer 完成；`deploy-and-verify.sh` 只负责更新后的项目注册和验证。
- `chaitin-stack.yml` 不包含真实 Secret；真实值只保留在服务器受控文件或 Portainer 环境变量中。
