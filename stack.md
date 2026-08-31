# Stack for the "chaitin" environment (security triage only).
#
# 启动方式（任选其一，二选一即可，演示推荐用 docker compose CLI）：
#   A) docker compose CLI：在服务器 /data/chaitin 目录下执行
#        docker compose --env-file stack.env -f chaitin-stack.yml up -d
#      其中 stack.env 至少定义 AUTH_PASSWORD / AUTH_SECRET，且 chmod 600。
#   B) Portainer → Stacks：粘贴本文档内容（或 git repo + reference），
#      在 Portainer 页面"Environment variables"里填入 AUTH_PASSWORD、
#      AUTH_SECRET，其余占位 `${...:-default}` 会自动处理。
#
# 常驻容器三个：
#   - agent-compose daemon   （Codex Agent 宿主 + Runtime LLM Facade）
#   - octobus                （能力总线网关，仅 chaitin-net 内部通信）
#   - agent-compose-ui       （浏览器控制台，经 Stack 内网反代 daemon）
# 不再编排 demo-console / agent-trigger-bridge / release-runner 等可视化
# 触发与发布容器；触发与验证一律走 SSH +
# `docker exec agent-compose agent-compose ...`，或经 agent-compose-ui
# 浏览器会话发起（仍由 daemon 经能力代理执行，不绕过网关）。
#
# 注意：agent-compose.yml 里的 octobus_servers 使用命名别名 `triage`，
# 因此 agents.<name>.capset_ids 必须使用带前缀形式 `triage/security-triage`；
# 直接写 `security-triage` 会因为"global octobus not configured"被 daemon 拒绝。
# workspace.provider=file + path=. 以 agent-compose.yml 所在目录作为
# workspace root（daemon 端 -f 指向该目录），禁止 `..` 穿越。
#
# Before updating this Stack, the server must already contain:
#   /data/chaitin/deploy-manifests/chaitin-triage-agent/.env          (0600)
#     项目 .env，由管理员手动维护。包含 OCTOBUS_* / SECURITY_TRIAGE_* /
#     WECOM_* 业务凭据，以及 LLM_API_ENDPOINT / LLM_API_KEY / LLM_MODEL
#     三项模型凭据（daemon entrypoint 读取并 export 为 Runtime LLM
#     Facade 的 provider 配置，同时也 export SECURITY_TRIAGE_LLM_* 系列
#     用于 narratorFromEnvironment 直连模式）。
#   /data/chaitin/deploy-manifests/chaitin-triage-agent/deploy/_daemon_entry.sh
#     daemon 入口脚本，负责从项目 .env 读取并正确 export 所有域前缀变量，
#     然后 exec tini → /app/agent-compose daemon。比 stack 内联脚本更完整。
#   /data/chaitin/private-knowledge-base/                              (0750)
#     私有知识库宿主目录，由 agent-compose 卷挂载进 guest 沙箱只读使用。
#   /data/chaitin/agent-compose/data/                                 (0750)
#     daemon 工作区与 sandbox 数据。
#   /data/chaitin/octobus/data/                                       (0750)
#     OctoBus 状态与审计数据。
#   /data/chaitin/secrets/agent-compose-ui-script-token              (0600)
#     agent-compose-ui 本地脚本服务 token（root-only，容器内降权读取）。
# No raw samples, private IOC, OctoBus token, model key, or private key is
# written in this file.

name: chaitin

networks:
  chaitin-net:
    name: chaitin-net

services:
  agent-compose:
    image: chaitin/agent-compose:latest
    container_name: agent-compose
    restart: always
    environment:
      HTTP_LISTEN: 0.0.0.0:7410
      DATA_ROOT: /data
      RUNTIME_DRIVER: docker
      DEFAULT_IMAGE: chaitin/agent-compose-guest:latest
      AGENT_COMPOSE_RUNTIME_BASE_URL: http://agent-compose:7410
      TZ: Asia/Shanghai
    # daemon 通过仓库附带的 _daemon_entry.sh 启动，避免 stack 文档与实际
    # 导出项分叉；该脚本读取项目 .env，导出 LLM（generic + 域前缀）、
#   OctoBus（admin + 各业务域）、Runtime Base URL 等，然后 exec tini daemon。
    entrypoint:
      - /bin/sh
      - -ec
    command:
      - |
        entry=/deploy/chaitin-triage-agent/deploy/_daemon_entry.sh
        [ -e "$$entry" ] || { echo "stack: missing $$entry" >&2; exit 78; }
        [ -x "$$entry" ] || chmod +x "$$entry" 2>/dev/null || true
        exec "$$entry"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc/localtime:/etc/localtime:ro
      - /data/chaitin/agent-compose/data:/data
      - /data/chaitin/deploy-manifests:/deploy:ro
      - /data/chaitin/private-knowledge-base:/data/chaitin/private-knowledge-base:ro
    working_dir: /data/work
    ports:
      - 127.0.0.1:7410:7410
    networks:
      - chaitin-net

  octobus:
    image: ghcr.io/chaitin/octobus:latest
    container_name: octobus
    restart: always
    environment:
      TZ: Asia/Shanghai
    volumes:
      - /data/chaitin/octobus/data:/var/lib/octobus
    # 不发布任何端口：仅在 chaitin-net 内部通信，公网唯一入口是 SSH。
    # agent-compose guest 沙箱经 capset → instance → service → method
    # 四段式 Connect RPC 路由调用，不存在绕过网关直连后端的路径。
    networks:
      - chaitin-net

  # Browser UI for Agent Compose. It authenticates browser users and proxies
  # requests to the daemon through the internal Stack network; it never mounts
  # the Docker socket or private knowledge base.
  # NOTE: Current upstream image used here is chaitin/agent-compose-ui:latest.
  #   Inside the container: nginx listens on 0.0.0.0:8000 (returns 200 on /),
  #   backend app listens on 127.0.0.1:8080 (401/404 on bare paths).  Published
  #   host port 7412 maps -> container :8000 (nginx), so SSH tunnels hit a 200 OK.
  #   Entrypoint is /agent-compose-entrypoint.sh (not /init in this image).
  agent-compose-ui:
    image: chaitin/agent-compose-ui:latest
    container_name: agent-compose-ui
    restart: always
    depends_on:
      - agent-compose
    environment:
      AGENT_COMPOSE_BACKEND: http://agent-compose:7410
      AUTH_ENABLED: "true"
      AUTH_USERNAME: ${AUTH_USERNAME:-admin}
      AUTH_PASSWORD: ${AUTH_PASSWORD:?set AUTH_PASSWORD in stack.env or Portainer env}
      AUTH_SECRET: ${AUTH_SECRET:?set AUTH_SECRET in stack.env or Portainer env}
      UI_DATABASE_PATH: /data/agent-compose-ui.db
      JUPYTER_PROXY_BASE: /jupyter
      NGINX_JUPYTER_PROXY_BASE: /jupyter
    entrypoint:
      - /bin/sh
      - -ec
    command:
      - |
        token_file=/run/secrets/agent-compose-ui-script-token
        test -r "$$token_file"
        SCRIPT_SERVICE_TOKEN="$$(tr -d '\r\n' < "$$token_file")"
        test -n "$$SCRIPT_SERVICE_TOKEN"
        export SCRIPT_SERVICE_TOKEN
        exec /agent-compose-entrypoint.sh nginx -g 'daemon off;'
    volumes:
      - /data/chaitin/agent-compose/ui:/data
      - /data/chaitin/agent-compose/data/sandboxes:/data/sandboxes:ro
      - /data/chaitin/secrets/agent-compose-ui-script-token:/run/secrets/agent-compose-ui-script-token:ro
    ports:
      # 仅绑定回环，公网不可达；外部访问走 SSH 隧道。
      - 127.0.0.1:${AGENT_COMPOSE_UI_HTTP_PORT:-7412}:8000
    healthcheck:
      test: ["CMD-SHELL", "wget -q --spider http://127.0.0.1:8000/ || exit 1"]
      interval: 30s
      timeout: 3s
      start_period: 30s
      retries: 3
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    networks:
      - chaitin-net
