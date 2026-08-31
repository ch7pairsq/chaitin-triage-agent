# 安全运营方向-安全告警降噪研判（Chaitin Triage Agent）

**服务器环境：**

> - **登录地址**：`8.147.68.154`
> - **用户名**：`root`
> - **端口**：`22`
> - **私钥登录示例**（PowerShell，私钥路径按实际替换）：
>   `ssh -i "D:\ai_ws_2026\lifetree-pro.pem" root@8.147.68.154`

### 服务器目录与文件总览（根目录：`/data/chaitin/`）

部署采用 **单宿主机 + Docker compose CLI**，所有业务数据、项目源码、凭据、知识库、容器状态卷统一收敛到
`/data/chaitin/` 之下（非分散的 `/var/lib/docker` volume），便于整体备份、迁移与权限审计。
业务知识库与流水线状态由 daemon 自管的本地卷供给（物理路径 `agent-compose/data/volumes/local/<uuid>/data/`，
随宿主 bind mount 持久化，容器重启不丢数据）；`agent-compose.yml` 另声明两个 external Docker 命名卷
（`chaitin-private-knowledge-base`、`chaitin-triage-state`）供 daemon 启动校验，guest 实际挂载以 daemon 本地卷为准。

| 路径（相对 `/data/chaitin/`） | 类型 | 权限 | 作用说明 |
| --- | --- | --- | --- |
| `chaitin-stack.yml` | 文件 | `644 root:root` | 三容器 Stack 定义（`name: chaitin`），等价于 `stack.md` 部署描述；由 `docker compose --env-file stack.env -f chaitin-stack.yml up -d` 启动。含：`agent-compose`（daemon）、`octobus`（能力网关，内网）、`agent-compose-ui`（浏览器控制台） |
| `stack.env` | 文件 | `600 root:root` | **仅** Stack 级环境变量：`AUTH_USERNAME` / `AUTH_PASSWORD` / `AUTH_SECRET` / `AGENT_COMPOSE_UI_HTTP_PORT`（UI 回环绑定端口，默认 `7412`）。**不包含**业务域 / OctoBus / LLM 等项目级凭据。 |
| `deploy-manifests/chaitin-triage-agent/` | 目录 | 混合 | 项目 Git 工作副本 + 运行时配置。daemon 以只读卷 `/deploy:ro` 挂载进容器，由 `agent-compose -p .../deploy-manifests/chaitin-triage-agent up` 注册为项目。 |
| `deploy-manifests/chaitin-triage-agent/.env` | 文件 | `600 root:root` | **项目级唯一真实凭据文件**（OCTOBUS_* / SECURITY_TRIAGE_* / WECOM_* / LLM_API_{ENDPOINT,KEY,MODEL} / SECURITY_TRIAGE_LLM_REAL_CALL）。由 `deploy/_daemon_entry.sh` 在 daemon 启动时读取并正确 export 域前缀变量。严禁 cat / printenv / git commit。 |
| `deploy-manifests/chaitin-triage-agent/agent-compose.yml` | 文件 | `644 root:root` | Codex Agent 声明：`octobus_servers.triage` 原生接入、`capset_ids=triage/security-triage`、`scheduler`（cron `0 * * * *`）、knowledge 只读卷、state 卷、`secret: true` 防止 UI 回显 LLM / token 项。 |
| `deploy-manifests/chaitin-triage-agent/deploy/_daemon_entry.sh` | 文件 | `755 root:root` | daemon 容器入口（见 `chaitin-stack.yml` command）。读取 `.env`，按 SECURITY_TRIAGE_ 前缀导出 Runtime LLM Facade 与 narratorFromEnvironment 所需变量，最后 `exec tini → /app/agent-compose daemon`。 |
| `deploy-manifests/chaitin-triage-agent/deploy/deploy-and-verify.sh` | 文件 | `755 root:root` | 一键部署 / 冒烟 / 重启自愈脚本（本次验证入口）。子命令：`deploy`（完整部署：.env 占位 → 建卷 → `agent-compose up` → 注册 → smoke）、`smoke`（guest 正向研判 A-1001）、`reboot-verify`（容器自恢复）、`help`。**不回显任何 Secret**；失败即非零退出。 |
| `agent-compose/` | 目录 | `755 root:root` | daemon 宿主工作区卷。所有子项均为 daemon 运行态，**验证人员不要手工删除**。 |
| `agent-compose/data/data.db` + `-wal/-shm` | 文件 | daemon 自管 | Codex Agent daemon 主 SQLite（项目 / 触发器 / 运行记录 / scheduler 等）。验证时：`docker exec agent-compose agent-compose project ls` 从该库查询。 |
| `agent-compose/data/workspaces/<hash>/content/` | 目录 | daemon 自管 | daemon 为 guest 启动时复制出的工作副本（即 guest 内 `/data/work` 来源）。带 `.bak*` 的文件是调试时 daemon 打补丁的历史快照，不影响运行。 |
| `agent-compose/data/sandboxes/YYYY/MM/DD/<id>/workspace/` | 目录 | daemon 自管 | 真实 guest 沙箱运行目录（每 run 一份），含执行产物、状态 SQLite WAL、audit.log NDJSON。按 traceId 查找 run 路径从 daemon 运行记录反查即可。 |
| `agent-compose/ui/` | 目录 | daemon 自管 | `agent-compose-ui.db` 与 UI 本地脚本服务运行目录。 |
| `octobus/data/` | 目录 | `999:systemd-journal` | OctoBus 网关状态（capset / instance / service 注册）与 `access.log`（能力调用 NDJSON，含 `trace_id`）。网关仅在 `chaitin-net` 内网运行，**不发布任何公网端口**。 |
| `private-knowledge-base/` | 目录 | `700 root:root` | 私有知识库宿主源目录（3 个结构化语料文件：IOC 证据包 816 条 + 威胁情报语料 + 判定规则证据语料）。由 Stack 只读挂载进 daemon（用于 UI 引用）；guest 容器内 `/knowledge` 实际由 daemon 本地卷供给（见下两行）。 |
| `agent-compose/data/volumes/local/<uuid>/data/`（知识库卷） | 目录 | daemon 自管 | **guest 内 `/knowledge` 的真实数据源**（daemon 本地卷驱动，v2608.5.0 实测：external Docker 命名卷不会被 guest 挂载）。当前 uuid 目录 `4dfc2f22-…/data/` 内为 3 个语料文件（与 `private-knowledge-base/` 源目录 1:1）。更新知识文件的正确做法：先覆盖 `/data/chaitin/private-knowledge-base/` 源目录，再 `cp -a` 同步到该 uuid 目录的 `data/` 下。 |
| `agent-compose/data/volumes/local/<uuid>/data/`（状态卷） | 目录 | daemon 自管 | **guest 内 `/triage-state` 的真实数据源**（当前 uuid 目录 `ca0c07e6-…/data/`）。存放 `security-triage-state.db`（研判记录 SQLite，TR-* 全量递增）、审计 WAL 与执行产物；随宿主 bind mount 持久化，**容器/daemon 重启记录零丢失**（已实测三轮重启验证）。 |
| **`chaitin-private-knowledge-base` / `chaitin-triage-state`** | Docker 命名 volume | `local driver` | `agent-compose.yml` 声明的 external 卷（`external: true`），daemon 启动/建 guest 时校验其存在性（`fast-verify` 亦检查）；若被误删，用 `docker volume create` 重建即可，**不影响 guest 运行与已落盘数据**（真实数据在上两行 daemon 本地卷内）。 |
| `secrets/` | 目录 | `700 root:root` | root 可读的运行时 token。仅保留 **1 个在用文件**： |
| `secrets/agent-compose-ui-script-token` | 文件 | `600 root:root` | `agent-compose-ui` 容器本地脚本服务 token（唯一在用）。由 Stack 以 `/run/secrets/agent-compose-ui-script-token` 只读挂载进 UI 容器，启动时由 entrypoint 读取并注入为 `SCRIPT_SERVICE_TOKEN`。 |

### 常驻容器与端口（`chaitin` Stack）

执行 `docker ps --filter 'name=^(agent-compose|agent-compose-ui|octobus)$'` 可见：

| 容器名 | 镜像 | restart | 端口映射（全部回环或内网） | 角色 |
| --- | --- | --- | --- | --- |
| `agent-compose` | `chaitin/agent-compose:latest` | `always` | `127.0.0.1:7410 → 7410/tcp` | Codex Agent daemon（宿主）+ Runtime LLM Facade。所有真实凭据只进该容器环境，**永不进入 guest**。 |
| `agent-compose-ui` | `chaitin/agent-compose-ui:latest` | `always` | `127.0.0.1:7412 → 8000/tcp`（nginx） | 浏览器控制台（回环绑定）。公网唯一访问方式是 SSH 本地端口转发隧道。含 `healthcheck`（wget `/`）。 |
| `octobus` | `ghcr.io/chaitin/octobus:latest` | `always` | 无端口映射（`chaitin-net` 内部） | 能力网关。沙箱 → capset → instance → service → method 四段式 Connect RPC 路由。access.log（NDJSON）为能力调用的权威审计。 |

**公网监听（`ss -tlnp`）仅应有 `sshd 22`**；其余业务端口均为 `127.0.0.1` 回环或 Docker 内部，安全边界符合要求。

### 验证人员常用入口命令

| 目标 | 命令（服务器 sh 或本地 PowerShell SSH） |
| --- | --- |
| 端到端正向研判一轮（guest 启动 A-1001，含 LLM 真实调用） | `cd /data/chaitin/deploy-manifests/chaitin-triage-agent && bash deploy/deploy-and-verify.sh smoke`（超时 300 s，结果含 `narrativeSource=llm` 与 `recordId`） |
| 重启自愈核验（全部 StartedAt ≥ boot_epoch 且 restart=always） | `cd /data/chaitin/deploy-manifests/chaitin-triage-agent && bash deploy/deploy-and-verify.sh reboot-verify` |
| daemon 项目与触发器列表 | `docker exec agent-compose agent-compose project ls` / `docker exec agent-compose agent-compose schedule list` |
| 从本地浏览器访问 UI（SSH 隧道） | PowerShell 前台：`ssh -i "D:\ai_ws_2026\lifetree-pro.pem" -N -L 7412:127.0.0.1:7412 root@8.147.68.154`，然后浏览器打开 `http://127.0.0.1:7412`（使用 `AUTH_USERNAME/AUTH_PASSWORD` 登录） |

## 场景：

SOC 每天被海量告警淹没，授权扫描、已知误报等重复噪音持续消耗分析师精力。本 Agent 聚焦**安全告警降噪研判**这一条有界工作流：接收告警 ID 后经 OctoBus 取数，先与私有威胁证据做 IOC 关联，再按结构化降噪规则判定误报（如授权漏扫 DNS 活动 → 误报分 0.85，抑制并复核），结论回写并发送企业微信脱敏通知，证据不足则显式转人工。整条链路"触发→取数→判定→处置→留痕"五阶段闭环，结论只由确定性规则与证据关联产出，模型仅解释、不改决策。

## 预期价值：

在**降误报**与**控漏报**之间建立可审计的自动化平衡：

- **降噪提效**：确定性规则压制已知误报模式，分析师只看值得看的告警；
- **漏报可控**：IOC 命中即升级研判，证据不足一律 fail-closed 转人工，绝不静默丢弃；
- **可解释可回放**：结论强制携带 evidenceRefs，traceid 贯穿 SQLite 快照、审计日志与网关 access.log，任意研判可完整复盘；
- **知识沉淀**：降噪规则结构化入库，支持消融自检与知识-代码双向绑定，运营经验持续积累；
- **合规内生**：状态最小化、通知脱敏、私有 IOC 绝不导出、凭据不出 daemon。

***

## 1. 架构图

**1）在线地址(高清)：**<https://www.processon.com/view/link/6a92fbf88d56e8392bab2185>

**2）架构图：**

![image](./docs/image/architecture.png)

### 3）关键架构要点

1. **guest 沙箱就是 Docker 容器** — daemon 通过 Docker API 创建 `agent-compose-guest` 镜像的容器，挂载卷与工作区后启动 Codex Agent。支持三种生命周期：`--rm`（用完即销毁，适合 cron）、默认停止保留（可 resume）、`--keep-running`（支持多轮 `exec`，适合交互）。安全告警研判为单轮任务用 `--rm`，连续研判多告警用 `--keep-running` 更高效。
2. **Docker Stack 只编排常驻容器**（daemon / 网关 / Portainer），不含业务镜像 — `DEFAULT_IMAGE` 是 daemon 的环境变量而非 Stack 声明，installer 预拉 guest 镜像避免首次卡在大文件下载；agent 代码通过 workspace provider（file/git）按需进入 guest 容器。
3. **Codex Agent 与 chaitin-triage-agent 都在 guest 容器内** — daemon 只负责创建容器和启动 Codex Agent，之后 Codex Agent 靠 LLM 理解 system\_prompt 自主决策执行什么 CLI。system\_prompt 锁死命令格式（`cd agent && node src/interfaces/cli.js --workflow security --alert-id <id>`），LLM 只能填 `<id>` 值不能发明新参数；`--workflow` 选项只来自显式 flag，不受 prompt 文本影响。
4. **研判流水线 9 状态：每状态先落库（SQLite 快照）再执行** — `#transition()` 先 `stateStore.save()` 写 SQLite 标记阶段起点，落库成功才执行该阶段业务逻辑，失败则回滚抛异常。快照含 `traceId / sequence / state / payload`，进程崩溃后运维从最后一条快照即可完整重建运行。
5. **转人工四触发点**：
(1) 告警不存在或取数失败
(2) 未命中降噪规则且无证据关联
(3) 回写 OctoBus 失败
(4) 任何未捕获异常 — 全部走 `exitCode=2`，这不是故障是设计行为。
6. **知识资产参与判定**：`kb-security-ioc-escalation`（证据关联）+ `kb-security-fp-dns-001`（降噪规则）— 正向 `consumed_by` 声明被谁消费，反向 `KNOWLEDGE_HIT` 审计日志记录实际命中，双向核对证明知识真实参与；消融开关 `KNOWLEDGE_ABLATION` 可按 `knowledge_id` 关闭知识注入，被消融知识跳过判定并打 `ablated` 标记。
7. **LLM 只解释不判定** — `narrator.summarize()` 不影响 `decision.status`，判定只能来自确定性规则 `evaluateRules()` 或私有证据关联 `correlateThreatEvidence()`；LLM 异常时降级 `DeterministicNarrator`，`narrativeSource` 置 `"fallback"`，禁止静默失败。
8. **chaitin-triage-capabilities 是 agent 纯函数的 HTTP 包装器** — 同仓库跨进程 import，基于 `node:http` 零第三方依赖，每个 method 都是确定性纯函数（零 IO · 零 LLM · 零敏感数据）。
9. **四条通道严格区分，真实密钥从不进沙箱** —
   | 通道                 | 路径                               | 凭据                             |
   | ------------------ | -------------------------------- | ------------------------------ |
   | OctoBus 业务能力       | 沙箱 → OctoBus 网关（直连，不经 daemon）    | scoped token                   |
   | LLM 调用             | 沙箱 → daemon Facade → 外部 provider | scoped token（真实 key 只在 daemon） |
   | SQLite 状态持久化       | 沙箱内本地卷 `/triage-state`（不经网络）     | 无                              |
   | 知识卷直读            | 沙箱内本地卷 `/knowledge`（只读挂载，不经网络）   | 无                              |

   前两条是跨信任边界的外部通道，后两条是沙箱内本地通道。LLM provider key、OctoBus 管理令牌、daemon AUTH\_TOKEN 全部只在 daemon `.env`（0600 权限），沙箱内只有 scoped token。
10. **多个 Agent 各有独立 guest 容器** — 共用同一个 `agent-compose-guest` 镜像，但各自独立容器，隔离 scoped token、隔离卷（知识卷只读可共享，状态卷按 agent 隔离）、隔离 workspace 路径、隔离 system\_prompt。
11. **信任边界：daemon 持全部真实凭据，guest 沙箱零真实凭据** — daemon `.env`（0600）存 LLM provider key / OctoBus 管理令牌 / AUTH\_TOKEN；沙箱只有 scoped token，真实密钥从文件系统、环境变量、网络三个层面都不进入 guest。
12. **trace\_id 全链路贯穿** — 从 TaskContext 生成 `traceId` 开始，SQLite 快照、NDJSON audit.log、OctoBus access.log（`x-octobus-ext-business-request-id`）四处同 ID 贯穿，任意时刻可按 traceId 回放完整运行链路。

***

## 2. 业务逻辑分层（调用链视图：五阶段主线 + trace_id 全链路贯穿）

主线五阶段：触发 → 编排 → 判定 → 处置 → 留痕。能力总线 / 知识库 / LLM narrator 三条支撑通道并入对应阶段，调用形式 `--workflow security --alert-id <id>`。

### 五阶段流水线（含支撑通道）

| 模块 | 本项目实现 | 调用链与约束 |
| --- | --- | --- |
| **① 触发层** | `interfaces/cli.js` + `security-cli.js`（组合根）· `agent-compose.yml` scheduler · `domains/task/task-context.js` | 工作流只由显式 CLI flag `--workflow` 选择；触发即生成 `TaskContext`（`traceId === taskId` 贯穿全链路）；域前缀环境变量 `SECURITY_TRIAGE_* → TRIAGE_*` 在此统一装配。 |
| **② 编排层** | `application/pipelines/security-triage-pipeline.js`（`SecurityTriageAgent.triage()`）· `shared/run-metrics.js` · **能力总线**：`capabilities/index.js` 注册表 + OctoBus Connect RPC | 9 状态机：`RECEIVED → ACQUIRE_CONTEXT → EXTRACT_SIGNALS → CORRELATE_THREAT_EVIDENCE → APPLY_RULES → LLM_SUMMARIZE → DECIDE_ACTION → PERSIST_RESULT → {COMPLETED / NEED_HUMAN}`；每次 `#transition()` 先 SQLite 快照再执行业务逻辑，失败回滚。能力必须注册到 `CAPABILITIES` 表（`fn / idempotent / deterministic / timeoutMs`），未注册一律抛错；所有能力调用必经 OctoBus 网关（token 鉴权 + NDJSON access.log）。 |
| **③ 判定层** | `capabilities/security/rule-engine.js`（`evaluateRules()`）· `capabilities/security/threat-evidence.js`（关联 + 决策）· `domains/judgment/judgment.js`（补齐 evidenceRefs）· **知识库**：`knowledge/corpus/security/`（只读卷 `/knowledge`） | **红线：结论只由确定性规则 / 私有证据关联产出，LLM 不可改判定**。降噪命中 `kb-security-fp-dns-001` → `suppress_with_review`；IOC 命中 `kb-security-ioc-escalation`（`matchedCount≥1`）优先级更高 → `open_case`；证据缺失或全无命中 → 转人工。知识-代码双向绑定（`consumed_by` 正向 + `KNOWLEDGE_HIT` 反向留痕）；消融开关 `KNOWLEDGE_ABLATION` 可按 id 关闭知识注入。结论经 `finalizeJudgment()` 强制补齐 `evidenceRefs[]`，无证据引用的结论按规范无效。 |
| **④ 处置层** | `infrastructure/octobus/connect-client.js`（回写）· `infrastructure/notify/wecom-notifier.js`（脱敏通知）· 内置 `manual_review / exitCode=2` 转人工 | **三出口必经 outbox**：Ⅰ OctoBus 回写（幂等键 `record:${traceId}`）；Ⅱ 企业微信通知（旁路，只发 alertId/status/action/traceId，不夹带 narrative/IOC/证据，限流 3s）；Ⅲ 非确定性决策恒转人工（告警不存在、规则+证据都无命中、回写失败、未捕获异常）→ `exitCode=2`（正常业务态，非故障）。outbox 指数退避重试（上限 9 次），超限由 `--recover-outbox` 恢复。 |
| **⑤ 留痕层 + LLM narrator 旁路** | `infrastructure/db/security-state-store.js`（SQLite 快照 + outbox）· `audit/audit-log.js`（NDJSON）· OctoBus 网关 `access.log` · **LLM narrator**：`infrastructure/model-gateway/security-narrator.js`（`OpenAICompatibleNarrator` + 确定性降级） | **写路径必经留痕**：Ⅰ `workflow_snapshots`（9 状态有序落库，payload 只含脱敏恢复字段，绝不存密钥/原始日志）；Ⅱ `delivery_outbox`（双投递 + 指数退避，禁止静默丢失）；Ⅲ `audit.log`（每次运行至少 `workflow.completed` + `KNOWLEDGE_HIT` 两条，写入失败不静默）；Ⅳ 网关 `access.log`（`x-octobus-ext-business-request-id=${traceId}`）。**LLM 红线：只解释不改决策**，输入经 `modelSafeAlert()` 脱敏（IOC 只以计数形式）；失败自动降级 `DeterministicNarrator`（`narrativeSource="fallback"`），流程不中断；真实 key 只在 daemon，沙箱仅持 scoped token。 |

### 底部锚点：trace_id 全链路贯穿

`traceId` 由 `createTaskContext()` 在触发层统一生成，贯穿五处写路径：
1. `TaskContext.traceId` / `taskId` 进程内传递；
2. `workflow_snapshots.trace_id` + `sequence`（SQLite 9 状态回放键）；
3. `delivery_outbox.trace_id`（outbox 投递关联键）；
4. `audit.log` NDJSON `traceId`；
5. OctoBus 网关 header `x-octobus-ext-business-request-id=${traceId}` → `access.log`。

任意时刻按 `traceId` 可完整回放。

### 依赖方向（单向向下，无循环）

**触发 → 编排 → （能力总线 / 知识库）→ 判定 / 处置 → 留痕（含 LLM 旁路）**。能力层零 IO 纯函数，不反向调用模型；留痕层是所有写路径的必经环节。

## 3. 时序图

**1）在线地址(高清)：**<https://www.processon.com/view/link/6a93e8408fda406a11e05faa>

**2）时序图：**

![image](./docs/image/sequence.png)

### 3）时序图要点

#### phase 1 · 启动期（4 个关键动作，凭据永不进沙箱）

1.  **daemon 读配置**：daemon 容器（宿主机 root:root 0600）加载 `.env`（真实 `OCTOBUS_TOKEN` / `LLM_API_KEY`）+ `agent-compose.yml`（capset_ids / volumes / env / scheduler）。
2.  **创建 guest 沙箱**：`Docker run agent-compose-guest:latest`，双卷挂载——`/knowledge` 只读（私有证据包，不经网络）+ `/triage-state`（SQLite WAL）；注入**仅 scoped token**（`SECURITY_TRIAGE_OCTOBUS_TOKEN=scoped` / `LLM_API_KEY=scoped`），真实密钥在文件系统、环境变量、网络三个层面都不进 guest。
3.  **注册 OctoBus capset**：daemon 用真实 `OCTOBUS_TOKEN` 向 OctoBus 注册 `triage/security-triage`，4 个已启用方法（GetAlertContext / EvaluateFalsePositiveRules / MatchThreatIndicators / RecordTriageResult），沙箱只能经网关调用这 4 个。
4.  **Runtime LLM Facade 就绪**：daemon 监听 `:7410`，接收沙箱 scoped token → 转译注入真实 `LLM_API_KEY` 调 provider。

#### phase 2 · 运行期（9 状态机主链）

5.  **启动 Agent**：daemon 启动 Codex Agent 进程进入 guest，`system_prompt` 锁死：只能调用经批准的 OctoBus 能力 / 不可直连后端。
6.  **trace_id 统一生成**：CLI 显式 `--workflow security --alert-id <id>` 触发（scheduler cron `0 * * * *`）；`createTaskContext()` 生成 `traceId/taskId`。
7.  **写屏障：先快照后执行**：9 状态机每次 `#transition()` **先写 SQLite workflow_snapshots(trace_id, sequence, state, payload_json) 落库再执行业务逻辑**，失败回滚抛异常，保证可回放。
8.  **GetAlertContext 必经 OctoBus**：Connect RPC `GET /capsets/triage/security-triage/connect/{instance}/GetAlertContext`，header `x-octobus-ext-business-request-id={trace_id}`，OctoBus 写 access.log NDJSON 归档；沙箱无法越过 OctoBus 直连后端。
9.  **判定分层**：两条旁路并行（知识库只读卷 `/knowledge` 直读，不走网络）——
    - IOC/SID 指纹关联：`correlateThreatEvidence()`，命中 `matchedCount≥1` **优先级高于降噪规则** → `escalate / open_case`；
    - 降噪规则：`evaluateRules()`，命中 `kb-security-fp-dns-001` → `suppress_with_review(falsePositiveScore=0.85)`；
    - **证据缺失不静默通过**：规则命中但证据不足 → `manual_review / request_missing_evidence`；
    - 全无命中 → `escalate / open_case`（高优先级人工）。
10. **LLM 红线：只解释不改判定**：`narrator.summarize()` 经 LLM Facade（scoped token）调用；输入经 `modelSafeAlert()` 三重计数脱敏——私有 IOC 只以 `rawSignalCount / networkIndicatorCount / matchedSnortSidCount` 形式进模型；**LLM 不可用时自动降级 `DeterministicNarrator`（`narrativeSource='fallback'`），流程绝不中断**。
11. **强制 evidenceRefs**：`finalizeJudgment()` 从判定证据的 `field / evidenceId` 提取补全 evidenceRefs[]，**无证据引用的结论按规范无效**。
12. **RecordTriageResult 必经 OctoBus + outbox 化**：幂等键 `record:{trace_id}`；先入 SQLite `delivery_outbox`，指数退避重试（30s→15m，上限 9 次），超限标记 `manual` 由 `--recover-outbox` CLI 子命令恢复，**禁止静默丢失**。
13. **恒转人工四触发点（exitCode=2）**：告警不存在、未命中降噪规则+无证据关联、OctoBus 回写失败、任何未捕获异常 → `status=manual_review`，**进程退出码 2 是正常业务态，非故障**。

#### phase 3 · 留痕期（trace_id 五处贯穿）

14. **五处锚点同一 trace_id**：① TaskContext.traceId 进程内传递 → ② workflow_snapshots(trace_id,sequence) SQLite 9 状态回放键 → ③ delivery_outbox(trace_id) 投递关联键 → ④ audit.log NDJSON（每次运行 2 条：`workflow.completed` 含结论+证据+指标、`KNOWLEDGE_HIT` 含知识 id+consumed_by 双向绑定）→ ⑤ OctoBus access.log header `x-octobus-ext-business-request-id={trace_id}`；任意时刻按 `trace_id` 五处同 ID 可完整回放。

## 4. 代码架构（洋葱架构）

```
chaitin-triage-agent/
├── agent-compose.yml          # agent-compose 声明（octobus_servers 原生接入 / scheduler 触发）
├── stack.md                   # Portainer Stack 常驻容器声明（daemon / octobus / UI，无硬编码凭据）
├── .env.example               # 环境变量样例（真实凭据只进 daemon 的 .env）
├── deploy/                    # 部署与验证脚本
│   └── deploy-and-verify.sh   #   一键部署 + 冒烟 + 重启自愈验证
├── knowledge/                 # 自建知识库
│   ├── corpus/security/       #   安全域判据：降噪规则、威胁证据判据、严重度门控、关键资产提级
│   │   ├── false-positive-rules.json
│   │   ├── false-positive-rules.example.yaml
│   │   ├── threat-evidence-judgment.json
│   │   ├── severity-gating.json
│   │   └── asset-criticality-escalation.json
│   └── registry/
│       └── security-decision-evidence.jsonl
├── octobus-services/          # OctoBus service package（可插拔能力包）
│   └── triage-capabilities/
│       ├── service.json       #   service root 声明
│       ├── proto/triage.proto #   gRPC 能力定义（triage.capabilities.v1.CapabilityService）
│       ├── package.json
│       ├── config.schema.json
│       └── secret.schema.json
├── docs/                      # 架构与时序图
│   └── image/                 #   architecture.png / sequence.png
└── agent/
    ├── package.json           # scripts: check / test
    ├── tools/
    │   └── verify-security-state.mjs  # 运维工具：留痕校验
    ├── test/                  # 测试：security / unified-cli / knowledge / observability / octobus-services
    └── src/
        ├── domains/           # 领域层：纯函数、零 IO（TaskContext / Judgment / EvidenceChain）
        ├── application/       # 应用层：用例编排
        │   ├── ports.js       #   Port 契约（能力 / 留痕 / 知识库 / 通知 / 解释）
        │   └── pipelines/     #   五阶段流水线（security）
        ├── capabilities/      # 能力层：确定性纯函数 + 注册表（index.js）
        │   └── security/      #   规则引擎、威胁证据关联、升级门控
        ├── infrastructure/    # 基础设施层：IO 实现（实现 ports 契约）
        │   ├── octobus/       #   Connect RPC 客户端
        │   ├── db/            #   SQLite 状态快照 + outbox
        │   ├── knowledge/     #   本地 RAG 检索、威胁证据加载
        │   ├── model-gateway/ #   narrator（LLM 仅解释；不可用时确定性降级）
        │   └── notify/        #   企业微信出站通知（单向、脱敏、限流）
        ├── interfaces/        # 接口层：统一 CLI / 安全 CLI / 事件入口
        ├── audit/             # 留痕层：追加写 NDJSON 审计日志
        ├── config/            # 配置层：域前缀环境变量别名、必填校验
        └── shared/            # 跨层共享：错误码、日志、trace、弹性、metrics
```

**模块边界规则**：`domains/` 不 import 任何 IO 模块；编排层通过构造函数注入 Port
实现；`capabilities/index.js` 之外不允许直接调用未注册能力；跨层通信只走接口。

## 5. 设计说明

### 5.1 模型与代码分工

- 计算、比对、校验、评分一律是 `capabilities/` 的 Node.js 纯函数（并封装为
  `octobus-services/triage-capabilities` 暴露给 OctoBus）；
- 模型（narrator）只解释证据与结论，**不产生任何数字 / 事实 / 状态**；
- 模型不可用时确定性降级（`narrativeSource: "fallback"`），流程不中断；
- 证据不足显式走 `manual_review` / `REFUSE_INSUFFICIENT_EVIDENCE`，禁止模型补全。

### 5.2 OctoBus 原生接入

- `agent-compose.yml` 在项目级声明 `octobus_servers.triage`，token 只保存在
  daemon，不进入 guest 沙箱；
- agent 以 `capset_ids` 声明最小权限能力集（演示仅 `triage/security-triage`），
  由 daemon 以 MCP/Connect/gRPC 代理；
- 沙箱内确定性工作流另持 per-capset scoped token 经 Connect RPC 直连网关：
  `POST /capsets/{capset_id}/connect/{instance_id}/{full_service}/{method}`，
  每次调用携带 `x-octobus-ext-business-request-id: <trace_id>`；
- 能力注册表 `capabilities/index.js`：capability\_id 命名 `{domain}.{operation}`，
  未注册的能力禁止调用。

### 5.3 LLM 凭据托管（Runtime LLM Facade）

真实 provider key 只配置在 agent-compose daemon 的 ``.env``
（``LLM_API_ENDPOINT`` / ``LLM_API_PROTOCOL`` / ``LLM_API_KEY`` / ``LLM_MODEL``）；
daemon 向沙箱注入 scoped token 与 facade URL。**LLM 默认真实调用**，路径二选一：
- **A) 直连 provider（演示服务器默认采用，满足真实调用核验要求）**：项目级
  ``SECURITY_TRIAGE_LLM_API_BASE`` / ``SECURITY_TRIAGE_LLM_MODEL`` /
  ``SECURITY_TRIAGE_LLM_API_KEY``（``agent-compose.yml`` 已标注 ``secret:true``
  防止 UI 回显）填 DeepSeek 等 OpenAI 兼容端点与凭据，
  ``narratorFromEnvironment()`` 命中三项后使用 ``OpenAICompatibleNarrator``
  调 ``POST /chat/completions``，终态 ``narrativeSource=llm``、``metrics.narrative_source=llm``。
- **B) Runtime LLM Facade**：上述三项留空即回退 daemon 注入值。

显式关闭真实调用（仅本地离线单测）：
``SECURITY_TRIAGE_LLM_REAL_CALL=0|false|off`` 时 ``narratorFromEnvironment()``
直接返回 ``DeterministicNarrator``（``kind="deterministic"``），不产生任何
``/chat/completions`` 请求；关闭与 LLM 异常降级在终态均标记 ``narrative_source=fallback``
或 ``deterministic``（规范 11.3 禁止静默失败）。

模型输入经过 ``modelSafeAlert()`` 脱敏（私有 IOC 仅以计数形式进模型），模型仅
用于解释，**永远不能修改**规则引擎给出的 ``status / action / matchedRuleId``
（规范 6 权限边界，流水线在调用前后均不读取模型字段改写结论）。

### 5.4 知识资产实质性口径

`knowledge/corpus/security/false-positive-rules.json` 是脱敏后入库的结构化
知识资产，每条规则必须携带：

- `knowledge_id`：知识资产唯一标识（如 `kb-security-fp-dns-001`）；
- 可执行判据（conditions 为显式取值，非"疑似/可能"式描述；
  `judgment` 为判据的机器可读形态：threshold / feature\_string / predicate）；
- `invalidation`：误判 / 漏判 / 绕过 / 不可用字段四要素；
- `evidence`：优先级；证据量缺失时显式 `evidence_count: null` + 说明，不伪造数字；
- `tradeoff`：分级策略、须人工确认的动作、证据不足时的处置与让位关系；
- `knowledgeStatement`：来源、积累过程、适用边界；
- `consumed_by`：正向消费声明（capability / prompt 消费点）。

提交时由 `agent/test/security/security-triage-agent.test.js` 的 schema 测试强制校验。
私有威胁证据包只含标识符，保存在仓库外（挂载卷 `/knowledge`）。

**知识-代码绑定**：每条知识资产携带 `consumed_by` 正向声明。
如 IOC 升级判据资产 `knowledge/corpus/security/threat-evidence-judgment.json`
（`knowledge_id: kb-security-ioc-escalation`）声明被
`security.correlate_threat_evidence` 能力与流水线 `CORRELATE_THREAT_EVIDENCE`
阶段消费，与流水线导出常量 `IOC_ESCALATION_KNOWLEDGE` 逐字段一致；
运行时命中知识后由 CLI 在终态审计之外追加 `KNOWLEDGE_HIT` 独立审计记录
反向印证——正向声明与反向留痕互为核对，防止知识与代码脱钩。

**知识消融自检**：`KNOWLEDGE_ABLATION` 环境变量提供消融开关
（逗号分隔 `knowledge_id`）：被消融的降噪规则不参与匹配，IOC 升级判据被
消融时跳过关联判定并回退规则引擎（`correlation.ablated: true`）；
结果 JSON 携带 `knowledgeAblated` 标记显式可见，
用于自检知识是否真实参与判定（用法见 7.5 步骤 2）。

### 5.5 留痕

- SQLite 状态快照：`workflow_snapshots`（trace\_id + sequence 有序落库）、
  `delivery_outbox`（通知失败重投）、会话槽位表、事件幂等表；
- 追加写审计日志：终态记录（`workflow.completed`）含结论 + `evidenceRefs` +
  原始入参 + 模型来源 + prompt 版本 + `metrics` 终态指标对象——
  `stage_durations`（各阶段耗时）/ `capability_calls` / `capability_failures` /
  `knowledge_hits` / `narrative_source` / `manual_escalation`
  （由 `shared/run-metrics.js` 收集器随单次运行在进程内累计）；
  知识命中时另追加 `KNOWLEDGE_HIT` 独立审计记录（见 3.4 知识-代码绑定）；
- OctoBus 网关侧 `access.log`（NDJSON）为能力调用留痕的权威输入，与本日志统一归档。

### 5.6 模拟边界

本项目运行时代码**没有任何静默 mock / 模拟返回**；所有能力调用、LLM 调用与
通知均为真实请求（Connect RPC / Runtime LLM Facade / 企业微信 HTTP）。仅存在
以下两处**显式声明**的模拟，均带明确标注且默认关闭：

| 模拟点         | 位置                                                                                                                                                 | 显式标注                                                                                                       | 默认行为                             |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------- |
| OctoBus 能力包 | OctoBus 网关内托管的 long-running service package（`chaitin-triage-capabilities` / `local-sandbox-adapter`），实现 `GetAlertContext` / `RecordTriageResult` 等 | 同仓库 `octobus-services/triage-capabilities/` 子模块，agent 纯函数的 HTTP 包装器；实例 ID 即"能力包"；真实沙箱接入后替换实例即可，Agent 代码零改动 | 环境中无真实沙箱，此为唯一数据来源模拟（生产替换实例，不改代码） |
| 本地能力包联调模式   | `octobus-services/triage-capabilities` 本地启动                                                                                                        | 启动日志输出 `"auth":"none(local-demo)"`；生产中由 OctoBus 网关托管并鉴权                                                    | 仅用于本地联调，不经 capset 不进生产           |

此外，演示案例为**预置脱敏回放数据**（响应携带 `dataSource: "replay"` 与 `replayNotice` 说明），不属于运行时
模拟；真实执行只能经受控触发链路，结果以 Agent Compose run 记录、OctoBus
`access.log` 与 SQLite 快照四项相互印证。

***

## 6. 部署说明

线上环境：OctoBus 与 agent-compose daemon 均以容器方式运行在 `chaitin` Stack 内（Portainer 管理，网络 `chaitin-net`，均不发布公网端口），Agent 项目部署目录为 `/data/chaitin/deploy-manifests/chaitin-triage-agent`。以下命令在本地 PowerShell 发起 SSH；私钥路径按实际情况替换，不要写入仓库。

#### 步骤 1：登录与常驻状态核验

```powershell
# 本地 PowerShell 登录服务器（私钥只留在本地，勿提交或截图）
ssh -i "D:\ai_ws_2026\lifetree-pro.pem" root@8.147.68.154
```

登录后在服务器（sh）执行：

```sh
# 1a) Stack 容器全部在运行
docker ps --filter 'label=com.docker.compose.project=chaitin' \
  --format 'table {{.Names}}\t{{.Status}}'
# 预期：agent-compose / octobus 等容器均 Up

# 1b) 重启策略核验（3.4 重启自愈的前提：全部 restart=always）
docker inspect -f '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}}' \
  $(docker ps -q --filter 'label=com.docker.compose.project=chaitin')
# 预期：每个容器均输出 restart=always

# 1c) agent-compose daemon 可查询（3.2.1：CLI 查询版本与项目列表）
docker exec agent-compose agent-compose --version
docker exec agent-compose agent-compose project ls
```

#### 步骤 2：首次准备（操作公钥 / Git 工作目录 / root-only .env）

目录与 `.env` 已存在时，只需执行 2a。

```sh
# 2a) 操作公钥写入 authorized_keys（6.1：可直接公钥登录；追加而非覆盖）
echo '<操作公钥>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys

# 2b) 受控 Git 工作目录（root-only 目录）
install -d -m 700 /data/chaitin/deploy-manifests
git clone https://github.com/ch7pairsq/chaitin-triage-agent.git \
  /data/chaitin/deploy-manifests/chaitin-triage-agent

# 2c) root-only .env（真实凭据只进此文件，不入 Git；3.2.3 模型凭据）
install -m 600 /data/chaitin/deploy-manifests/chaitin-triage-agent/.env.example \
  /data/chaitin/deploy-manifests/chaitin-triage-agent/.env
# 仅编辑该 .env 填入 OCTOBUS_* / SECURITY_TRIAGE_OCTOBUS_*（含 capset token / FULL_SERVICE 默认 triage.capabilities.v1.CapabilityService）/ LLM 覆盖项；
# 模型真实凭据由 Stack 从此文件读取并映射为 daemon 的 LLM_* 变量
# （Runtime LLM Facade，见 5.3）。
stat -c '%a %U:%G %n' /data/chaitin/deploy-manifests/chaitin-triage-agent/.env
# 通过标准：600 root:root；禁止 cat / printenv 输出内容
```

#### 步骤 3：准备外部卷

`agent-compose.yml` 声明的 external 卷需存在（daemon 启动校验用；guest 实际挂载数据来自 daemon 本地卷 `agent-compose/data/volumes/local/`，见总览表）。

```sh
docker volume inspect chaitin-private-knowledge-base chaitin-triage-state
```

#### 步骤 4：受控注册项目

由管理员在服务器手动执行（Stack 不再编排 release-runner 等发布容器，触发与验证一律走 SSH + `docker exec`）：

```sh
docker exec agent-compose agent-compose \
  -p /data/chaitin/deploy-manifests/chaitin-triage-agent up
```

#### 步骤 5：注册与调度确认

```sh
docker exec agent-compose agent-compose project ls --json
# 预期：仅 1 个 agent（triage-operator）+ 1 个调度器

docker exec agent-compose agent-compose schedule list
# 预期：仅 hourly-security-boundary-check（cron "0 * * *"，
#       即 3.2.2 要求的定时触发）
```

#### 步骤 6：guest 冒烟验证（正向）

```sh
# 6a) 正向：安全告警研判完整执行一轮（3.4 完整执行 + 运行记录；
#     能力调用经 OctoBus 网关，3.3.3，access.log 留有本次 trace 记录）
docker exec agent-compose agent-compose -p chaitin-triage-agent \
  run triage-operator --rm \
  --command 'cd agent && node src/interfaces/cli.js --workflow security --alert-id A-1001'
# 预期：stdout 输出 JSON 终态（traceId / status / action / evidenceRefs）
```

#### 步骤 7：交付前自检（对应 3.4 五项）

- [ ] **服务器重启后，两套服务可自动恢复，无需人工干预**：交付前实测一次服务器 `reboot`，SSH 恢复后运行 `reboot-verify` 并留存输出（核验全部预期容器 restart=always 且 StartedAt 晚于系统启动时间，即由 Docker 自动拉起而非重启前残留）：

```sh
bash deploy/deploy-and-verify.sh reboot-verify
```

- [ ] **可使用所提供的公钥直接登录**：见步骤 2a，登录信息见 README 开头"服务器环境"。
- [ ] **可在服务器上查询到 agent-compose 的项目与触发器、OctoBus 的能力集与所暴露方法**：项目与触发器见步骤 5 两条命令；能力集经 capset 调用路径核验（7.2 / 7.4）。
- [ ] **Agent 已完整执行至少一轮，且保留可查的运行记录或日志**：见步骤 6a；SQLite 快照按 traceId 校验见 7.4 步骤 2。
- [ ] **仓库内不含任何明文密钥**：凭据一律环境变量占位（`secret: true` 标注），`.env` 不入库，仓库根有 `.gitignore` 覆盖。

#### 步骤 8：安全边界核验（3.2.4 / 3.3.4）

```sh
# 8a) 全部容器无公网端口映射（OctoBus 不对公网发布端口）
docker ps --filter 'label=com.docker.compose.project=chaitin' \
  --format 'table {{.Names}}\t{{.Ports}}'
# 预期：agent-compose / octobus 等均无 0.0.0.0 公网映射，
#       仅 chaitin-net 内部通信或绑定 127.0.0.1

# 8b) 服务器对外仅暴露 SSH（安全组仅向授权来源开放）
ss -tlnp
# 预期：公网监听端口仅 sshd（22），其余均为容器内部 / 回环地址
```

> **讲解点（3.3.4）**：OctoBus 不发布公网端口的实现方式——Stack 声明中不含 ports 映射，网关仅存在于 `chaitin-net` 内部网络；Agent 沙箱与后端实例均经该内网走 Connect RPC，公网唯一入口是 SSH。Agent 侧所有能力调用均经网关四段式路由（capset → instance → service → method），不存在绕过网关直连后端的路径。

#### 步骤 9：通过 SSH 隧道访问 UI（无需暴露公网端口）

`agent-compose-ui` 仅绑定服务器回环地址 `127.0.0.1:7412`，不发布公网端口。**本地浏览器访问 UI 必须通过 SSH 隧道（本地端口转发）**，公钥登录后由 SSH 加密通道代理所有 HTTP 请求。

本地 PowerShell（Windows；私钥按实际路径替换）：

```powershell
# 前台模式：保持窗口运行；按 Ctrl+C 断开；如 7412 已占用可修改左侧本地端口为其他未占用端口
ssh -i "D:\ai_ws_2026\lifetree-pro.pem" -N -L 7412:127.0.0.1:7412 root@8.147.68.154
```

隧道建立成功后，**本地浏览器打开** `http://127.0.0.1:7412` 即可看到 `agent-compose-ui`（包括 agent-compose.yml 可视化、项目列表、触发器与运行记录等）。考官使用已登记在服务器 `~/.ssh/authorized_keys` 中的私钥，替换上述命令中的 `-i` 参数即可从任何一台装有 SSH 客户端的机器访问。

> **讲解点（配合 6 步骤 8 安全边界）**：UI 采用回环绑定 + SSH 隧道双保险，公网扫不到；SSH 是服务器对外唯一公网监听服务（22），关闭隧道窗口即 UI 访问立断，无控制面裸漏公网的窗口期。

服务器上可直接运行 `deploy/deploy-and-verify.sh`（一键部署 / 冒烟 / 重启核验，含上述步骤 2、3、4、6 的自动化核验，不回显任何 Secret；`reboot-verify` 子命令即步骤 7 的重启自愈验收）。

## 7. 完整验证流程说明

> 环境：Node.js ≥ 22.5（内置 `node:sqlite` / `node:test`），无需 npm install（零第三方依赖）。
> 以下命令在仓库根 `chaitin-triage-agent/` 下执行；PowerShell 中 curl 请用 `curl.exe`。
> 验证路径：**本地验证（7.1 – 7.3）→ 线上完整业务流（7.4）→ 知识实质性与消融（7.5）**，逐节执行即覆盖要求的全量验证项。

### 7.0 验证步骤映射

| 验证条目 | 验证位置 | 证据产物 |
| --- | --- | --- |
| daemon 常驻、CLI 查询版本与项目 | 部署步骤 1 / 5 | `agent-compose --version` / `project ls` 输出 |
| 自建项目可定时触发 | 部署步骤 4 / 5 | scheduler `hourly-security-boundary-check`（cron `0 * * * *`） |
| 模型凭据、实际完成模型调用 | 7.4 步骤 1 | 结果 JSON `narrativeSource: "llm"`（Runtime LLM Facade 真实调用） |
| 控制面不对公网无鉴权开放 | 部署步骤 8 | 无公网端口映射，对外仅 SSH |
| OctoBus daemon status 正常 | 部署步骤 1 | 容器 Up、daemon 可达 |
| service → instance → capset 三层链路 | 7.2 / 7.4 | Connect URL 四段式路由 + capset token 鉴权 |
| 经 OctoBus 调用能力 + 审计日志 | 7.2 / 7.4 | access.log NDJSON（trace_id 关联） |
| OctoBus 不对公网发布端口 | 部署步骤 8 | 无公网端口映射 |
| 服务器重启自愈 | 部署步骤 7 | `reboot-verify` 留存输出 |
| 完整执行一轮 + 运行记录 | 7.4 | run 记录 + SQLite 快照 + audit.log |
| 仓库无明文密钥 | 仓库审查 | 凭据均为变量占位、`secret: true`、`.env` 不入库 |
| 业务闭环（触发 / 取数 / 判定 / 处置 / 留痕） | 7.4 步骤 1 | 结果 JSON `states` 五阶段数组 |
| LLM 与脚本分工合理 | 7.4 / 7.5 | 判定仅出自规则引擎与证据关联；模型仅 narrative |
| 至少一处能力调用经 OctoBus | 7.2 / 7.4 | Connect RPC 网关路由 |
| 结论有证据支撑 | 7.4 步骤 1 | `evidenceRefs`（无证据引用的结论无效） |
| 知识实质性（消融自检） | 7.5 | `KNOWLEDGE_ABLATION` 移除知识即改变输出 |

### 7.1 本地静态检查（结构 / 语法 / 单测）

```bash
# 7.1.1 进入目录并确认结构
cd chaitin-triage-agent
dir agent\src            # 应看到 domains/application/capabilities/infrastructure/interfaces/audit/config/shared 八个包
dir octobus-services\triage-capabilities   # 应看到 service.json / proto / dist / *.schema.json

# 7.1.2 静态语法检查
cd agent
npm run check
# 预期：零输出、退出码 0（检查 cli / security-cli / 两个 tools 脚本）

# 7.1.3 全量单元测试
npm test
# 预期：tests 86 / pass 86 / fail 0
# 覆盖：规则引擎、威胁关联、RAG、
#       OctoBus 客户端、安全流水线闭环、
#       SQLite 留痕、outbox 恢复、企业微信通知、统一 CLI 分发、
#       service package 端到端、知识-代码绑定与消融（test/knowledge/）、
#       终态指标（test/observability/）
```

### 7.2 能力总线本地验证（Connect RPC + access.log + 能力治理）

> 覆盖 3.3.2（三层链路）、3.3.3（经网关调用 + 审计日志）。本地以能力包直起方式联调；生产中由 OctoBus 网关托管并经 capset 暴露，路由格式完全一致。

```bash
# 7.2.1 启动能力包（新开一个终端，保持运行）
cd chaitin-triage-agent\octobus-services\triage-capabilities
node dist\index.js
# 预期 stderr 输出一行 JSON：
# {"event":"triage_capabilities.started","host":"127.0.0.1","port":9090,
#  "service":"triage.capabilities.v1.CapabilityService",
#  "capabilities":[...6 个能力...],"auth":"none(local-demo)"}
# 可选环境变量：TRIAGE_CAPABILITIES_HOST / _PORT / _TOKEN / _ACCESS_LOG
```

把下面的 JSON 存为 `runtime\smoke-request.json`（runtime/ 已被 .gitignore 覆盖）：

```json
{"context":{"sourceAssetTag":"vulnerability_scanner","eventTime":"2026-08-25T10:00:00Z","approvedScanWindow":true,"destinationPort":53},
 "rules":{"rules":[{"ruleId":"fp_dns_001","description":"Authorized scanner DNS activity.",
   "evidenceRequired":["sourceAssetTag","eventTime","approvedScanWindow","destinationPort"],
   "conditions":{"sourceAssetTag":"vulnerability_scanner","approvedScanWindow":true,"destinationPort":53},
   "decision":{"falsePositiveScore":0.85,"action":"suppress_with_review"}}]}}
```

```bash
# 7.2.2 Connect RPC 调用（在仓库根 chaitin-triage-agent\ 下另开终端执行）
# 注意 URL 为网关四段式路由：capsets/{capset}/connect/{instance}/{service}/{method}
curl.exe -s -X POST "http://127.0.0.1:9090/capsets/triage-capabilities/connect/demo-1/triage.capabilities.v1.CapabilityService/EvaluateFalsePositiveRules" ^
  -H "content-type: application/json" ^
  -H "x-octobus-ext-business-request-id: smoke-trace-1" ^
  --data "@runtime\smoke-request.json"
# 预期：{"status":"needs_review","action":"suppress_with_review","matchedRuleId":"fp_dns_001",
#        "falsePositiveScore":0.85,"evidence":[...4 项证据...],...}

# 7.2.3 能力总线留痕核验（3.3.3 调用审计日志）
type octobus-services\triage-capabilities\runtime\access.log
# 预期：一行 NDJSON，含 "trace_id":"smoke-trace-1" 与 capability 路由、status 200
# —— 这就是能力总线 access.log 留痕（生产中为 OctoBus 网关侧 access.log）

# 7.2.4 能力治理验证（未注册能力拒绝）
curl.exe -s -X POST "http://127.0.0.1:9090/capsets/triage-capabilities/connect/demo-1/triage.capabilities.v1.CapabilityService/CallModel" ^
  -H "content-type: application/json" -d "{}"
# 预期：404 {"code":"not_found","message":"未注册的能力：CallModel ..."}
# —— 模型调用不是注册能力，不能经能力总线绕行（分工红线的总线侧体现）
```

验证完成后回到 `octobus-services\triage-capabilities` 终端 Ctrl+C 停止服务。

### 7.3 统一 CLI fail-closed 验证

```bash
cd chaitin-triage-agent\agent
node src\interfaces\cli.js --workflow security --alert-id A-1001
# 预期：非零退出码 + stderr 报 "Missing required value: OCTOBUS_BASE_URL"
# —— 未配置网关时显式失败（fail closed），绝不猜测回退
```

### 7.4 线上完整业务流（经真实 OctoBus 的五阶段闭环）

> 覆盖 5.1.1 业务闭环、5.1.2 LLM 与脚本分工、5.1.3 经 OctoBus 调用、5.1.4 结论有证据、3.2.3 实际模型调用。
> 前提：OctoBus 网关已运行，已导入 `triage-capabilities` 能力包并创建 capset（`security-triage`），后端沙箱实现了 `triage.capabilities.v1.CapabilityService`。

```bash
cd chaitin-triage-agent
copy .env.example .env
# 编辑 .env：填入 OCTOBUS_BASE_URL 与 security capset 的 token；
# LLM 真实凭据只配在 agent-compose daemon 的 .env（见 5.3）

cd agent
```

**步骤 1：安全告警研判（触发 → 取数 → 判定 → 处置 → 留痕 全闭环）**

```bash
set SECURITY_TRIAGE_OCTOBUS_BASE_URL=http://127.0.0.1:8080
set SECURITY_TRIAGE_OCTOBUS_CAPSET_ID=security-triage
set SECURITY_TRIAGE_OCTOBUS_INSTANCE_ID=chaitin-triage-capabilities
set SECURITY_TRIAGE_OCTOBUS_TOKEN=<token>
set SECURITY_TRIAGE_OCTOBUS_FULL_SERVICE=triage.capabilities.v1.CapabilityService
set SECURITY_TRIAGE_STATE_DB_PATH=runtime\security-triage-state.db
node src\interfaces\cli.js --workflow security --alert-id A-1001
# 预期：stdout 输出 JSON 终态（traceId / status / action / evidenceRefs /
#       narrativeSource / recorded / states），并已追加一行审计日志到 runtime\audit.log
# 核对四个验证点：
#   - states 数组覆盖五阶段（RECEIVED → ... → COMPLETED，业务闭环）
#   - evidenceRefs 非空（结论有证据支撑，无证据引用的结论无效）
#   - narrativeSource 为 "llm"（经 Runtime LLM Facade 完成真实模型调用，3.2.3）；
#     若为 "fallback" 表示模型不可用已确定性降级，结论不受影响
#   - 判定字段（status / action / falsePositiveScore）只由规则引擎与证据关联产出
# 退出码：0 正常；2 表示 manual_review（证据不足转人工，属正常业务态）
```

**步骤 2：按 traceId 校验 SQLite 留痕完整性（3.4 运行记录）**

```bash
node tools\verify-security-state.mjs <步骤 1 输出的 traceId>
# 预期：{"traceId":"...","snapshotCount":<N>,"latestState":"COMPLETED","latestSequence":N}
```

**步骤 3：通知失败重投（outbox 恢复模式）**

```bash
node src\interfaces\cli.js --workflow security --recover-outbox
# 预期：{"recovered":N,"pending":M,...}
```

### 7.5 知识实质性与消融自检

> 覆盖 5.2 知识实质性（自检方式：移除知识后输出应有明显变化）与 5.1.2 LLM 与脚本分工。
> 前提：沿用 7.4 的环境变量，并通过 `--threat-evidence`（或 `SECURITY_TRIAGE_THREAT_EVIDENCE_PATH`）指向私有威胁证据包（仓库外、仅含标识符的 JSONL），使研判命中 IOC 升级判据 `kb-security-ioc-escalation`。

```bash
cd agent
```

**步骤 1：知识绑定核验（KNOWLEDGE\_HIT 反向留痕）**

```bash
node src\interfaces\cli.js --workflow security --alert-id A-1001 ^
  --threat-evidence <私有威胁证据包JSONL路径>
findstr /C:"KNOWLEDGE_HIT" runtime\audit.log
# sh（服务器 / Unix 环境等价命令）：
#   grep KNOWLEDGE_HIT runtime/audit.log
# 预期（仅命中非空时写入）：一行独立审计记录
# {"event":"KNOWLEDGE_HIT","workflow":"security","traceId":"...",
#  "knowledge_ids":["kb-security-ioc-escalation"],
#  "consumed_by":[{"knowledge_id":"kb-security-ioc-escalation",
#   "consumed_by":[{"type":"capability","ref":"security.correlate_threat_evidence"},
#                  {"type":"prompt","ref":"security-triage-pipeline#CORRELATE_THREAT_EVIDENCE"}]}]}
# 核对：audit 中 knowledge_ids / consumed_by 与知识资产
# knowledge\corpus\security\threat-evidence-judgment.json 的声明一致——
# 资产正向声明"谁消费"，审计反向印证"确实消费"，互为印证。
# —— 这直接回应 5.2"声明的规则未被实际使用"红线：知识消费可查证。
```

**步骤 2：知识消融自检（KNOWLEDGE\_ABLATION）**

```bash
set KNOWLEDGE_ABLATION=kb-security-fp-dns-001
node src\interfaces\cli.js --workflow security --alert-id A-1001 ^
  --threat-evidence <私有威胁证据包JSONL路径>
# 对比消融前后同一告警的输出：被消融的降噪规则不再参与判定，
# 且结果 JSON 出现 "knowledgeAblated":["kb-security-fp-dns-001"]。
# 若消融 IOC 判据（set KNOWLEDGE_ABLATION=kb-security-ioc-escalation）：
# IOC 关联判定被跳过（correlation.ablated=true），判定回退规则引擎。
# —— 即 5.2 的自检方式：移除知识 → 输出变化 → 知识构成实质经验。
# 核验完成后清空开关，恢复完整知识：
set KNOWLEDGE_ABLATION=
```

**步骤 3：终态指标核验（result.metrics）**

```bash
findstr /C:"workflow.completed" runtime\audit.log
# 预期：终态审计记录携带 metrics 对象
#  "metrics":{"stage_durations":{...各阶段耗时毫秒...},
#             "capability_calls":N,"capability_failures":N,
#             "knowledge_hits":N,"narrative_source":"...",
#             "manual_escalation":true|false}
# 也可直接查看 CLI stdout 结果 JSON 的 metrics 字段，两者应一致。
# —— narrative_source / knowledge_hits 同时是 5.1.2（模型仅解释）与
#    知识命中（5.2）的量化佐证。
```

## 8. 实施过程中遇到的问题及处理方式

### 8.1 运行期常见现象速查（多为设计行为，非缺陷）

| 现象                                             | 原因与处置                                                                                                       |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `Missing required value: OCTOBUS_BASE_URL`     | 未配置网关地址。fail closed 是设计行为，配置 `.env` / 环境变量后重试                                                               |
| `manual_review`（退出码 2）                         | 证据不足或流程失败转人工，属正常业务态，不是 bug                                                                                  |
| `narrativeSource: "fallback"`                  | LLM 不可用，已确定性降级；结论不受影响（模型只解释不判定）                                                                             |
| 测试出现 `node:sqlite` 报错                          | Node 版本低于 22.5，升级 Node                                                                                      |
| 想看能力目录                                         | `node -e "import('./src/capabilities/index.js').then(m => console.log(m.listCapabilityIds()))"`（在 agent/ 下） |

### 8.2 开发 / 联调真实问题复盘

联调问题复盘统一维护在仓库根的
[development-debugging-retrospective.md](../development-debugging-retrospective.md)
：16 类问题按**六层 + 一个横切面**组织，每条含
**现象 / 根因 / 处理 / 复盘口径**四要素；文档收尾明确区分
**已验证**与**待生产侧复验**（OctoBus 专用审计检索、Guest 重启后 facade
连通性），不以模拟结果替代真实结论。下表为按层归纳的速览；
Agent 侧四类问题的完整定位过程（现象 / 定位过程 / 解决方式 / 改进方向）
另见 `docs/issues.md`。

| 层次    | 问题与根因                                                                         | 处理方式                                                                                                                               |
| ----- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 配置层   | `agent-compose.yml` 误用 Docker Compose 风格顶层 `version: 1`，解析器不接受；部分字段层级 / 类型不兼容 | 最小配置先过 schema 解析，再逐项加回模型、工作区、触发器、调度。结论：Agent Compose 是 Agent 项目声明，不是通用 Docker Compose                                              |
| 配置层   | 统一 CLI 域前缀变量（`SECURITY_TRIAGE_*`）不回退到通用 `OCTOBUS_*`，别名回退优先级判断有误               | 修正 `config/env.js` 回退逻辑（通用名未设且前缀存在才回退），补前缀 / 通用 / 并存 / 缺失四格矩阵单测                                                                    |
| 凭据层   | 服务器容器重建后 `AUTH_*` 变量被 PowerShell 批量替换误伤，OctoBus 鉴权全失败                         | 受控备份恢复原值；替换脚本改显式清单 + 预检 diff（不回显取值）；按泄露处理完成密钥轮换                                                                                    |
| 凭据层   | Guest 内模型请求 401：通用 `LLM_API_KEY` 被 agent-compose runtime facade 占用 / 覆盖       | 真实 provider key 只配 daemon `.env`（`LLM_API_ENDPOINT` / `LLM_API_KEY` / `LLM_MODEL`），沙箱内为 facade 注入的 scoped token；模型失败一律确定性降级，判定不受影响 |
| 凭据层   | schema 阶段无法确定网关是否要求 capset 专用 token，过早写入通用 token 会掩盖授权边界                      | 先验证变量 / 调用契约，再按 OctoBus 返回结果启用对应 capset 的最小权限 token；token 只经服务器 Secret 注入，不进 Git / 页面 / 日志                                         |
| 运行时层  | Guest 缺 `AGENT_COMPOSE_RUNTIME_BASE_URL` 时无法访问 runtime facade                 | Stack 提供容器内地址 `http://agent-compose:7410`；更新 Stack 后重启 Guest 复验                                                                    |
| 运行时层  | 主机重启后定时任务脱离会话级模型配置，Runtime 等待超时                                               | 模型配置持久化到 daemon `.env`，由 Runtime LLM Facade 统一注入，不依赖会话环境                                                                           |
| 运行时层  | CLI 级审计测试中 `spawnSync` 阻塞事件循环，子进程 fetch 全部超时                                  | 改异步 `spawn` 驱动子进程 + 30 秒看门狗；禁止在持有事件循环依赖（本地 HTTP 替身 / 定时器）的进程内同步 spawn                                                              |
| 模型层   | 单看"模型失败"无法区分 HTTP 错误 / 超时 / 网络不可达 / 输出格式错误                                    | 按 `trace_id` 留存失败类别与最终 narration source：模型侧失败走 LLM fallback，Guest/facade 不可达按运行时网络问题处理；两者均不改确定性规则动作                                |
| 总线与审计 | 普通 `access.log` 未按 `trace_id` 提供完整可检索记录，单类日志无法证明全链路                           | 以 SQLite 状态快照、Connect RPC 调用记录、NDJSON 审计日志与控制台结构化展示交叉核验；OctoBus 专用审计检索标记为待生产复验                                                     |
| 部署层   | deploy 脚本 docker compose 子命令拼接顺序 / 引号错误，部署中断                                  | 修正拼接写法；部署前新增只读状态检查步骤（容器、.env 权限、卷、安全边界）；纳入 shellcheck                                                                                      |
| 部署层   | Portainer 管理的 Stack 引用本机构建上下文 / 宿主路径，更新失败或 500                                | 发布改为 Git Workspace + 已构建镜像；Stack 只声明服务、卷、网络与 Secret 引用，先 Compose 预览再更新                                                             |
| 知识与数据 | 知识若只写在文档、阈值无依据或移除后输出不变，无法证明其参与决策                                              | 规则溯源字段（knowledge\_id / judgment / consumed\_by）+ `KNOWLEDGE_ABLATION` 消融自检 + `KNOWLEDGE_HIT` 反向留痕，正向声明与反向印证互为核对                    |
| 知识与数据 | 远程联调需本机 PEM，存在误提交 / 误读取风险；外部查询不可稳定自动化                                     | 私钥 ACL 收紧为仅本机账户可读，不上传服务器 / 仓库 / 模型 / 日志；IOC、Token 最小暴露；外部依赖改离线库 + 受控单条补全                               |

> 口径：明确区分**已验证**与**待生产侧复验**（如 OctoBus 专用审计检索、
> Guest 重启后 facade 连通性），不以模拟结果替代真实结论。

## 9. 领域知识

本项目所有知识资产统一存放于仓库根的 [`knowledge/`](./knowledge) 目录：

- `knowledge/corpus/security/` — 安全域判据类知识资产（JSON，带 `knowledge_id` / `consumed_by` / `judgment` 等元数据，遵循知识资产实质性口径）。

### 9.1 安全研判知识资产（knowledge/corpus/security/）

| 资产文件 | knowledge_id | 用途 | 流程中的使用位置 |
| --- | --- | --- | --- |
| [`false-positive-rules.json`](./knowledge/corpus/security/false-positive-rules.json) | `kb-security-fp-dns-001` | 授权扫描窗口内已登记扫描资产的 DNS 探测降噪规则（命中 → `suppress_with_review`，不自动升级） | `agent/src/capabilities/security/rule-engine.js` 加载，由 `agent/src/application/pipelines/security-triage-pipeline.js` 的 APPLY_RULES 阶段消费 |
| [`false-positive-rules.example.yaml`](./knowledge/corpus/security/false-positive-rules.example.yaml) | — | 降噪规则的 YAML 示例（同判据的另一种序列化形式，便于人工编辑；运行时不加载） | 仅作为编辑模板，不参与运行时判定 |
| [`threat-evidence-judgment.json`](./knowledge/corpus/security/threat-evidence-judgment.json) | `kb-security-ioc-escalation` | 私有威胁证据命中升级判据（`matchedCount ≥ 1 → ESCALATE / open_case`，优先级高于降噪规则） | 代码侧常量 `IOC_ESCALATION_KNOWLEDGE`（`agent/src/application/pipelines/security-triage-pipeline.js` 顶部声明），由 CORRELATE_THREAT_EVIDENCE 阶段消费 |
| [`severity-gating.json`](./knowledge/corpus/security/severity-gating.json) | `kb-security-severity-gating` | 告警严重度降噪门控（`severity ∈ {high, critical}` 时降噪复核结论强制降级人工确认） | `agent/src/capabilities/security/escalation-gates.js` 的 `SEVERITY_GATING_KNOWLEDGE` 常量 + `applySeverity()` 函数 |
| [`asset-criticality-escalation.json`](./knowledge/corpus/security/asset-criticality-escalation.json) | `kb-security-asset-criticality-escalation` | 关键资产降噪提级判据（`assetCriticality = critical` 或 `high 且 falsePositiveScore < 0.9` 时降级人工确认） | `agent/src/capabilities/security/escalation-gates.js` 的 `ASSET_CRITICALITY_KNOWLEDGE` 常量 + `applyAssetCriticality()` 函数 |

### 9.2 知识-代码绑定（consumed_by 反向自证）

每个知识资产文件均声明 `consumed_by` 数组，标注"谁消费本知识"。代码侧对应常量保持同步，运行时命中后写入审计日志 `KNOWLEDGE_HIT` 事件，构成"资产声明 → 代码消费 → 审计反向印证"的闭环。绑定关系见下表：

| knowledge_id | 声明的 capability 消费方 | 声明的 prompt 消费方 | 代码侧绑定位置 |
| --- | --- | --- | --- |
| `kb-security-fp-dns-001` | `security.evaluate_false_positive_rules` | `security-triage-pipeline#APPLY_RULES` | `rule-engine.js` 规则数组携带 `knowledge_id` 字段 |
| `kb-security-ioc-escalation` | `security.correlate_threat_evidence` | `security-triage-pipeline#CORRELATE_THREAT_EVIDENCE` | `security-triage-pipeline.js` 的 `IOC_ESCALATION_KNOWLEDGE` 常量 |
| `kb-security-severity-gating` | `security.gates.apply_severity` | `security-triage-pipeline#APPLY_RULES` | `escalation-gates.js` 的 `SEVERITY_GATING_KNOWLEDGE` 常量 |
| `kb-security-asset-criticality-escalation` | `security.gates.apply_asset_criticality` | `security-triage-pipeline#APPLY_RULES` | `escalation-gates.js` 的 `ASSET_CRITICALITY_KNOWLEDGE` 常量 |

### 9.3 知识消融自检（KNOWLEDGE_ABLATION）

通过 `KNOWLEDGE_ABLATION` 环境变量传入逗号分隔的 `knowledge_id`，可在运行时移除指定知识资产并观察输出变化，用于验证知识实质性（见 7.5）。消融实现位置：

- `agent/src/config/env.js` 的 `readKnowledgeAblation()` 解析环境变量为 `Set<string>`。
- `agent/src/interfaces/security-cli.js` 在加载规则后过滤掉消融集合中的规则，并把被消融者显式标记到结果 `knowledgeAblated[]`。
- `agent/src/application/pipelines/security-triage-pipeline.js` 在 IOC 升级、规则匹配、降噪门控三处分别检查消融集合，命中即跳过判据并留痕。

## 10. 使用建议

> 依据联调实践整理：先明确 OctoBus 在本项目中的定位边界，
> 再列出适合其演进方向的改进建议，以及本项目在当前阶段的对应处置。

### 10.1 对 OctoBus 的改进建议

结合联调实践，按优先级整理如下：

| 优先级 | 建议方向        | 具体内容                                                                                                                         | 本项目当前的自建处置                                                                     |
| --- | ----------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 高   | 可观测性体系      | access.log 仅 NDJSON、无反向查询后台；trace 检索靠手动 grep，网关侧 SQLite 单文件长期会成为瓶颈。建议内置基于 ClickHouse 类 OLAP 的审计查询后台，支持按 `trace_id` 反向检索全链路调用 | Agent 侧以 SQLite 状态快照 + NDJSON 审计日志 + 网关 access.log 三源交叉核验（见 8.2 P11，属待生产侧复验项） |
| 高   | LLM 统一管控与降级 | Runtime LLM Facade 已有雏形。建议增强：模型欠费 / 超限 / 配额耗尽时自动降级到备选模型或确定性路径；支持网关侧配置多模型路由，按成本与场景选择模型（开源节流）；LLM 调用与能力调用统一 `trace_id` 串通      | 确定性降级已实现（`narrativeSource: "fallback"`，结论不受模型故障影响），但仅覆盖本项目                     |
| 中   | 阶段性 ID      | 每次调用除 `trace_id` 外补充 stage / sequence 级 ID，在网关侧即可定位到具体执行阶段，缩短排障路径                                                            | 状态机 sequence 已落 SQLite 快照（`workflow_snapshots` 按 trace\_id + sequence 有序）      |
| 中   | 全链路网关化      | 人工复核等出网动作也应经网关统一鉴权与审计，避免旁路调用破坏审计完整性                                                                                          | 人工复核走 `NEED_HUMAN` / `manual_review` 状态留痕，通知经企业微信脱敏通道                          |
| 中   | 运营统计能力      | 按 capset / agent 维度的流量统计、费用统计（Token 用量 / 调用次数），支撑成本核算与配额管理                                                                   | 暂无，靠 access.log 手工统计；终态 metrics 含 `capability_calls` 计数（仅单次运行粒度）               |
| 低   | 认证增强        | Bearer Token 之外支持 jwt / oidc 等策略，适配企业多租户与细粒度授权                                                                               | token 由 daemon Secret 注入、root-only 文件管控（600），权限边界已在演示范围内收紧                     |
| 低   | Skill 沉淀机制  | 支持将业务实操经验固化为可分发的 skill / 知识包，并与 capset 联动（能力 + 经验一起交付）                                                                       | 以 `knowledge/corpus` 结构化知识资产 + `consumed_by` 知识-代码绑定实现（见 5.4），但不可跨项目分发        |

> 说明：以上建议不改变本项目结论——在"本地 Node.js 能力网关"这一定位下，OctoBus 的
> capset 抽象、MCP 原生支持与 on-demand 运行模式正是当前选型的决定性因素；改进建议
> 均指向其向生产长期运行演进时需要补齐的短板。



