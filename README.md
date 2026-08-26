# Chaitin Triage Agent（安全告警 + 恶意样本研判 Agent）

一个 agent-compose 项目，包含**安全告警降噪研判**与**恶意样本研判**两条有界工作流。
单一部署单元 `triage-operator`，两条工作流各自持有独立的 OctoBus capset 凭据、
SQLite 留痕库与知识输入；全部代码遵循《AI Agent 企业级开发规范》
（逻辑架构 / 业务模块八层划分 / 代码架构 Clean 分层）。

***

## 1. 逻辑架构：业务模块八层映射（规范 §4）

| 模块       | 本项目实现                                                                                                                   | 职责落点                                                                                                  |
| -------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **触发层**  | `agent-compose.yml` scheduler（cron）+ 统一 CLI（`agent/src/interfaces/cli.js`）                                              | 定时 / CLI 触发，解析入参生成标准化 `TaskContext`（`domains/task/task-context.js`，trace\_id / task\_id 在此统一生成并贯穿全链路） |
| **编排层**  | `application/pipelines/*-triage-pipeline.js`、`application/orchestrator/malware-conversation.js`                         | 业务闭环五阶段编排：触发 → 取数 → 判定 → 处置 → 留痕；多轮会话槽位收集                                                             |
| **判定层**  | 结论**只由确定性规则产出**（`capabilities/`）；模型（narrator）仅解释，不改决策                                                                   | 结构化结论 + `evidenceRefs`（无证据引用的结论按规范无效）                                                                 |
| **能力层**  | `octobus-services/triage-capabilities`（OctoBus service package，Node.js 纯函数）                                             | 取数 / 匹配 / 格式校验 / 评分 / YARA 起草，全部确定性可单测                                                                |
| **处置层**  | `RecordTriageResult` 结果回写 / 企业微信脱敏通知（`infrastructure/notify/wecom-notifier.js`）/ 高危升级人工（`NEED_HUMAN` / `manual_review`） | 处置动作 + 状态回写；YARA `autoPublish` 恒为 false                                                               |
| **能力总线** | OctoBus（capset → service → instance → method）                                                                           | 所有能力调用必须经网关（Connect RPC），带 token 鉴权与 `access.log` NDJSON                                              |
| **知识库**  | `knowledge/`（结构化降噪规则 + RAG 语料 + 私有登记册/证据包，均在仓库外或脱敏入库）                                                                   | 知识资产含判据、失效条件、证据口径、适用边界；私有 IOC 只做标识符关联，绝不导出                                                            |
| **留痕层**  | SQLite 状态快照（`infrastructure/db/`）+ 追加写审计日志（`audit/audit-log.js`）+ 能力总线 access.log                                       | 全链路 trace\_id 贯穿，任意时刻可回放                                                                              |

依赖单向向下：**触发 → 编排 → （能力总线 / 知识库）→ 判定/处置 → 留痕**；
能力层不反向调用模型；留痕是所有写路径的必经环节。

## 2. 代码架构：目录规范（规范 §5.2 Clean/洋葱架构）

```
chaitin-triage-agent/
├── agent-compose.yml          # agent-compose 声明（octobus_servers 原生接入 / scheduler 触发）
├── .env.example               # 环境变量样例（真实凭据只进 daemon 的 .env）
├── knowledge/                 # 自建知识库（规范 §8）
│   ├── corpus/                #   结构化知识资产：降噪规则（脱敏后入库）、脱敏报告契约、RAG 语料
│   ├── registry/              #   私有登记册 / 证据包（标识符级，不含样本字节与原始 IOC）
│   └── security/              #   （预留）安全域知识资产
├── octobus-services/          # OctoBus service package（规范 §7.1，可插拔能力包）
│   └── triage-capabilities/
│       ├── service.json       #   service root 声明（schema / name / proto.roots / proto.files）
│       ├── proto/triage.proto #   gRPC 能力定义（triage.capabilities.v1.CapabilityService）
│       ├── dist/index.js      #   Connect RPC JSON 实现（含 access.log 与 token 鉴权）
│       └── config.schema.json / secret.schema.json
├── docs/                      # 历史设计文档
└── agent/
    ├── package.json           # scripts: check（语法检查）/ test（node --test）
    ├── tools/                 # 运维工具：VT 查询助手、留痕校验
    ├── test/                  # 测试（security / malware / unified-cli / octobus-services）
    └── src/
        ├── domains/           # 领域层：纯函数、零 IO 依赖（可 100% 单测）
        │   ├── task/          #   TaskContext、双工作流状态机
        │   ├── judgment/      #   判定结论模型、定级枚举、evidenceRefs 补齐
        │   └── audit/         #   证据链记录模型
        ├── application/       # 应用层：用例编排（不触基础设施细节）
        │   ├── ports.js       #   Port 契约（能力总线 / 留痕 / 知识库 / 通知 / 解释）
        │   ├── pipelines/     #   触发→取数→判定→处置→留痕 用例流水线（security / malware）
        │   └── orchestrator/  #   多轮会话编排（意图识别、槽位收集）
        ├── capabilities/      # 能力层：确定性纯函数 + 能力注册表（index.js）
        │   ├── security/      #   规则引擎、威胁证据关联
        │   └── malware/       #   报告契约校验、风险评分、YARA 起草
        ├── infrastructure/    # 基础设施层：IO 实现（实现 ports 契约）
        │   ├── octobus/       #   OctoBus Connect RPC 客户端（统一一份）
        │   ├── db/            #   SQLite 状态快照 + outbox（security / malware 各一库）
        │   ├── knowledge/     #   本地 RAG 检索、威胁证据加载
        │   ├── model-gateway/ #   narrator（LLM 仅解释；不可用时确定性降级）
        │   ├── notify/        #   企业微信出站通知（单向、脱敏、限流）
        │   ├── registry/      #   私有样本登记册加载与引用解析
        ├── interfaces/        # 接口层（触发层）：统一 CLI、事件入口、组合根
        ├── audit/             # 留痕层：追加写 NDJSON 审计日志
        ├── config/            # 配置层：域前缀环境变量别名、必填校验
        └── shared/            # 跨层共享：错误码、结构化日志、trace 生成、弹性执行器
```

**模块边界规则**：`domains/` 不 import 任何 IO 模块；编排层通过构造函数注入 Port
实现；`capabilities/index.js` 之外不允许直接调用未注册能力；跨层通信只走接口。

## 3. 核心机制

### 3.1 模型与代码分工（规范红线）

- 计算、比对、校验、评分一律是 `capabilities/` 的 Node.js 纯函数（并封装为
  `octobus-services/triage-capabilities` 暴露给 OctoBus）；
- 模型（narrator）只解释证据与结论，**不产生任何数字 / 事实 / 状态**；
- 模型不可用时确定性降级（`narrativeSource: "fallback"`），流程不中断；
- 证据不足显式走 `manual_review` / `REFUSE_INSUFFICIENT_EVIDENCE`，禁止模型补全。

### 3.2 OctoBus 原生接入（规范 §7）

- `agent-compose.yml` 在项目级声明 `octobus_servers.triage`，token 只保存在
  daemon，不进入 guest 沙箱；
- agent 以 `capset_ids` 声明最小权限能力集（`triage/security-triage`、
  `triage/malware-analysis`），由 daemon 以 MCP/Connect/gRPC 代理；
- 沙箱内确定性工作流另持 per-capset scoped token 经 Connect RPC 直连网关：
  `POST /capsets/{capset_id}/connect/{instance_id}/{full_service}/{method}`，
  每次调用携带 `x-octobus-ext-business-request-id: <trace_id>`；
- 能力注册表 `capabilities/index.js`：capability\_id 命名 `{domain}.{operation}`，
  未注册的能力禁止调用。

### 3.3 LLM 凭据托管（Runtime LLM Facade）

真实 provider key 只配置在 agent-compose daemon 的 `.env`
（`LLM_API_ENDPOINT` / `LLM_API_PROTOCOL` / `LLM_API_KEY` / `LLM_MODEL`）；
daemon 向沙箱注入 scoped token 与 facade URL。项目级 `*_LLM_API_BASE` /
`*_LLM_MODEL` 仅作覆盖项，留空即回退 facade 注入值；本地（沙箱外）直连
OpenAI 兼容端点时才填写。

### 3.4 知识资产实质性口径（规范 §8）

`knowledge/corpus/security/false-positive-rules.json` 是脱敏后入库的结构化
知识资产，每条规则必须携带：

- 可执行判据（conditions 为显式取值，非"疑似/可能"式描述）；
- `invalidation`：误判 / 漏判 / 绕过 / 不可用字段四要素；
- `evidence`：优先级；样本量缺失时显式 `evidence_count: null` + 说明，不伪造数字；
- `knowledgeStatement`：来源、积累过程、适用边界。

提交时由 `agent/test/security/security-triage-agent.test.js` 的 schema 测试强制校验。
私有威胁证据 / 样本登记册只含标识符，保存在仓库外（挂载卷 `/knowledge`）。

### 3.5 留痕（规范 §11）

- SQLite 状态快照：`workflow_snapshots`（trace\_id + sequence 有序落库）、
  `delivery_outbox`（通知失败重投）、会话槽位表、事件幂等表；
- 追加写审计日志：终态记录含结论 + `evidenceRefs` + 原始入参 + 模型来源 +
  prompt 版本；
- OctoBus 网关侧 `access.log`（NDJSON）为能力调用留痕的权威输入，与本日志统一归档。

### 3.6 模拟边界（显式声明，规范不允许静默 mock）

本项目运行时代码**没有任何静默 mock / 模拟返回**；所有能力调用、LLM 调用与
通知均为真实请求（Connect RPC / Runtime LLM Facade / 企业微信 HTTP）。仅存在
以下两处**显式声明**的模拟，均带明确标注且默认关闭：

| 模拟点 | 位置 | 显式标注 | 默认行为 |
| --- | --- | --- | --- |
| OctoBus 演示沙箱后端 | OctoBus 网关内托管的后端实例（`security-triage-demo` / `local-sandbox-adapter`），实现 `GetAlertContext` / `GetSanitizedReport` 等 | 报告 `source` 字段显式取值（`offline-static` / `isolated-sandbox` / `mock`）；实例 ID 即"演示后端"；真实沙箱接入后替换实例即可，Agent 代码零改动 | 环境中无真实沙箱，此为唯一数据来源模拟（生产替换实例，不改代码） |
| 本地能力包联调模式 | `octobus-services/triage-capabilities` 本地启动 | 启动日志输出 `"auth":"none(local-demo)"`；生产中由 OctoBus 网关托管并鉴权 | 仅用于本地联调，不经 capset 不进生产 |

此外，`chaitin-interactive-demo` 回放控制台返回的 12 个案例为**预置脱敏回放
数据**（响应携带 `dataSource: "replay"` 与 `replayNotice` 说明），不属于运行时
模拟；真实执行只能经其受控触发链路，结果以 Agent Compose run 记录、OctoBus
`access.log` 与 SQLite 快照四项相互印证。

***

## 4. 完整实操验证流程

> 环境：Node.js ≥ 22.5（内置 `node:sqlite` / `node:test`），无需 npm install（零第三方依赖）。
> 以下命令在仓库根 `chaitin-triage-agent/` 下执行；PowerShell 中 curl 请用 `curl.exe`。

### 阶段 0：进入目录并确认结构

```bash
cd chaitin-triage-agent
dir agent\src            # 应看到 domains/application/capabilities/infrastructure/interfaces/audit/config/shared 八个包
dir octobus-services\triage-capabilities   # 应看到 service.json / proto / dist / *.schema.json
```

### 阶段 1：静态语法检查

```bash
cd agent
npm run check
# 预期：零输出、退出码 0（检查 cli / security-cli / malware-cli / 两个 tools 脚本）
```

### 阶段 2：全量单元测试（52 个）

```bash
npm test
# 预期：tests 52 / pass 52 / fail 0
# 覆盖：规则引擎、威胁关联、报告契约、风险评分、YARA 起草、RAG、
#       OctoBus 客户端、双流水线闭环、SQLite 留痕、outbox 恢复、
#       企业微信通知、统一 CLI 分发、service package 端到端
```

### 阶段 3：本地启动 OctoBus 能力包（triage-capabilities）

```bash
cd chaitin-triage-agent\octobus-services\triage-capabilities
node dist\index.js
# 预期 stderr 输出一行 JSON：
# {"event":"triage_capabilities.started","host":"127.0.0.1","port":9090,
#  "service":"triage.capabilities.v1.CapabilityService",
#  "capabilities":[...6 个能力...],"auth":"none(local-demo)"}
# 可选环境变量：TRIAGE_CAPABILITIES_HOST / _PORT / _TOKEN / _ACCESS_LOG
```

（新开一个终端做后续验证；此服务即规范 §7.1 的 service package，
生产中由 OctoBus 网关托管并经 capset 暴露，本地模式用于联调。）

### 阶段 4：Connect RPC 调用 + 能力总线留痕验证

把下面的 JSON 存为 `runtime\smoke-request.json`（runtime/ 已被 .gitignore 覆盖）：

```json
{"context":{"sourceAssetTag":"vulnerability_scanner","eventTime":"2026-08-25T10:00:00Z","approvedScanWindow":true,"destinationPort":53},
 "rules":{"rules":[{"ruleId":"fp_dns_001","description":"Authorized scanner DNS activity.",
   "evidenceRequired":["sourceAssetTag","eventTime","approvedScanWindow","destinationPort"],
   "conditions":{"sourceAssetTag":"vulnerability_scanner","approvedScanWindow":true,"destinationPort":53},
   "decision":{"falsePositiveScore":0.85,"action":"suppress_with_review"}}]}}
```

```bash
# 以下命令在仓库根 chaitin-triage-agent\ 下执行（另开终端，保持阶段 3 的服务运行）
curl.exe -s -X POST "http://127.0.0.1:9090/capsets/triage-capabilities/connect/demo-1/triage.capabilities.v1.CapabilityService/EvaluateFalsePositiveRules" ^
  -H "content-type: application/json" ^
  -H "x-octobus-ext-business-request-id: smoke-trace-1" ^
  --data "@runtime\smoke-request.json"
# 预期：{"status":"needs_review","action":"suppress_with_review","matchedRuleId":"fp_dns_001",
#        "falsePositiveScore":0.85,"evidence":[...4 项证据...],...}

type octobus-services\triage-capabilities\runtime\access.log
# 预期：一行 NDJSON，含 "trace_id":"smoke-trace-1" 与 capability 路由、status 200
# —— 这就是规范 §7.3 要求的能力总线 access.log 留痕
```

再验证能力治理（未注册能力拒绝）：

```bash
curl.exe -s -X POST "http://127.0.0.1:9090/capsets/triage-capabilities/connect/demo-1/triage.capabilities.v1.CapabilityService/CallModel" ^
  -H "content-type: application/json" -d "{}"
# 预期：404 {"code":"not_found","message":"未注册的能力：CallModel ..."}
```

验证完成后回到 `octobus-services\triage-capabilities` 终端 Ctrl+C 停止服务。

### 阶段 5：统一 CLI 自检 + fail-closed 验证

```bash
cd chaitin-triage-agent\agent
node src\interfaces\cli.js --workflow malware --self-check
# 预期：{"status":"ok","checks":{"octobusConfigured":false,"statePathConfigured":false,"ragStatus":"not_configured"}}

node src\interfaces\cli.js --workflow security --alert-id A-1001
# 预期：非零退出码 + stderr 报 "Missing required value: OCTOBUS_BASE_URL"
# —— 未配置网关时显式失败（fail closed），绝不猜测回退

node src\interfaces\cli.js --alert-id A-1001 --self-check
# 预期：报错 "Choose exactly one workflow: security or malware."
# —— prompt / 混合参数不能同时选择两个能力域
```

### 阶段 6：接入真实 OctoBus 后的完整业务流

前提：OctoBus 网关已运行，已导入 `triage-capabilities` 能力包并创建两个
capset（`security-triage` / `malware-analysis`），后端沙箱实现了
`security.triage.v1.SecurityTriageService` 与 `malware.triage.v1.MalwareTriageService`。

```bash
cd chaitin-triage-agent
copy .env.example .env
# 编辑 .env：填入 OCTOBUS_BASE_URL 与两个 capset 的 token；
# LLM 真实凭据只配在 agent-compose daemon 的 .env（见 §3.3）

cd agent
# 6.1 安全告警研判（触发 → 取数 → 判定 → 处置 → 留痕 全闭环）
set SECURITY_TRIAGE_OCTOBUS_BASE_URL=http://127.0.0.1:8080
set SECURITY_TRIAGE_OCTOBUS_CAPSET_ID=security-triage
set SECURITY_TRIAGE_OCTOBUS_INSTANCE_ID=security-triage-demo
set SECURITY_TRIAGE_OCTOBUS_TOKEN=<token>
set SECURITY_TRIAGE_STATE_DB_PATH=runtime\security-triage-state.db
node src\interfaces\cli.js --workflow security --alert-id A-1001
# 预期：stdout 输出 JSON 终态（traceId / status / action / evidenceRefs /
#       narrativeSource / recorded），并已追加一行审计日志到 runtime\audit.log
# 退出码：0 正常；2 表示 manual_review（证据不足转人工，属正常业务态）

# 6.2 按返回的 traceId 校验 SQLite 留痕完整性
node tools\verify-security-state.mjs <上一步输出的 traceId>
# 预期：{"traceId":"...","snapshotCount":<N>,"latestState":"COMPLETED","latestSequence":N}

# 6.3 通知失败重投（outbox 恢复模式）
node src\interfaces\cli.js --workflow security --recover-outbox
# 预期：{"recovered":N,"pending":M,...}

# 6.4 恶意样本研判（只传 sample_id + SHA-256，绝不传样本）
set MALWARE_TRIAGE_OCTOBUS_BASE_URL=http://127.0.0.1:8080
set MALWARE_TRIAGE_OCTOBUS_CAPSET_ID=malware-analysis
set MALWARE_TRIAGE_OCTOBUS_INSTANCE_ID=local-sandbox-adapter
set MALWARE_TRIAGE_OCTOBUS_AUTH_TOKEN=<token>
set MALWARE_TRIAGE_STATE_DB_PATH=runtime\malware-triage-state.db
node src\interfaces\cli.js --workflow malware --sample-id apk-001 --sha256 <64位SHA-256> --profile android-apk
# 预期：action=HUMAN_REVIEW_REQUIRED（YARA 候选仅生成待审核，autoPublish 恒为 false）

# 6.5 多轮会话入口（槽位跨轮保留，补齐 SHA-256 后才启动工作流）
node src\interfaces\cli.js --workflow malware --session-id demo-1 --message "研判 sample_id apk-001"
node src\interfaces\cli.js --workflow malware --session-id demo-1 --message "sha256 <64位SHA-256>"

# 6.6 事件入口（允许字段白名单 + 幂等）
node src\interfaces\cli.js --workflow malware --event-file <仅含允许字段的告警JSON>
```

### 阶段 7：真实服务器部署（agent-compose / OctoBus 均为 Docker 容器）

线上环境：OctoBus 与 agent-compose daemon 均以容器方式运行在 `chaitin` Stack 内
（Portainer 管理，网络 `chaitin-net`），部署目录为
`/data/chaitin/deploy-manifests/chaitin-triage-agent`。
以下命令在本地 PowerShell 发起 SSH；私钥路径按实际情况替换，不要写入仓库。

```powershell
# 登录服务器（私钥只留在本地，勿提交或截图）
ssh -i "D:\ai_ws_2026\lifetree-pro.pem" root@8.147.68.154
```

```sh
# 1) 确认 Stack 容器与 agent-compose daemon 可用
docker ps --filter 'label=com.docker.compose.project=chaitin' \
  --format 'table {{.Names}}\t{{.Status}}'
docker exec agent-compose agent-compose --version

# 2) 首次部署：准备受控 Git 工作目录与 root-only .env（目录已存在则跳过 clone）
install -d -m 700 /data/chaitin/deploy-manifests
git clone https://github.com/ch7pairsq/chaitin-triage-agent.git \
  /data/chaitin/deploy-manifests/chaitin-triage-agent
install -m 600 /data/chaitin/deploy-manifests/chaitin-triage-agent/.env.example \
  /data/chaitin/deploy-manifests/chaitin-triage-agent/.env
# 仅编辑该 .env 填入 OCTOBUS_* / 两个 capset token / LLM 覆盖项；
# 模型真实凭据由 Stack 从此文件读取并映射为 daemon 的 LLM_* 变量。
stat -c '%a %U:%G %n' /data/chaitin/deploy-manifests/chaitin-triage-agent/.env
# 通过标准：600 root:root；禁止 cat / printenv 输出内容

# 3) 准备外部卷（私有知识库只读挂载 /knowledge，状态库 /triage-state）
docker volume inspect chaitin-private-knowledge-base chaitin-triage-state

# 4) 受控注册：优先由 chaitin-interactive-demo 的发布中心（release-runner，
#    Stack 内网受控发布器）执行 fetch → 固定 ref → up → 无样本健康检查；
#    或由管理员在服务器手动执行：
docker exec agent-compose agent-compose \
  -p /data/chaitin/deploy-manifests/chaitin-triage-agent up

# 5) 注册与调度确认（含每小时安全边界巡检、每日 09:15 恶意样本自检）
docker exec agent-compose agent-compose project ls --json
docker exec agent-compose agent-compose schedule list

# 6) 无变更性 guest 自检（不提供样本 / IOC / 生产告警）
docker exec agent-compose agent-compose -p chaitin-triage-agent \
  run triage-operator --rm \
  --command 'cd agent && node src/interfaces/cli.js --workflow malware --self-check'

# 7) 健康检查通过后，下线旧的两条注册（旧 security/malware 独立 agent）
```

界面化操作：`chaitin-interactive-demo`（demo-console）的发布中心与受控实时触发
均通过 Stack 内网的 `release-runner` / `agent-trigger-bridge` 完成，浏览器不接触
任何 token、私钥或 Docker socket。详细命令见其
`docs/operations-command-runbook.md`；服务器上也可直接运行其
`deploy/deploy-and-verify.sh`（一键预检 / 部署 / 重启 / 验证，含上述第 2、3、4、
6 步的自动化核验，不回显任何 Secret）。

***

## 5. 常见问题

| 现象                                         | 原因与处置                                                                                                       |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `Missing required value: OCTOBUS_BASE_URL` | 未配置网关地址。fail closed 是设计行为，配置 `.env` / 环境变量后重试                                                               |
| `manual_review`（退出码 2）                     | 证据不足或流程失败转人工，属正常业务态，不是 bug                                                                                  |
| `narrativeSource: "fallback"`              | LLM 不可用，已确定性降级；结论不受影响（模型只解释不判定）                                                                             |
| `Choose exactly one workflow`              | 命令同时命中两个能力域；`--workflow` 必须显式二选一                                                                            |
| 测试出现 `node:sqlite` 报错                      | Node 版本低于 22.5，升级 Node                                                                                      |
| 想看能力目录                                     | `node -e "import('./src/capabilities/index.js').then(m => console.log(m.listCapabilityIds()))"`（在 agent/ 下） |

