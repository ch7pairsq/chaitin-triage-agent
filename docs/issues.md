# 实施问题与处理记录

## 1. daemon 内外路径不一致

- 现象：宿主路径 `/data/chaitin/deploy-manifests/chaitin-triage-agent` 可见，但 daemon CLI 报找不到项目。
- 定位：Stack 把宿主 `/data/chaitin/deploy-manifests` 只读挂载为容器内 `/deploy`。
- 处理：所有 daemon 内命令统一使用 `/deploy/chaitin-triage-agent`；部署脚本找不到该路径时直接失败，不再回退宿主路径。

## 2. CLI 版本漂移导致“验证成功”假象

- 现象：`--version`、`schedule list`、`scheduler list` 在 v2608.5.0 不可用，但旧脚本吞掉错误。
- 定位：以服务器 `agent-compose --help` 和 `scheduler --help` 为准核对实际子命令。
- 处理：固定使用 `agent-compose version` 与 `agent-compose -p chaitin-triage-agent scheduler ls --json`；任一失败均返回非零。

## 3. 冒烟只看退出码，无法证明业务闭环

- 现象：旧脚本把退出码 2 也视为成功，且不检查结果是否落库、是否真实调用模型。
- 处理：冒烟必须同时满足 `COMPLETED`、`evidenceRefs` 非空、`recorded=true`、`narrativeSource=llm`；否则部署失败。

## 4. 结论可能没有证据引用

- 现象：未命中规则时曾返回升级动作和空 `evidence`，而领域断言只检查数组类型。
- 处理：未命中可执行判据时转 `manual_review/request_additional_evidence`，保留已观察上下文证据；领域断言强制 `evidenceRefs` 非空，并加入回归测试。

## 5. 审计日志随临时 guest 消失

- 现象：默认写入 workspace 的 `runtime/audit.log`，`run --rm` 后不可持续核验。
- 处理：部署固定 `TRIAGE_AUDIT_LOG_PATH=/triage-state/audit.log`，与 SQLite 共用持久化状态卷；按 trace ID 联合查询。

## 6. 模型凭据边界表述与实际运行不一致

- 现象：文档曾宣称 provider key 不进入 guest，但当前已验证实现是项目级 Secret 环境变量注入。
- 处理：不再作未验证的 facade 隔离承诺；明确真实 key 只保存在服务器 `0600 root:root` 的 `.env`，`agent-compose.yml` 使用 `secret: true` 避免控制面回显。后续切换 facade 必须重新做真实调用验证。

## 7. 网关日志关联边界

- 现象：Agent 请求发送业务 trace header，但当前 OctoBus `access.log` 版本未稳定落该字段。
- 处理：不虚构网关 trace 查询能力。交付核验以 Agent 终态 trace、SQLite、持久化审计日志为精确关联，以 OctoBus 同一运行时间窗口内两次 200 调用作网关佐证。

## 8. 数值参数的证据边界

- 现状：规则中的 `0.85` 与关键资产门控 `0.9` 是保守策略参数，尚无批量统计或校准集证明。
- 口径：不得称为概率、准确率或已校准阈值，也不能单独作为“知识实质性”证据。交付说明应聚焦可执行多字段谓词、失效条件、绕过点、不可单独使用字段、人工确认边界及知识消融结果；并准备私有复盘登记以说明来源。
