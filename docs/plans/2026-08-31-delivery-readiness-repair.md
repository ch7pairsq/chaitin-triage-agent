# 交付就绪严格修复计划

## 目标

使仓库、配置、运行环境和 `README.md` 操作步骤保持一致，所有成功结论均由可复验输出支撑。服务器基础镜像通过 Portainer Stack 由管理员手动更新；本轮不执行服务器重启验证，也不改变现有登录配置。

## 修复顺序

1. 测试先行修复证据约束与现有失败用例。
2. 持久化 Agent 审计日志，修复部署脚本假阳性。
3. 补齐干净仓库部署资产与凭据边界。
4. 以本地长版 README 为基线，修正命令、路径、证据口径与交付准备清单。
5. 完成本地全量验证、密钥扫描和提交推送。
6. 服务器保留回滚备份后同步 GitHub 精确 commit，并按 README 复演；Portainer Stack 更新由管理员手动完成。

## 验证门槛

- `npm run check`、`npm test`、Shell 语法检查全部通过。
- 仓库密钥扫描无命中，干净 Git 副本可复现部署配置。
- 服务器上的项目对应精确 Git commit，旧版本有可恢复备份。
- `agent-compose version`、`project ls`、`scheduler ls --json` 和 OctoBus 状态查询成功。
- 真实运行满足 `COMPLETED`、`evidenceRefs` 非空、`recorded=true`、`narrativeSource=llm`。
- 同一运行可在 SQLite 与持久化 `audit.log` 中按 trace ID 精确关联，并以 OctoBus 同一运行时间窗口内的成功调用作网关佐证。
- README 中的操作命令可按顺序执行。

## 回滚

服务器已保留带时间戳的旧目录备份。同步新 Git commit 时原位继承真实 `.env` 并保持 `600 root:root`，不得输出其内容；关键验证失败时恢复旧目录。
