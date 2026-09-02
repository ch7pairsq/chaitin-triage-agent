# ADR 0002：备份与业务运行目录物理分离

- 状态：已采用
- 日期：2026-09-02

## 背景

业务源码、agent-compose 状态和 OctoBus 状态位于 `/data/chaitin`。如果更新备份也写入该目录，目录巡检、迁移或容量统计可能把回滚材料误认为业务数据；业务目录异常扩容也会同时影响备份可用性。

## 备选方案

1. 继续把备份放在业务根目录的子目录中：改动最少，但不能形成清晰的业务/备份边界。
2. 只把归档文件写入 Docker volume：容器使用方便，但宿主机定位、离线复制和权限核查不直观。
3. 使用独立宿主根目录 `/data/chaitin_backup`：路径清晰、可单独授权和迁移，代价是 release-worker 需要增加一个受限 bind mount。

## 决策

采用方案 3。当前业务的所有新备份写入 `/data/chaitin_backup/chaitin-triage-agent`：

- `deploy/update-stacks.sh` 的默认备份根目录指向该路径；
- release-worker 仅把宿主机 `/data/chaitin_backup` 挂载为容器内 `/host-backup`；
- release-worker 使用 `/host-backup/chaitin-triage-agent`，不通过 `/host-data/chaitin` 写备份；
- 备份目录权限为 `0700`，新归档文件权限为 `0600`；
- 文件名必须包含 `backup-YYYYMMDD-HHMMSS`；
- Wazuh、agent-compose、agent-compose UI、OctoBus 和 webhook receiver 均不挂载备份目录。

## 影响

- 业务目录可以独立检查，不再混入历史快照和回滚归档。
- 新服务器必须在启动 release-worker 前创建 `/data/chaitin_backup/chaitin-triage-agent`。
- 更新 release-worker Compose 挂载后必须重新创建该容器，旧容器环境不会自动获得新路径。
- 备份仍与业务数据处于同一宿主机；如需主机级容灾，应另行复制到受控的异机或离线介质。

## 验证

仓库验证强制检查脚本默认路径、release-worker 环境变量和 bind mount。运行后还应确认：

```sh
find /data/chaitin -xdev -maxdepth 5 \( -iname '*backup*' -o -name '*.bundle' \) -print
find /data/chaitin_backup/chaitin-triage-agent -maxdepth 1 -type f -name '*-backup-*' -print
```

第一条应无输出；第二条应列出统一更新脚本产生的回滚文件。
