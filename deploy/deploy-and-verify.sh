#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# deploy-and-verify.sh — 一键预检 / 部署 / 冒烟 / 重启自愈核验
#
# 用法（在服务器项目根执行）：
#   bash deploy/deploy-and-verify.sh fast-verify
#   bash deploy/deploy-and-verify.sh deploy
#   bash deploy/deploy-and-verify.sh smoke
#   bash deploy/deploy-and-verify.sh reboot-verify
#   bash deploy/deploy-and-verify.sh help
#
# 可选环境变量：
#   DEPLOY_DAEMON_PROJECT_PATH  覆盖 agent-compose -p 在 daemon 内的项目绝对路径
#                               （README 6 默认：/data/chaitin/deploy-manifests/chaitin-triage-agent）
#   SMOKE_TIMEOUT_SECONDS       guest 冒烟超时，默认 300
# 约束：不回显任何 Secret；失败即非零退出。
# ---------------------------------------------------------------------------
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
PROJECT_NAME="chaitin-triage-agent"
DAEMON_CONTAINER="agent-compose"
# 预期常驻容器列表（手动 docker run 启动时不会有 compose label，
# 所以所有容器发现都按显式名称匹配，不依赖 label 过滤）
EXPECTED_CONTAINERS=(agent-compose agent-compose-ui octobus)
STACK_LABEL="com.docker.compose.project=chaitin"
LOG_PREFIX="[triage-verify]"
SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-300}"
DEFAULT_DAEMON_PATH="/data/chaitin/deploy-manifests/chaitin-triage-agent"
DEPLOY_DAEMON_PROJECT_PATH="${DEPLOY_DAEMON_PROJECT_PATH:-${DEFAULT_DAEMON_PATH}}"

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_RST=""
fi

log_info()  { echo "${LOG_PREFIX} ${C_CYAN}INFO${C_RST}  $*"; }
log_ok()    { echo "${LOG_PREFIX} ${C_GREEN} OK ${C_RST}  $*"; }
log_warn()  { echo "${LOG_PREFIX} ${C_YELLOW}WARN${C_RST}  $*" >&2; }
log_fail()  { echo "${LOG_PREFIX} ${C_RED}FAIL${C_RST}  $*" >&2; }
fail() { log_fail "$*"; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "缺少必需命令：$1"; }

check_container_up() {
  local name="$1"
  # 按容器名精确匹配（手动 docker run 启动的容器没有 compose label）
  local found
  found="$(docker ps --filter "name=^/${name}$" --format '{{.Names}}' 2>/dev/null)"
  [ -n "${found}" ] && [ "${found}" = "${name}" ]
}

# 枚举所有预期常驻容器的 ID（用于 fast-verify / reboot-verify）
list_expected_cids() {
  local name
  for name in "${EXPECTED_CONTAINERS[@]}"; do
    docker ps --filter "name=^/${name}$" --format '{{.ID}}' 2>/dev/null || true
  done
}

resolve_daemon_project_path() {
  if [ -n "${DEPLOY_DAEMON_PROJECT_PATH_OVERRIDE:-}" ]; then
    echo "${DEPLOY_DAEMON_PROJECT_PATH_OVERRIDE}"
    return 0
  fi
  if docker exec "${DAEMON_CONTAINER}" test -f "${DEPLOY_DAEMON_PROJECT_PATH}/agent-compose.yml" >/dev/null 2>&1; then
    echo "${DEPLOY_DAEMON_PROJECT_PATH}"
    return 0
  fi
  log_warn "daemon 内未发现 ${DEPLOY_DAEMON_PROJECT_PATH}/agent-compose.yml，回退使用宿主路径 ${PROJECT_ROOT}（请确认为 daemon 容器挂载目录）"
  echo "${PROJECT_ROOT}"
}

cmd_fast_verify() {
  log_info "=== fast-verify：只读预检开始 ==="
  need_cmd docker
  need_cmd stat
  local failed=0 nm

  log_info "核验常驻容器全部 Up..."
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | awk 'NR==1; NR>1 {for (n in expect) if ($1==expect[n]) print}' \
        expect="${EXPECTED_CONTAINERS[*]}" 2>/dev/null || {
    # awk 兜底：直接按名打印
    printf "%-30s %-25s %s\n" "NAMES" "STATUS" "PORTS"
    for nm in "${EXPECTED_CONTAINERS[@]}"; do
      check_container_up "${nm}" || continue
      docker ps --filter "name=^/${nm}$" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
    done
  }
  local running_count=0
  for nm in "${EXPECTED_CONTAINERS[@]}"; do
    check_container_up "${nm}" && running_count=$((running_count+1))
  done
  if [ "${running_count}" -ge 2 ]; then
    log_ok "至少 2 个常驻容器在运行（当前 ${running_count}/${#EXPECTED_CONTAINERS[@]} 预期）"
  else
    log_fail "常驻容器不足（检测到 ${running_count} 个，预期至少 2）"; failed=$((failed+1))
  fi

  log_info "核验全部常驻容器 restart=always..."
  local cid
  while IFS= read -r cid; do
    [ -z "${cid}" ] && continue
    local inspect
    inspect="$(docker inspect -f '{{.Name}} restart={{.HostConfig.RestartPolicy.Name}}' "${cid}")"
    case "${inspect}" in
      *"restart=always"*) log_ok "  ${inspect}" ;;
      *) log_fail "  ${inspect}（期望 restart=always）"; failed=$((failed+1)) ;;
    esac
  done < <(list_expected_cids)

  log_info "核验 agent-compose daemon CLI..."
  if check_container_up "${DAEMON_CONTAINER}"; then
    local version daemon_rc
    # 优先 version 子命令，回退 --version（不同 daemon 版本参数名不一致），均失败时仅 warn 不计数失败
    set +e
    docker exec "${DAEMON_CONTAINER}" agent-compose version > /tmp/ac-version.$$ 2>&1
    daemon_rc=$?
    if [ "${daemon_rc}" -ne 0 ]; then
      docker exec "${DAEMON_CONTAINER}" agent-compose --version > /tmp/ac-version.$$ 2>&1
      daemon_rc=$?
    fi
    set -e
    version="$(cat /tmp/ac-version.$$ 2>/dev/null || true)"; rm -f /tmp/ac-version.$$
    if [ "${daemon_rc}" -eq 0 ] && [ -n "${version}" ] && ! echo "${version}" | grep -qiE "Error response|Container .* restarting|container is restarting|unknown flag"; then
      log_ok "agent-compose version => ${version}"
    else
      log_info "  version 标志不可用（${version:-rc=${daemon_rc}}），以 project ls 作为 CLI 存活探针"
    fi
    log_info "agent-compose project ls："
    if docker exec "${DAEMON_CONTAINER}" agent-compose project ls > /tmp/ac-projects.$$ 2>&1; then
      cat /tmp/ac-projects.$$
      log_ok "daemon CLI project ls 正常（证明 daemon gRPC/HTTP API 可达）"
    else
      log_fail "project ls 失败：$(head -n 2 /tmp/ac-projects.$$ 2>/dev/null)"
      failed=$((failed+1))
    fi
    rm -f /tmp/ac-projects.$$
    # scheduler 子命令仅在新版 daemon 存在，静默探测不失败
    log_info "agent-compose 调度信息："
    if docker exec "${DAEMON_CONTAINER}" agent-compose scheduler list > /tmp/ac-sched.$$ 2>&1; then
      cat /tmp/ac-sched.$$
    elif docker exec "${DAEMON_CONTAINER}" agent-compose schedule list > /tmp/ac-sched.$$ 2>&1; then
      cat /tmp/ac-sched.$$
    else
      log_info "  （当前 daemon 版本未提供 scheduler/schedule 子命令或暂未配置调度）"
    fi
    rm -f /tmp/ac-sched.$$ 2>/dev/null || true
  else
    log_fail "daemon 容器 ${DAEMON_CONTAINER} 未运行"; failed=$((failed+1))
  fi

  local env_file="${PROJECT_ROOT}/.env"
  log_info "核验 .env 文件权限..."
  if [ -f "${env_file}" ]; then
    local env_stat
    env_stat="$(stat -c '%a %U:%G %n' "${env_file}" 2>&1 || true)"
    log_info "${env_stat}"
    case "${env_stat}" in
      "600 root:root ${env_file}") log_ok ".env 权限 600 root:root 符合安全要求" ;;
      *) log_warn ".env 权限建议调整为 600 root:root（当前：${env_stat}）"; failed=$((failed+1)) ;;
    esac
    for key in OCTOBUS_BASE_URL OCTOBUS_TOKEN \
               SECURITY_TRIAGE_OCTOBUS_BASE_URL SECURITY_TRIAGE_OCTOBUS_TOKEN SECURITY_TRIAGE_OCTOBUS_CAPSET_ID SECURITY_TRIAGE_OCTOBUS_INSTANCE_ID SECURITY_TRIAGE_OCTOBUS_FULL_SERVICE \
               LLM_API_ENDPOINT LLM_API_KEY LLM_MODEL; do
      grep -q "^${key}=" "${env_file}" 2>/dev/null || log_warn ".env 缺少键：${key}（首次部署为空属正常，按 README 6.2 步骤 2c 填写）"
    done
  else
    log_warn ".env 尚未创建（deploy 子命令会生成占位副本）"
  fi

  log_info "核验外部 Docker volumes..."
  for vol in chaitin-private-knowledge-base chaitin-triage-state; do
    if docker volume inspect "${vol}" >/dev/null 2>&1; then
      log_ok "docker volume ${vol} 存在"
    else
      log_warn "docker volume ${vol} 不存在（deploy 子命令将创建）"; failed=$((failed+1))
    fi
  done

  log_info "核验安全边界：无 0.0.0.0 公网绑定..."
  local port_lines nm
  # 按预期容器列表生成表格，不用 label 过滤（注意：命令替换内禁止使用 local 关键字）
  port_lines="$(printf '%-30s %s\n' "NAMES" "PORTS"
    for nm in "${EXPECTED_CONTAINERS[@]}"; do
      docker ps --filter "name=^/${nm}$" --format '{{.Names}}\t{{.Ports}}' 2>/dev/null || true
    done)"
  echo "${port_lines}"
  if echo "${port_lines}" | grep -qE "[[:space:]]0\.0\.0\.0:|^0\.0\.0\.0:"; then
    log_warn "检测到 0.0.0.0 公网绑定，不符合 3.3.4 安全边界要求"; failed=$((failed+1))
  else
    log_ok "无 0.0.0.0 公网绑定（仅回环或内网通信）"
  fi

  log_info "核验主机公网监听（仅应 sshd 22）..."
  if command -v ss >/dev/null 2>&1; then
    ss -tlnp 2>&1 || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tlnp 2>&1 || true
  else
    log_warn "ss/netstat 均不可用，跳过监听检查"
  fi

  echo
  if [ "${failed}" -eq 0 ]; then log_ok "=== fast-verify：全部关键检查通过 ==="
  else log_warn "=== fast-verify：完成，共 ${failed} 项警告/失败（首次部署可接受）==="; fi
  return 0
}

cmd_deploy() {
  log_info "=== deploy：完整部署开始 ==="
  need_cmd docker
  need_cmd install
  cmd_fast_verify || true

  if [ ! -f "${PROJECT_ROOT}/agent-compose.yml" ] || [ ! -f "${PROJECT_ROOT}/.env.example" ]; then
    fail "PROJECT_ROOT=${PROJECT_ROOT} 不是有效仓库根（缺少 agent-compose.yml 或 .env.example）"
  fi

  local env_file="${PROJECT_ROOT}/.env"
  if [ ! -f "${env_file}" ]; then
    log_info ".env 不存在，基于 .env.example 生成 600 占位副本..."
    install -m 600 "${PROJECT_ROOT}/.env.example" "${env_file}"
    chown root:root "${env_file}" 2>/dev/null || true
    log_ok "已生成：${env_file}"
    log_warn "请编辑该 .env 填入真实凭据后再次运行 deploy（README 6 步骤 2c）"
  fi

  for vol in chaitin-private-knowledge-base chaitin-triage-state; do
    docker volume inspect "${vol}" >/dev/null 2>&1 && continue
    log_warn "docker volume ${vol} 不存在，正在创建..."
    docker volume create "${vol}" >/dev/null || fail "创建 volume ${vol} 失败"
    log_ok "已创建 volume ${vol}"
  done

  check_container_up "${DAEMON_CONTAINER}" || fail "daemon 容器 ${DAEMON_CONTAINER} 未运行，请先启动 Stack"
  local daemon_proj_path
  daemon_proj_path="$(resolve_daemon_project_path)"
  # NOTE: agent-compose CLI explicitly does not support -p/--project-name for
  # `up` or `project up` (it's only for selecting an already-deployed project
  # on run/exec/ps/down). The compose project name comes from the yml itself.
  log_info "注册项目：cd ${daemon_proj_path} && agent-compose -f agent-compose.yml project up"
  docker exec "${DAEMON_CONTAINER}" bash -lc 'cd "$1" && agent-compose -f agent-compose.yml project up' _ "${daemon_proj_path}" \
    || fail "agent-compose project up 失败"

  log_info "核验注册结果 project ls --json："
  docker exec "${DAEMON_CONTAINER}" agent-compose project ls --json 2>&1 || true
  log_info "核验调度 schedule list："
  docker exec "${DAEMON_CONTAINER}" agent-compose schedule list 2>&1 || true

  log_info "执行 guest 冒烟（alert-id=A-1001）..."
  cmd_smoke || log_warn "首次冒烟未成功，可稍后单独运行 smoke 复验"

  log_ok "=== deploy：完成 ==="
}

cmd_smoke() {
  log_info "=== smoke：guest 正向冒烟开始（超时 ${SMOKE_TIMEOUT_SECONDS}s，alert-id=A-1001） ==="
  need_cmd docker
  check_container_up "${DAEMON_CONTAINER}" || fail "daemon 容器 ${DAEMON_CONTAINER} 未运行"
  local run_rc=0
  local timeout_cmd=""
  if command -v timeout >/dev/null 2>&1; then timeout_cmd="timeout ${SMOKE_TIMEOUT_SECONDS}"
  else log_warn "系统无 timeout 命令，无法限制 guest 冒烟时长（建议安装 coreutils）"; fi
  set +e
  if [ -n "${timeout_cmd}" ]; then
    # shellcheck disable=SC2086
    docker exec "${DAEMON_CONTAINER}" agent-compose -p "${PROJECT_NAME}" \
      run triage-operator --rm \
      --command 'cd agent && node src/interfaces/cli.js --workflow security --alert-id A-1001' \
      </dev/null
    run_rc=$?
    if [ "${run_rc}" = "124" ]; then
      log_fail "smoke 超时（${SMOKE_TIMEOUT_SECONDS}s）"; return 124
    fi
  else
    docker exec "${DAEMON_CONTAINER}" agent-compose -p "${PROJECT_NAME}" \
      run triage-operator --rm \
      --command 'cd agent && node src/interfaces/cli.js --workflow security --alert-id A-1001' \
      </dev/null
    run_rc=$?
  fi
  set -e
  case "${run_rc}" in
    0|2) log_ok "smoke 完成（退出码 ${run_rc}；2 = manual_review 属正常业务态）"; return 0 ;;
    *) log_fail "smoke 失败（退出码 ${run_rc}）"; return "${run_rc}" ;;
  esac
}

cmd_reboot_verify() {
  log_info "=== reboot-verify：服务器重启自愈核验开始 ==="
  need_cmd docker
  need_cmd awk
  local boot_epoch=""
  local uptime_sec=""
  if command -v uptime >/dev/null 2>&1; then
    local boot_raw
    boot_raw="$(uptime -s 2>/dev/null || true)"
    if [ -n "${boot_raw}" ]; then
      boot_epoch="$(date -d "${boot_raw}" +%s 2>/dev/null || true)"
    fi
  fi
  if [ -z "${boot_epoch}" ] && [ -r /proc/uptime ]; then
    uptime_sec="$(awk -F. '{print $1}' /proc/uptime 2>/dev/null || true)"
    if [ -n "${uptime_sec}" ] && [ "${uptime_sec}" -gt 0 ] 2>/dev/null; then
      local now_epoch
      now_epoch="$(date +%s)"
      boot_epoch=$(( now_epoch - uptime_sec ))
    fi
  fi
  if [ -z "${boot_epoch}" ]; then
    local who_line
    who_line="$(who -b 2>/dev/null | awk '{print $3,$4}' || true)"
    [ -n "${who_line}" ] && boot_epoch="$(date -d "${who_line}" +%s 2>/dev/null || true)"
  fi
  [ -n "${boot_epoch}" ] || fail "无法解析系统启动时间（尝试 uptime / /proc/uptime / who -b 均失败）"
  local now_epoch uptime_display
  now_epoch="$(date +%s)"
  uptime_display=$(( now_epoch - boot_epoch ))
  log_info "系统启动时间 epoch=${boot_epoch}，uptime=${uptime_display}s（约 $((uptime_display/60)) 分钟）"

  local total=0 ok=0 bad=0
  echo "----------------------------------------------------------------------"
  printf "%-30s %-10s %-20s %-14s %s\n" "NAME" "RESTART" "StartedAt(UTC)" "StartedEpoch" "AUTO_RECOVERED"
  echo "----------------------------------------------------------------------"
  local cid
  while IFS= read -r cid; do
    [ -z "${cid}" ] && continue
    total=$((total+1))
    local name restart started_at started_epoch recovered
    name="$(docker inspect -f '{{.Name}}' "${cid}" | sed 's|^/||')"
    restart="$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "${cid}")"
    started_at="$(docker inspect -f '{{.State.StartedAt}}' "${cid}" | cut -c1-19 | tr 'T' ' ')"
    started_epoch="$(date -d "${started_at} UTC" +%s 2>/dev/null || echo 0)"
    if [ "${started_epoch}" -ge "${boot_epoch}" ] 2>/dev/null && [ "${restart}" = "always" ]; then
      recovered="YES"; ok=$((ok+1))
    else
      recovered="NO"; bad=$((bad+1))
    fi
    printf "%-30s %-10s %-20s %-14s %s\n" "${name}" "${restart}" "${started_at}" "${started_epoch}" "${recovered}"
  done < <(list_expected_cids)
  echo "----------------------------------------------------------------------"
  echo

  if [ "${total}" -eq 0 ]; then fail "未检测到任何常驻容器（预期：${EXPECTED_CONTAINERS[*]}）"
  elif [ "${bad}" -eq 0 ]; then
    log_ok "=== reboot-verify：全部 ${total} 个容器通过（StartedAt>=boot_epoch 且 restart=always）==="; return 0
  else
    log_fail "=== reboot-verify：${bad}/${total} 个容器未通过（请人工核对 StartedAt / restart 策略）==="; return 1
  fi
}

cmd_help() {
  cat <<'HELP_EOF'
deploy/deploy-and-verify.sh — 一键预检 / 部署 / 冒烟 / 重启自愈核验

用法（在服务器项目根执行）：
  bash deploy/deploy-and-verify.sh <子命令>

子命令：
  fast-verify    只读预检（容器/重启策略/.env/卷/安全边界）
  deploy         完整部署：预检 -> .env 占位 -> 建卷 -> agent-compose up -> 注册 -> smoke
  smoke          仅 guest 正向冒烟（alert-id=A-1001，0 或 2 视为正常）
  reboot-verify  服务器重启自愈核验（README 6 步骤 7，需要先 reboot 服务器）
  help           显示本帮助

环境变量：
  DEPLOY_DAEMON_PROJECT_PATH    覆盖 daemon 内项目绝对路径（默认：/data/chaitin/deploy-manifests/chaitin-triage-agent）
  SMOKE_TIMEOUT_SECONDS         guest 冒烟超时（默认：300）

说明：不回显任何 Secret；deploy 是唯一产生变更的子命令。
HELP_EOF
}

main() {
  local sub="${1:-help}"
  case "${sub}" in
    fast-verify)   cmd_fast_verify ;;
    deploy)        cmd_deploy ;;
    smoke)         cmd_smoke ;;
    reboot-verify) cmd_reboot_verify ;;
    help|-h|--help) cmd_help ;;
    *) echo "未知子命令：${sub}" >&2; cmd_help >&2; exit 2 ;;
  esac
}
main "$@"