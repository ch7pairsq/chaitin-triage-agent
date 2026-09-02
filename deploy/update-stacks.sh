#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
default_repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=${UPDATE_STACKS_REPO_ROOT:-$default_repo_root}
mode=interactive
phase=all
env_file="$repo_root/.env"
backup_root=${UPDATE_STACKS_BACKUP_ROOT:-/data/chaitin_backup/chaitin-triage-agent}
state_root=${UPDATE_STACKS_STATE_ROOT:-/data/chaitin}
command_runner=${UPDATE_STACKS_COMMAND_RUNNER:-}

usage() {
  echo "usage: deploy/update-stacks.sh [--mode interactive|release-worker] [--phase all|platform|release|verify] [--env-file FILE] [--backup-root DIR] [--state-root DIR]" >&2
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) [ "$#" -ge 2 ] || usage; mode="$2"; shift 2 ;;
    --phase) [ "$#" -ge 2 ] || usage; phase="$2"; shift 2 ;;
    --env-file) [ "$#" -ge 2 ] || usage; env_file="$2"; shift 2 ;;
    --backup-root) [ "$#" -ge 2 ] || usage; backup_root="$2"; shift 2 ;;
    --state-root) [ "$#" -ge 2 ] || usage; state_root="$2"; shift 2 ;;
    *) usage ;;
  esac
done

case "$mode:$phase" in
  interactive:all|release-worker:platform|release-worker:release|release-worker:verify) ;;
  *) usage ;;
esac

run_external() {
  if [ -n "$command_runner" ]; then
    /bin/sh "$command_runner" "$@"
  else
    "$@"
  fi
}

capture_external() {
  if [ -n "$command_runner" ]; then
    /bin/sh "$command_runner" "$@"
  else
    "$@"
  fi
}

wazuh_compose="$repo_root/deploy/stacks/wazuh/docker-compose.yml"
wazuh_certs_compose="$repo_root/deploy/stacks/wazuh/generate-indexer-certs.yml"
triage_compose="$repo_root/deploy/stacks/triage-platform/docker-compose.yml"
release_compose="$repo_root/deploy/stacks/release-webhook/docker-compose.yml"
current_stage=preflight
rollback_point=none
platform_stopped=0

handle_exit() {
  exit_code="$1"
  trap - EXIT HUP INT TERM
  if [ "$exit_code" -ne 0 ]; then
    echo "Stack update failed: stage=$current_stage" >&2
    echo "rollback_point=$rollback_point" >&2
    if [ "$platform_stopped" -eq 1 ]; then
      run_external docker compose --env-file "$env_file" -f "$triage_compose" up -d octobus agent-compose agent-compose-ui >/dev/null 2>&1 || true
    fi
  fi
  exit "$exit_code"
}
trap 'handle_exit $?' EXIT HUP INT TERM

preflight() {
  current_stage=preflight
  case "$state_root" in
    /*) ;;
    *) echo "state root must be an absolute path: $state_root" >&2; return 78 ;;
  esac
  case "$backup_root" in
    /*) ;;
    *) echo "backup root must be an absolute path: $backup_root" >&2; return 78 ;;
  esac
  [ "$state_root" != "/" ] || { echo "state root must not be /" >&2; return 78; }
  [ "$backup_root" != "/" ] || { echo "backup root must not be /" >&2; return 78; }
  case "$backup_root" in
    "$state_root"|"$state_root"/*)
      echo "backup root must be outside business state root: backup=$backup_root state=$state_root" >&2
      return 78
      ;;
  esac
  for file in \
    "$env_file" \
    "$repo_root/agent-compose.yml" \
    "$repo_root/services/security-ops/resources/knowledge.jsonl" \
    "$wazuh_compose" \
    "$wazuh_certs_compose" \
    "$triage_compose" \
    "$release_compose" \
    "$repo_root/deploy/stacks/wazuh/prepare-config.sh" \
    "$repo_root/deploy/stacks/triage-platform/prepare-config.sh" \
    "$repo_root/deploy/stacks/triage-platform/bootstrap.sh" \
    "$repo_root/deploy/stacks/triage-platform/verify.sh" \
    "$repo_root/deploy/stacks/release-webhook/prepare-config.sh"
  do
    [ -r "$file" ] || { echo "required deployment file is missing: $file" >&2; return 78; }
  done

  expected_branch=${RELEASE_DEPLOY_BRANCH:-develop}
  actual_branch=$(capture_external git -C "$repo_root" rev-parse --abbrev-ref HEAD)
  [ "$actual_branch" = "$expected_branch" ] || { echo "deployment branch is $actual_branch, expected $expected_branch" >&2; return 78; }
  worktree_status=$(capture_external git -C "$repo_root" status --porcelain)
  [ -z "$worktree_status" ] || { echo "deployment worktree is not clean" >&2; return 78; }

  /bin/sh -n "$repo_root/deploy/stacks/wazuh/prepare-config.sh"
  /bin/sh -n "$repo_root/deploy/stacks/triage-platform/prepare-config.sh"
  /bin/sh -n "$repo_root/deploy/stacks/triage-platform/bootstrap.sh"
  /bin/sh -n "$repo_root/deploy/stacks/triage-platform/verify.sh"
  /bin/sh -n "$repo_root/deploy/stacks/release-webhook/prepare-config.sh"
  run_external docker info >/dev/null
  run_external docker compose --env-file "$env_file" -f "$wazuh_certs_compose" config --quiet
  run_external docker compose --env-file "$env_file" -f "$wazuh_compose" config --quiet
  run_external docker compose --env-file "$env_file" -f "$triage_compose" config --quiet
  run_external docker compose --env-file "$env_file" -f "$release_compose" config --quiet
}

create_backups() {
  timestamp=$(date '+%Y%m%d-%H%M%S')
  commit_backup="$backup_root/commit-backup-$timestamp.bundle"
  configuration_backup="$backup_root/configuration-backup-$timestamp.tar.gz"
  sqlite_backup="$backup_root/sqlite-backup-$timestamp.tar.gz"

  mkdir -p "$backup_root"
  chmod 0700 "$backup_root"
  for target in "$commit_backup" "$configuration_backup" "$sqlite_backup"; do
    [ ! -e "$target" ] || { echo "backup target already exists: $target" >&2; return 73; }
  done

  current_stage=backup-commit
  run_external git -C "$repo_root" bundle create "$commit_backup" HEAD
  [ -s "$commit_backup" ] || { echo "commit backup was not created" >&2; return 1; }
  chmod 0600 "$commit_backup"
  rollback_point="$commit_backup"

  current_stage=backup-configuration
  set -- .env
  for relative_path in \
    deploy/stacks/wazuh/config \
    deploy/stacks/wazuh/generated \
    deploy/stacks/triage-platform/generated \
    deploy/stacks/release-webhook/generated
  do
    [ ! -e "$repo_root/$relative_path" ] || set -- "$@" "$relative_path"
  done
  tar -czf "$configuration_backup" -C "$repo_root" "$@"
  chmod 0600 "$configuration_backup"
  rollback_point="$commit_backup,$configuration_backup"

  current_stage=backup-sqlite-stop
  run_external docker compose --env-file "$env_file" -f "$triage_compose" stop agent-compose octobus
  platform_stopped=1

  current_stage=backup-sqlite
  sqlite_files=$(
    cd "$state_root"
    for directory in octobus/data agent-compose/data; do
      if [ -d "$directory" ]; then
        find "$directory" -type f \( \
          -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o \
          -name '*.sqlite' -o -name '*.sqlite-wal' -o -name '*.sqlite-shm' -o \
          -name '*.sqlite3' -o -name '*.sqlite3-wal' -o -name '*.sqlite3-shm' \
        \) -print
      fi
    done
  )
  if [ -n "$sqlite_files" ]; then
    printf '%s\n' "$sqlite_files" | tar -czf "$sqlite_backup" -C "$state_root" -T -
  else
    tar -czf "$sqlite_backup" --files-from /dev/null
  fi
  chmod 0600 "$sqlite_backup"
  rollback_point="$commit_backup,$configuration_backup,$sqlite_backup"
  echo "backup_commit=$commit_backup"
  echo "backup_configuration=$configuration_backup"
  echo "backup_sqlite=$sqlite_backup"
}

update_platform() {
  create_backups

  current_stage=runtime-directories
  mkdir -p \
    "$state_root/octobus/data" \
    "$state_root/agent-compose/data" \
    "$state_root/agent-compose/ui"
  run_external chown 999:999 "$state_root/octobus/data"

  current_stage=wazuh-configuration
  if [ ! -s "$repo_root/deploy/stacks/wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
    run_external docker compose --env-file "$env_file" -f "$wazuh_certs_compose" run --rm generator
  fi
  run_external /bin/sh "$repo_root/deploy/stacks/wazuh/prepare-config.sh" "$env_file"
  run_external /bin/sh "$repo_root/deploy/stacks/triage-platform/prepare-config.sh"
  run_external /bin/sh "$repo_root/deploy/stacks/release-webhook/prepare-config.sh" "$env_file"

  current_stage=wazuh
  run_external docker compose --env-file "$env_file" -f "$wazuh_compose" up -d --build

  current_stage=triage-platform
  run_external docker compose --env-file "$env_file" -f "$triage_compose" up -d
  run_external docker compose --env-file "$env_file" -f "$triage_compose" up -d --force-recreate agent-compose agent-compose-ui
  platform_stopped=0

  current_stage=bootstrap
  run_external /bin/sh "$repo_root/deploy/stacks/triage-platform/bootstrap.sh"
}

update_release() {
  current_stage=release-webhook
  run_external docker compose --env-file "$env_file" -f "$release_compose" up -d --build
}

verify_platform() {
  current_stage=verification
  run_external /bin/sh "$repo_root/deploy/stacks/triage-platform/verify.sh"
}

preflight
case "$mode:$phase" in
  interactive:all)
    update_platform
    update_release
    verify_platform
    ;;
  release-worker:platform) update_platform ;;
  release-worker:release) update_release ;;
  release-worker:verify) verify_platform ;;
esac

current_stage=complete
echo "Stack update phase completed: mode=$mode phase=$phase"
