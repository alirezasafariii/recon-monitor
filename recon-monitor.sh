#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# launchd and non-interactive shells have a minimal PATH.
export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

# Prefer the tested, project-owned Katana for CLI and launchd invocations.
PROJECT_KATANA="$ROOT_DIR/state/bin/katana"
if [[ -e "$PROJECT_KATANA" || -L "$PROJECT_KATANA" ]]; then
  if [[ ! -f "$PROJECT_KATANA" || ! -x "$PROJECT_KATANA" ]]; then
    printf '[ERROR] Project Katana is not executable: %s\n' "$PROJECT_KATANA" >&2
    exit 1
  fi
  export PATH="$ROOT_DIR/state/bin:$PATH"
fi


PYTHON_BIN="${RECON_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    printf '[ERROR] python3 is required.\n' >&2
    exit 1
  fi
fi


# BEGIN recon-monitor verified Katana run guard (PR 193)
# Real recon runs must not silently fall back to stock Katana on PATH.
# Keep doctor, init, and preview-only commands available on fresh checkouts.
if [[ "${1:-}" == "run" ]]; then
  _recon_preview=0
  for _recon_arg in "$@"; do
    case "$_recon_arg" in
      --dry-run|--help|-h) _recon_preview=1 ;;
    esac
  done
  if [[ "$_recon_preview" -eq 0 ]]; then
    if [[ ! -f "$PROJECT_KATANA" || ! -x "$PROJECT_KATANA" ]]; then
      printf '[ERROR] Patched project Katana is required for recon runs: %s\n' "$PROJECT_KATANA" >&2
      printf '[ERROR] Install it with: ./install.sh --install-project-katana\n' >&2
      exit 1
    fi
    _recon_katana_help="$("$PROJECT_KATANA" -h 2>&1 || true)"
    if [[ "$_recon_katana_help" != *"recon-checkpoint-dir"* ||
          "$_recon_katana_help" != *"recon-completion-log"* ]]; then
      printf '[ERROR] Project Katana lacks the required checkpoint/completion capabilities.\n' >&2
      printf '[ERROR] Reinstall it with: ./install.sh --install-project-katana\n' >&2
      exit 1
    fi
  fi
fi
# END recon-monitor verified Katana run guard (PR 193)

exec "$PYTHON_BIN" "$ROOT_DIR/app/recon_monitor.py" "$@"
