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

exec "$PYTHON_BIN" "$ROOT_DIR/app/recon_monitor.py" "$@"
