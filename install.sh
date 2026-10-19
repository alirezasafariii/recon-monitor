#!/usr/bin/env bash
set -Eeuo pipefail
# BEGIN recon-monitor project Katana dispatch (PR 193)
# Separate entry point: never run project initialization for this operation.
if [[ "${1:-}" == "--install-project-katana" ]]; then
  if [[ "$#" -ne 1 ]]; then
    echo "Usage: ./install.sh [--install-missing] or ./install.sh --install-project-katana" >&2
    exit 2
  fi
  _recon_katana_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  exec bash "$_recon_katana_root/tools/install_project_katana.sh"
fi
# END recon-monitor project Katana dispatch (PR 193)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_MISSING=0
[[ "${1:-}" == "--install-missing" ]] && INSTALL_MISSING=1
[[ $# -le 1 ]] || { echo "Usage: ./install.sh [--install-missing]" >&2; exit 1; }

export PATH="/usr/local/bin:/opt/homebrew/bin:$HOME/go/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
required=(bash sqlite3 curl python3)
passive=(subfinder assetfinder dnsx waybackurls katana httpx)
optional=(notify naabu nuclei)
missing_required=()
missing_passive=()
missing_optional=()

echo "Recon Monitor 8.x dependency check"
echo "=================================="
for cmd in "${required[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then echo "[OK]      $cmd -> $(command -v "$cmd")"; else echo "[MISSING] $cmd (required)"; missing_required+=("$cmd"); fi
done
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PYVER' || { echo "[MISSING] Python 3.10+ is required" >&2; exit 1; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYVER
fi
for cmd in "${passive[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then echo "[OK]      $cmd -> $(command -v "$cmd")"; else echo "[MISSING] $cmd (related stage will degrade/skip)"; missing_passive+=("$cmd"); fi
done
for cmd in "${optional[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then echo "[OK]      $cmd -> $(command -v "$cmd")"; else echo "[OPTIONAL] $cmd"; missing_optional+=("$cmd"); fi
done

if [[ "$INSTALL_MISSING" -eq 1 ]]; then
  command -v brew >/dev/null 2>&1 || { echo "Homebrew is required for --install-missing." >&2; exit 1; }
  # Install only commands that are actually missing. Existing formulae are not upgraded.
  for cmd in jq sqlite python subfinder dnsx katana httpx nuclei naabu; do
    check="$cmd"
    [[ "$cmd" == "python" ]] && check="python3"
    if ! command -v "$check" >/dev/null 2>&1; then
      brew install "$cmd" || true
    fi
  done
  if command -v go >/dev/null 2>&1; then
    command -v assetfinder >/dev/null 2>&1 || go install github.com/tomnomnom/assetfinder@latest || true
    command -v waybackurls >/dev/null 2>&1 || go install github.com/tomnomnom/waybackurls@latest || true
    command -v notify >/dev/null 2>&1 || go install github.com/projectdiscovery/notify/cmd/notify@latest || true
  fi
fi

chmod +x "$ROOT_DIR/recon-monitor.sh" "$ROOT_DIR/install.sh" "$ROOT_DIR/upgrade-v2.sh" "$ROOT_DIR/upgrade-v3.sh" "$ROOT_DIR/app/recon_monitor.py"
# BEGIN recon-monitor verified Katana provisioning (PR 193)
# --install-missing must provision the tested binary, not rely on stock Brew.
if [[ "${INSTALL_MISSING:-0}" == "1" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    if ! command -v brew >/dev/null 2>&1; then
      echo "[ERROR] Go compiler is required for pinned Katana" >&2
      exit 1
    fi
    brew install go
  fi
  bash "$ROOT_DIR/tools/install_project_katana.sh"
elif [[ ! -x "$ROOT_DIR/state/bin/katana" ]]; then
  echo "[WARN] Tested project Katana not found. Install with:" >&2
  echo "       ./install.sh --install-project-katana" >&2
fi
# END recon-monitor verified Katana provisioning (PR 193)

"$ROOT_DIR/recon-monitor.sh" init

echo
echo "Run health checks:"
echo "  cd $ROOT_DIR"
echo "  ./recon-monitor.sh doctor"
