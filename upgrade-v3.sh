#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${1:-$HOME/Downloads/recon-monitor}"

[[ -d "$DEST_DIR" ]] || { echo "Destination project not found: $DEST_DIR" >&2; exit 1; }
[[ "$SOURCE_DIR" != "$DEST_DIR" ]] || { echo "Source and destination must be different directories." >&2; exit 1; }

# Do not replace program files while a live reconnaissance run owns the lock.
if [[ -d "$DEST_DIR/.run.lock" ]]; then
  LOCK_PID="$(cat "$DEST_DIR/.run.lock/pid" 2>/dev/null || true)"
  if [[ -n "$LOCK_PID" ]] && kill -0 "$LOCK_PID" 2>/dev/null; then
    echo "A Recon Monitor run is active (PID $LOCK_PID). Stop it safely before upgrading." >&2
    exit 1
  fi
  rm -rf "$DEST_DIR/.run.lock"
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$DEST_DIR/upgrade-backup-v3-$STAMP"
mkdir -p "$BACKUP_DIR/program" "$BACKUP_DIR/data"

PROGRAM_ITEMS=(
  app docs tests fixtures plugins
  recon-monitor.sh install.sh upgrade-v2.sh upgrade-v3.sh
  README.md README_FA.md CHANGELOG.md MIGRATION-v2.md MIGRATION-v3.md
  tool-compatibility.json config.env.example MANIFEST.sha256
)

for item in "${PROGRAM_ITEMS[@]}"; do
  [[ -e "$DEST_DIR/$item" ]] && cp -a "$DEST_DIR/$item" "$BACKUP_DIR/program/" || true
done

DB_PATH="$DEST_DIR/state/recon-v2.db"
if [[ -f "$DB_PATH" ]]; then
  python3 - "$DB_PATH" "$BACKUP_DIR/data/recon-v2.db" <<'PY'
import sqlite3, sys
source = sqlite3.connect(sys.argv[1])
destination = sqlite3.connect(sys.argv[2])
try:
    source.backup(destination)
finally:
    source.close(); destination.close()
PY
fi

# Background services execute program files from this directory. Stop them before replacement.
if [[ -x "$DEST_DIR/recon-monitor.sh" ]]; then
  (cd "$DEST_DIR" && ./recon-monitor.sh dashboard stop >/dev/null 2>&1) || true
  (cd "$DEST_DIR" && ./recon-monitor.sh api stop >/dev/null 2>&1) || true
fi

rollback() {
  status=$?
  trap - ERR
  echo "Upgrade failed; restoring program files and database..." >&2
  for item in "${PROGRAM_ITEMS[@]}"; do rm -rf "$DEST_DIR/$item"; done
  if [[ -d "$BACKUP_DIR/program" ]]; then cp -a "$BACKUP_DIR/program/." "$DEST_DIR/"; fi
  if [[ -f "$BACKUP_DIR/data/recon-v2.db" ]]; then
    mkdir -p "$DEST_DIR/state"
    cp -f "$BACKUP_DIR/data/recon-v2.db" "$DB_PATH"
  fi
  echo "Rollback completed. Backup: $BACKUP_DIR" >&2
  exit "$status"
}
trap rollback ERR

mkdir -p "$DEST_DIR/app" "$DEST_DIR/docs" "$DEST_DIR/tests" "$DEST_DIR/fixtures" "$DEST_DIR/plugins" "$DEST_DIR/policies"
rm -rf "$DEST_DIR/app" "$DEST_DIR/docs" "$DEST_DIR/tests" "$DEST_DIR/fixtures"
cp -a "$SOURCE_DIR/app" "$DEST_DIR/app"
cp -a "$SOURCE_DIR/docs" "$DEST_DIR/docs"
cp -a "$SOURCE_DIR/tests" "$DEST_DIR/tests"
cp -a "$SOURCE_DIR/fixtures" "$DEST_DIR/fixtures"
# Merge release plugins without deleting user-created plugin directories.
cp -a "$SOURCE_DIR/plugins/." "$DEST_DIR/plugins/"

for item in recon-monitor.sh install.sh upgrade-v2.sh upgrade-v3.sh README.md README_FA.md CHANGELOG.md MIGRATION-v2.md MIGRATION-v3.md tool-compatibility.json config.env.example MANIFEST.sha256; do
  [[ -e "$SOURCE_DIR/$item" ]] && cp -a "$SOURCE_DIR/$item" "$DEST_DIR/$item"
done
cp -a "$SOURCE_DIR/policies/targets.json.example" "$DEST_DIR/policies/targets.json.example"

chmod +x "$DEST_DIR/recon-monitor.sh" "$DEST_DIR/install.sh" "$DEST_DIR/upgrade-v2.sh" "$DEST_DIR/upgrade-v3.sh" "$DEST_DIR/app/recon_monitor.py"

cd "$DEST_DIR"
./recon-monitor.sh init --no-wizard
python3 -m compileall -q app tests
./recon-monitor.sh test >/dev/null
[[ "$(./recon-monitor.sh --version)" == "3.0.0" ]]

trap - ERR

echo "Upgraded: $DEST_DIR"
echo "Backup:   $BACKUP_DIR"
echo "Version:  $(./recon-monitor.sh --version)"
echo "Preserved: config.env, targets.txt, policies/targets.json, recon.db, state/, output/, reports/, logs/, and user plugins"
echo "Background Dashboard/API services were stopped. Restart them after running doctor and tests."
