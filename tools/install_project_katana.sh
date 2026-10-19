#!/usr/bin/env bash
# Build the exact Katana producer required for verified frontier/checkpoint support.
# Usage: tools/install_project_katana.sh
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM="https://github.com/projectdiscovery/katana.git"
UPSTREAM_COMMIT="35267ac5c8ff1db9694a319d0eb466ed97b0969f"
PATCH_FILE="$ROOT_DIR/docs/prototypes/katana-v1.8.0-frontier.patch"
DEST_DIR="$ROOT_DIR/state/bin"
DEST="$DEST_DIR/katana"

if [[ $# -ne 0 ]]; then
  printf 'Usage: %s\n' "$0" >&2
  exit 2
fi
for tool in git go python3 mktemp install mv; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf '[ERROR] Missing required build tool: %s\n' "$tool" >&2
    exit 1
  }
done
[[ -f "$PATCH_FILE" ]] || {
  printf '[ERROR] Missing producer patch: %s\n' "$PATCH_FILE" >&2
  exit 1
}
[[ -f "$ROOT_DIR/tools/katana_stage_local_acceptance.py" ]] || {
  printf '[ERROR] Missing local acceptance test\n' >&2
  exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/recon-katana-build.XXXXXX")"
STAGED=""
cleanup() {
  if [[ -n "$STAGED" ]]; then rm -f "$STAGED"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

printf '[INFO] Cloning pinned Katana source\n'
git clone --quiet "$UPSTREAM" "$WORK/source"
git -C "$WORK/source" checkout --quiet --detach "$UPSTREAM_COMMIT"
ACTUAL_COMMIT="$(git -C "$WORK/source" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$UPSTREAM_COMMIT" ]] || {
  printf '[ERROR] Unexpected Katana upstream commit: %s\n' "$ACTUAL_COMMIT" >&2
  exit 1
}
git -C "$WORK/source" apply --check "$PATCH_FILE"
git -C "$WORK/source" apply "$PATCH_FILE"

printf '[INFO] Building patched Katana with %s\n' "$(go version)"
(
  cd "$WORK/source"
  GOTOOLCHAIN=local go build -buildvcs=false -trimpath -o "$WORK/katana" ./cmd/katana
)

# A version label like v1.8.0 is insufficient to identify the patched producer.
HELP="$("$WORK/katana" -h 2>&1 || true)"
for capability in recon-checkpoint-dir recon-completion-log; do
  if [[ "$HELP" != *"$capability"* ]]; then
    printf '[ERROR] Built Katana lacks required capability: %s\n' "$capability" >&2
    exit 1
  fi
done

python3 "$ROOT_DIR/app/katana_runtime_contract.py" "$WORK/katana" >/dev/null\nprintf '[INFO] Running actual Stage acceptance against loopback servers\n'
if ! python3 "$ROOT_DIR/tools/katana_stage_local_acceptance.py" \
     --binary "$WORK/katana" --output "$WORK/katana-stage-acceptance.json" \
     >"$WORK/acceptance.log" 2>&1; then
  cat "$WORK/acceptance.log" >&2
  printf '[ERROR] Katana localhost acceptance failed; existing binary unchanged\n' >&2
  exit 1
fi

# Promote a validated binary on the same filesystem. Failures leave the previous
# project-owned binary intact; existing running processes keep their old inode.
mkdir -p "$DEST_DIR"
STAGED="$(mktemp "$DEST_DIR/.katana-next.XXXXXX")"
install -m 755 "$WORK/katana" "$STAGED"
mv -f "$STAGED" "$DEST"
STAGED=""

# Validate what the project launcher actually selects (also used by launchd).
PROBE="$WORK/path-probe.sh"
printf '#!/bin/sh\ncommand -v katana\n' > "$PROBE"
chmod +x "$PROBE"
SELECTED="$(RECON_PYTHON="$PROBE" bash "$ROOT_DIR/recon-monitor.sh" doctor)"
[[ "$SELECTED" == "$DEST" ]] || {
  printf '[ERROR] Launcher selected %s, expected %s\n' "$SELECTED" "$DEST" >&2
  exit 1
}

if command -v shasum >/dev/null 2>&1; then
  HASH="$(shasum -a 256 "$DEST" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  HASH="$(sha256sum "$DEST" | awk '{print $1}')"
else
  HASH="unavailable"
fi

printf '[OK] Installed tested Katana: %s\n' "$DEST"
printf '[OK] Upstream: %s\n' "$UPSTREAM_COMMIT"
printf '[OK] Binary SHA256: %s\n' "$HASH"
