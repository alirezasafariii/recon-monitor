"""Project Katana runtime contract shared by CLI preflight and URL stage."""

from __future__ import annotations
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


_COMPLETION_FLAG = "-recon-completion-log"
_COMPLETION_TEXT = "EXPERIMENTAL v1 per-origin standard-engine completion JSONL"
_CHECKPOINT_FLAG = "-recon-checkpoint-dir"
_CHECKPOINT_TEXT = "EXPERIMENTAL v1 durable standard-engine GET frontier checkpoint"
_MAX_HELP_BYTES = 1024 * 1024


def completion_supported(help_text: str) -> bool:
    return _COMPLETION_FLAG in help_text and _COMPLETION_TEXT in help_text


def checkpoint_supported(help_text: str) -> bool:
    return _CHECKPOINT_FLAG in help_text and _CHECKPOINT_TEXT in help_text


def urls_enabled(targets) -> bool:
    """Match Orchestrator._run_stage: modules.urls defaults to enabled."""
    return any(bool(target.modules.get("urls", True)) for target in targets)


def check_binary(binary: Path, *, timeout: float = 5.0) -> str | None:
    """Return a diagnostic (failure), or None when both contracts are proven.

    Run only '-h' offline, bound its runtime and on-disk output. This is a
    capability check, not a proof that every future crawl will succeed.
    """
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return f"Patched project Katana is missing or not executable: {binary}"
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            result = subprocess.run(
                [str(binary), "-h"],
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
            if result.returncode != 0:
                return f"Project Katana help probe failed (exit {result.returncode}): {binary}"
            if output.tell() > _MAX_HELP_BYTES:
                return f"Project Katana help output exceeds {_MAX_HELP_BYTES} bytes: {binary}"
            output.seek(0)
            help_text = output.read(_MAX_HELP_BYTES + 1).decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Project Katana capability probe failed: {exc}"
    if not completion_supported(help_text) or not checkpoint_supported(help_text):
        return f"Project Katana lacks verified completion/checkpoint contract: {binary}"
    return None


def check_project(root: Path) -> str | None:
    error = check_binary(root / "state" / "bin" / "katana")
    if error is not None:
        return error + "\nInstall with: ./install.sh --install-project-katana"
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify project Katana without crawling")
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    error = check_binary(args.binary)
    if error:
        parser.exit(1, error + "\n")
    print("KATANA CONTRACT VERIFIED")
