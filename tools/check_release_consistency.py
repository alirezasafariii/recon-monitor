#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core import APP_VERSION, SCHEMA_VERSION  # noqa: E402

MARKER = f"<!-- recon-monitor-current: app={APP_VERSION} schema={SCHEMA_VERSION} -->"


def fail(message: str) -> None:
    raise SystemExit(f"release consistency error: {message}")


def read(path: str) -> str:
    file_path = ROOT / path
    if not file_path.is_file():
        fail(f"missing {path}")
    return file_path.read_text(encoding="utf-8")


def first_nonempty(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_marker(path: str) -> str:
    text = read(path)
    require(MARKER in text, f"{path} must contain canonical marker {MARKER!r}")
    return text


def require_schema_claim(path: str, text: str) -> None:
    schema = re.escape(str(SCHEMA_VERSION))
    require(
        re.search(rf"(?is)\bschema\b[^\n]{{0,120}}(?:\*\*)?{schema}(?:\*\*)?", text)
        is not None,
        f"{path} does not state current schema {SCHEMA_VERSION}",
    )


def main() -> int:
    cli_version = subprocess.check_output(
        [str(ROOT / "recon-monitor.sh"), "--version"],
        cwd=ROOT,
        text=True,
    ).strip()
    require(cli_version == APP_VERSION, f"CLI={cli_version!r}, core={APP_VERSION!r}")

    readme = require_marker("README.md")
    require(
        first_nonempty(readme) == f"# Recon Monitor {APP_VERSION}",
        "README.md heading is not the current application version",
    )
    require_schema_claim("README.md", readme[:5000])

    readme_fa = require_marker("README_FA.md")
    require(
        first_nonempty(readme_fa) == f"# راهنمای Recon Monitor {APP_VERSION}",
        "README_FA.md heading is not the current application version",
    )
    require_schema_claim("README_FA.md", readme_fa[:5000])

    architecture = require_marker("docs/ARCHITECTURE.md")
    require_schema_claim("docs/ARCHITECTURE.md", architecture)
    require("Recon Monitor 3.0 architecture" not in architecture, "architecture title is stale")
    require("SQLite schema 7" not in architecture, "architecture still claims schema 7")

    changelog = read("CHANGELOG.md")
    require(
        first_nonempty(changelog).startswith(f"# Recon Monitor {APP_VERSION}"),
        "CHANGELOG.md does not start with the current application version",
    )
    require_schema_claim("CHANGELOG.md", changelog[:8000])

    migration_path = f"MIGRATION-v{APP_VERSION}.md"
    migration = read(migration_path)
    require(APP_VERSION in first_nonempty(migration), f"{migration_path} heading version mismatch")
    require_schema_claim(migration_path, migration[:5000])

    release_notes_path = f"docs/RELEASE_NOTES_v{APP_VERSION}.md"
    release_notes = read(release_notes_path)
    require(APP_VERSION in first_nonempty(release_notes), f"{release_notes_path} heading version mismatch")
    require_schema_claim(release_notes_path, release_notes[:8000])

    print(f"release metadata consistent: app={APP_VERSION} schema={SCHEMA_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
