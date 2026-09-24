#!/usr/bin/env python3
"""Bounded, opt-in verification of fresh JS candidates from a saved run.

This is NOT the full JavaScript analysis stage: it never changes the source run,
the database, baseline, latest pointers, or stored JavaScript artifacts.
A dry-run is the default; --execute performs at most 12 pinned GETs.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

from core import (  # noqa: E402
    AppPaths, Config, Logger, PolicySet, ReconError, RunLock,
    atomic_write_text, classify_url, json_dumps,
)
from stages import _download_url, _select_javascript_urls  # noqa: E402

MAX_NEW = 12
MAX_PER_HOST = 3
ACCEPTED_JS_TYPES = (
    "javascript", "ecmascript", "text/plain",
    "application/octet-stream", "application/json",
)


def _valid_run_id(run_id: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,79}", run_id) is not None


def select_fresh_js(
    current: Path,
    *,
    run_id: str,
    target: str,
    policy: object,
    allowed_hosts: tuple[str, ...],
    max_new: int,
    per_host: int,
) -> tuple[list[str], dict[str, int]]:
    """Choose only never-attempted JS from the production host-balanced quota."""
    if not (1 <= max_new <= MAX_NEW and 1 <= per_host <= MAX_PER_HOST):
        raise ReconError("Validation caps: --max-new 1..12 and --per-host 1..3.")
    if not _valid_run_id(run_id):
        raise ReconError("Invalid source run ID.")
    if not allowed_hosts or len(set(allowed_hosts)) != len(allowed_hosts):
        raise ReconError("Specify distinct, explicitly authorized --hosts.")
    if not all(
        h and h == h.lower() and re.fullmatch(r"[a-z0-9.-]+", h)
        and policy.host_in_scope(h)
        for h in allowed_hosts
    ):
        raise ReconError("Each explicitly authorized host must be in the target policy scope.")

    url_file = current / "urls.txt"
    availability_file = current / "javascript-availability.jsonl"
    source_file = current / "url-collection.json"
    if not all(p.is_file() for p in (url_file, availability_file, source_file)):
        raise ReconError("Source run is missing urls.txt, availability, or URL collection metadata.")
    try:
        source = json.loads(source_file.read_text(encoding="utf-8"))
        if source.get("run_id") != run_id or source.get("target") != target:
            raise ReconError("Source URL collection belongs to a different run or target.")
        attempted = {
            str(row["url"])
            for line in availability_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
            for row in (json.loads(line),)
            if isinstance(row, dict) and isinstance(row.get("url"), str)
        }
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ReconError("Cannot read source run evidence.") from exc

    candidates = sorted({
        url.strip()
        for url in url_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if classify_url(url.strip()) == "javascript"
    })
    selected, _ = _select_javascript_urls(candidates, policy.limits.max_js_files)
    eligible: dict[str, list[str]] = {host: [] for host in allowed_hosts}
    for url in selected:
        if url in attempted or not policy.url_in_scope(url):
            continue
        parts = urllib.parse.urlsplit(url)
        if (
            parts.scheme != "https" or parts.hostname not in eligible
            or parts.username or parts.password or parts.port not in (None, 443)
            or parts.query or parts.fragment or not parts.path.lower().endswith(".js")
        ):
            continue
        eligible[parts.hostname].append(url)

    planned: list[str] = []
    for _ in range(per_host):
        for host in allowed_hosts:
            if len(planned) >= max_new:
                break
            if eligible[host]:
                planned.append(eligible[host].pop(0))
    counts = dict(collections.Counter(
        urllib.parse.urlsplit(url).hostname for url in planned
    ))
    return planned, counts


def execute_validation(
    paths: AppPaths,
    config: Config,
    policy: object,
    run_id: str,
    planned: list[str],
    *,
    download=_download_url,
    pause=time.sleep,
) -> tuple[Path, list[dict[str, object]]]:
    """Use the real pinned downloader, but never persist source-run changes."""
    if not config.authorized:
        raise ReconError("Run authorization is not enabled in config.env.")
    if not planned or len(planned) > MAX_NEW:
        raise ReconError("Validation requires 1..12 explicitly scoped URLs.")

    logger = Logger(paths)
    ctx = SimpleNamespace(
        config=config, policy=policy, budget=None,
        next_requested=lambda: False,
    )
    rows: list[dict[str, object]] = []
    out_dir: Path | None = None
    with RunLock(paths.lock, logger):
        # A validation's results live away from current/, runs/, DB and LATEST.
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        out_dir = paths.output / policy.name / "js-validations" / (
            f"{run_id}-{stamp}-{os.getpid()}"
        )
        out_dir.mkdir(parents=True, exist_ok=False)
        try:
            for index, url in enumerate(planned):
                if index:
                    pause(1.0 / max(1, policy.limits.request_rate))
                host = urllib.parse.urlsplit(url).hostname or ""
                row: dict[str, object] = {
                    "host": host,
                    "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                }
                try:
                    result = download(
                        ctx, url, policy.limits.max_js_bytes, max_redirects=0,
                    )
                    status = int(result.get("status_code") or 0)
                    content_type = str(result.get("content_type") or "").lower()
                    if result.get("not_found"):
                        state = "not_found"
                    elif "data" in result:
                        state = (
                            "javascript"
                            if not content_type or any(
                                typ in content_type for typ in ACCEPTED_JS_TYPES
                            )
                            else "unexpected_content_type"
                        )
                    else:
                        state = "error"
                    row.update(
                        status_code=status,
                        state=state,
                        content_type=content_type,
                        bytes=len(result["data"]) if "data" in result else 0,
                        error_code=str(result.get("error") or "")[:80],
                    )
                except Exception as exc:
                    # No URL, response body or token-bearing exception message in reports.
                    row.update(status_code=0, state="error", content_type="",
                               bytes=0, error_code=type(exc).__name__)
                rows.append(row)
                print(
                    f"{host}: HTTP {row['status_code']} | "
                    f"{row['state']} | {row['content_type'] or '<missing>'}"
                )
                if row["status_code"] in (403, 429):
                    print("Access denied or rate limited: stopping the validation.")
                    break
        finally:
            atomic_write_text(
                out_dir / "results.jsonl",
                "".join(json_dumps(row) + "\n" for row in rows),
            )
            atomic_write_text(
                out_dir / "summary.json",
                json_dumps({
                    "source_run_id": run_id,
                    "target": policy.name,
                    "planned": len(planned),
                    "attempted": len(rows),
                    "states": dict(collections.Counter(
                        str(row["state"]) for row in rows
                    )),
                    "note": "Bounded JS download validation only; not a full stage or completed scan.",
                }, pretty=True) + "\n",
            )
    return out_dir, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, dest="run_id")
    parser.add_argument("--target", required=True)
    parser.add_argument("--hosts", nargs="+", required=True,
                        help="Explicitly authorized, exact hostnames; no wildcards")
    parser.add_argument("--max-new", type=int, default=MAX_NEW)
    parser.add_argument("--per-host", type=int, default=MAX_PER_HOST)
    parser.add_argument("--execute", action="store_true",
                        help="Opt in to up to 12 bounded GETs; preview is default")
    args = parser.parse_args(argv)
    try:
        if not _valid_run_id(args.run_id):
            raise ReconError("Invalid source run ID.")
        if not (1 <= args.max_new <= MAX_NEW and 1 <= args.per_host <= MAX_PER_HOST):
            raise ReconError("Validation caps: --max-new 1..12 and --per-host 1..3.")
        paths = AppPaths.from_root(ROOT)
        policies = PolicySet.load(paths)
        matches = policies.select(args.target)
        if len(matches) != 1 or matches[0].name != args.target:
            raise ReconError("Specify exactly one configured target policy name.")
        policy = matches[0]
        hosts = tuple(host.strip().lower() for host in args.hosts)
        planned, counts = select_fresh_js(
            paths.output / policy.name / "runs" / args.run_id / "current",
            run_id=args.run_id, target=policy.name, policy=policy,
            allowed_hosts=hosts, max_new=args.max_new, per_host=args.per_host,
        )
        print(f"Fresh HTTPS .js candidates: {len(planned)} (maximum {args.max_new})")
        for host in hosts:
            print(f"  {host}: {counts.get(host, 0)}")
        if not args.execute:
            print("PREVIEW ONLY. No network requests were sent; add --execute to validate.")
            return 0
        if not planned:
            print("No eligible, previously unattempted JS candidates. Nothing requested.")
            return 0
        output, _rows = execute_validation(
            paths, Config(paths), policy, args.run_id, planned,
        )
        print(f"Separate validation report: {output / 'summary.json'}")
        return 0
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
