#!/usr/bin/env python3
"""Run an explicitly bounded JavaScript *stage subset* in an isolated sandbox.

Default is an offline preview. --execute opts in to at most 12 pinned GETs,
using the production JS stage and the saved URL evidence, but a fresh database,
object store, and run directory. The original run, baseline, and alerts remain
untouched. No URL crawling, source maps, redirects, or downstream stages run.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "app", ROOT / "tools"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from core import (  # noqa: E402
    AppPaths, CommandRunner, Config, Database, Logger, PolicySet,
    Progress, ReconError, RunLock, TargetPolicy, atomic_write_text, json_dumps,
)
from execution import BudgetManager  # noqa: E402
from js_validation import (  # noqa: E402
    MAX_NEW, MAX_PER_HOST, _valid_run_id, select_fresh_js,
)
from stages import StageContext, stage_javascript  # noqa: E402


def prior_validation_hashes(paths: AppPaths, target: str, run_id: str) -> frozenset[str]:
    """Prevent retrying samples from earlier bounded validation executions."""
    if not _valid_run_id(run_id):
        raise ReconError("Invalid source run ID.")
    base = paths.output / target / "js-validations"
    found: set[str] = set()
    for file in base.glob(f"{run_id}-*/results.jsonl"):
        if not file.is_file():
            continue
        try:
            for line in file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                digest = row.get("url_sha256") if isinstance(row, dict) else None
                if isinstance(digest, str) and len(digest) == 64 and all(
                    ch in "0123456789abcdef" for ch in digest
                ):
                    found.add(digest)
        except (OSError, ValueError, TypeError) as exc:
            raise ReconError("Cannot inspect a previous JS validation report.") from exc
    return frozenset(found)


def prior_isolated_stage_hashes(
    paths: AppPaths, target: str, run_id: str,
) -> frozenset[str]:
    """Exclude all URLs selected by a prior isolated replay of this source run.

    The existing sandbox's JS input file records the original submitted URL
    set, including any URLs skipped after a safety stop. This is intentionally
    conservative: do not silently retry a prior replay on a new --execute.
    """
    if not _valid_run_id(run_id):
        raise ReconError("Invalid source run ID.")
    root = paths.output / target / "js-stage-replays"
    found: set[str] = set()
    for summary_path in root.glob(f"{run_id}-*/summary.json"):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if (not isinstance(summary, dict)
                    or summary.get("source_run_id") != run_id
                    or summary.get("target") != target
                    or not _valid_run_id(str(summary.get("sandbox_run_id") or ""))):
                raise ReconError("Malformed prior isolated JS stage summary.")
            replay_root = summary_path.parent.resolve()
            run_path = (
                replay_root / "output" / target / "runs"
                / str(summary["sandbox_run_id"]) / "current" / "javascript-urls.txt"
            ).resolve()
            if not run_path.is_relative_to(replay_root) or not run_path.is_file():
                raise ReconError("Prior isolated JS stage URL selection is missing.")
            for url in run_path.read_text(encoding="utf-8").splitlines():
                if url:
                    found.add(hashlib.sha256(url.encode("utf-8")).hexdigest())
        except (OSError, ValueError, TypeError) as exc:
            raise ReconError("Cannot inspect a prior isolated JS stage.") from exc
    return frozenset(found)


class SequentialRequestGate:
    """At most one request in flight; retain target-policy global pacing."""
    def __init__(self, rate: int) -> None:
        self.interval = 1.0 / max(1, rate)
        self.next_request = 0.0
        self.attempted = 0
        self.stop_status = 0

    def before_request(self, _url: str) -> None:
        if self.stop_status:
            raise ReconError("Validation halted after an access-denied or rate-limited response.")
        now = time.monotonic()
        if now < self.next_request:
            time.sleep(self.next_request - now)
        self.next_request = time.monotonic() + self.interval
        self.attempted += 1

    def after_response(self, status_code: int) -> None:
        if status_code in (403, 429):
            self.stop_status = status_code


def run_isolated_stage(
    source_paths: AppPaths,
    config: Config,
    original_policy: TargetPolicy,
    source_run_id: str,
    urls: list[str],
) -> tuple[Path, dict[str, Any]]:
    """Execute only stage_javascript against a newly initialized sandbox root."""
    if not config.authorized:
        raise ReconError("Explicit authorized-scope configuration is required.")
    if not urls or len(urls) > MAX_NEW or not _valid_run_id(source_run_id):
        raise ReconError("Isolated JS stage requires 1..12 validated, scoped URL candidates.")
    if any(not original_policy.url_in_scope(url) for url in urls):
        raise ReconError("The stage candidate set includes an out-of-scope URL.")

    # Clone policy for the sandbox; do not mutate the live target configuration.
    cloned_raw = json.loads(json.dumps(original_policy.raw))
    cloned_raw["javascript"] = {
        **dict(cloned_raw.get("javascript") or {}),
        "download_source_maps": False,
    }
    policy = TargetPolicy.from_dict(cloned_raw)
    policy.limits.js_workers = 1
    policy.limits.max_js_files = len(urls)
    policy.limits.max_http_requests = len(urls)
    policy.limits.timeout_seconds = 30
    policy.limits.max_runtime_minutes = 15
    gate = SequentialRequestGate(policy.limits.request_rate)

    logger = Logger(source_paths, verbose=False)
    with RunLock(source_paths.lock, logger):
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        sandbox_root = (
            source_paths.output / original_policy.name / "js-stage-replays"
            / f"{source_run_id}-{timestamp}-{os.getpid()}"
        )
        sandbox_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        paths = AppPaths.from_root(sandbox_root)
        paths.ensure()
        db = Database(paths.db)
        sandbox_logger = Logger(paths, verbose=False)
        try:
            new_run_id = db.create_run(original_policy.name, 1, "isolated_js_subset")
            run_dir = paths.output / original_policy.name / "runs" / new_run_id
            db.create_run_target(new_run_id, policy, run_dir, baseline=True)
            current = run_dir / "current"
            current.mkdir(parents=True, exist_ok=True)
            atomic_write_text(current / "urls.txt", "".join(url + "\n" for url in urls))
            atomic_write_text(
                current / "url-collection.json",
                json_dumps({
                    "run_id": new_run_id,
                    "target": policy.name,
                    "metrics": {
                        "collection_status": "partial",
                        "collection_reasons": ["isolated_subset_of_saved_urls"],
                        "source_run_id": source_run_id,
                        "selected_input_count": len(urls),
                        "url_selection": {"javascript_candidates": len(urls)},
                    },
                }) + "\n",
            )
            db.stage_begin(new_run_id, policy.name, "javascript", 1)
            ctx = StageContext(
                paths, config, policy, db, sandbox_logger,
                CommandRunner(sandbox_logger), Progress(False),
                new_run_id, run_dir, False,
                budget=BudgetManager.create(db, new_run_id, policy.name, policy),
                download_max_redirects=0,
                request_gate=gate.before_request,
                response_gate=gate.after_response,
            )
            try:
                metrics = stage_javascript(ctx)
            except Exception as exc:
                db.stage_finish(
                    new_run_id, policy.name, "javascript", "failed",
                    error=type(exc).__name__,
                )
                db.finish_run_target(new_run_id, policy.name, "failed")
                db.finish_run(new_run_id, "failed", type(exc).__name__)
                raise
            else:
                # The subset is never equivalent to full URL/JS coverage.
                metrics["collection_status"] = "partial"
                metrics["isolated_subset"] = True
                metrics["source_run_id"] = source_run_id
                metrics["network_requests_observed"] = gate.attempted
                metrics["stopped_after_http_status"] = gate.stop_status
                db.stage_finish(
                    new_run_id, policy.name, "javascript", "partial",
                    metrics=metrics,
                )
                db.finish_run_target(new_run_id, policy.name, "partial")
                db.finish_run(new_run_id, "partial")
                summary = {
                    "source_run_id": source_run_id,
                    "sandbox_run_id": new_run_id,
                    "target": original_policy.name,
                    "requested_js_urls": len(urls),
                    "network_requests_observed": gate.attempted,
                    "stopped_after_http_status": gate.stop_status,
                    "downloaded": int(metrics.get("downloaded") or 0),
                    "not_found": int(metrics.get("not_found") or 0),
                    "errors": int(metrics.get("errors") or 0),
                    "unexpected_content_types": int(
                        metrics.get("unexpected_content_types") or 0
                    ),
                    "indicators": int(metrics.get("indicators") or 0),
                    "collection_status": "partial",
                    "limitations": (
                        "Isolated 12-URL-or-smaller subset. No source maps, "
                        "baseline comparison, crawling, or downstream stages; "
                        "not a complete scan or source-run update."
                    ),
                }
                atomic_write_text(
                    sandbox_root / "summary.json",
                    json_dumps(summary, pretty=True) + "\n",
                )
                return sandbox_root, summary
        finally:
            db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, dest="run_id")
    parser.add_argument("--target", required=True)
    parser.add_argument("--hosts", nargs="+", required=True,
                        help="Explicitly authorized exact hosts, no wildcards")
    parser.add_argument("--max-new", type=int, default=MAX_NEW)
    parser.add_argument("--per-host", type=int, default=MAX_PER_HOST)
    parser.add_argument("--execute", action="store_true",
                        help="Opt in to a bounded isolated stage replay; offline preview is default")
    args = parser.parse_args(argv)
    try:
        if not _valid_run_id(args.run_id):
            raise ReconError("Invalid source run ID.")
        if not (1 <= args.max_new <= MAX_NEW and 1 <= args.per_host <= MAX_PER_HOST):
            raise ReconError("Isolated stage caps: --max-new 1..12; --per-host 1..3.")
        paths = AppPaths.from_root(ROOT)
        policies = PolicySet.load(paths)
        match = policies.select(args.target)
        if len(match) != 1 or match[0].name != args.target:
            raise ReconError("Specify exactly one configured target name.")
        policy = match[0]
        hosts = tuple(host.strip().lower() for host in args.hosts)
        validated = prior_validation_hashes(paths, policy.name, args.run_id)
        replayed = prior_isolated_stage_hashes(paths, policy.name, args.run_id)
        excluded = validated | replayed
        planned, counts = select_fresh_js(
            paths.output / policy.name / "runs" / args.run_id / "current",
            run_id=args.run_id, target=policy.name, policy=policy,
            allowed_hosts=hosts, max_new=args.max_new, per_host=args.per_host,
            excluded_url_sha256=excluded,
        )
        print(f"New, never-validated HTTPS .js subset: {len(planned)}")
        for host in hosts:
            print(f"  {host}: {counts.get(host, 0)}")
        print(f"Previously validated URL hashes excluded: {len(validated)}")
        print(f"Previously isolated-stage URL hashes excluded: {len(replayed)}")
        print(f"Unique previously selected URL hashes excluded: {len(excluded)}")
        if not args.execute:
            print("OFFLINE PREVIEW. No network or source-run changes; add --execute to opt in.")
            return 0
        if not planned:
            print("No eligible new JS candidates; no requests made.")
            return 0
        out, summary = run_isolated_stage(
            paths, Config(paths), policy, args.run_id, planned,
        )
        print(
            f"Isolated partial JS stage: "
            f"{summary['downloaded']} downloaded, "
            f"{summary['unexpected_content_types']} rejected content-types, "
            f"{summary['network_requests_observed']} network requests"
        )
        print(f"Sandbox-only result: {out / 'summary.json'}")
        return 0
    except ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
