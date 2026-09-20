from __future__ import annotations

import concurrent.futures
import contextlib
import json
import math
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from core import (
    AppPaths,
    CommandRunner,
    Config,
    Database,
    Logger,
    Progress,
    ReconError,
    StageError,
    TargetPolicy,
    atomic_write_bytes,
    atomic_write_text,
    classify_url,
    explain_risk,
    extract_js_indicators,
    json_dumps,
    normalize_host,
    normalize_url,
    normalize_url_preserving_semantics,
    query_host_records_fallback,
    read_jsonl,
    safe_filename,
    semantic_js_normalize,
    sha256_bytes,
    sha256_text,
    tool_path,
    utc_now,
    write_jsonl,
)
from intelligence import build_js_diff, classify_endpoint, technology_confidence
from execution import BudgetManager, WorkQueue, BudgetExceeded, DatabaseWriter
from storage import ContentAddressedStore
from safe_transport import fetch_pinned_tls_peer, perform_pinned_download, perform_pinned_request


@dataclass(slots=True)
class StageContext:
    paths: AppPaths
    config: Config
    policy: TargetPolicy
    db: Database
    logger: Logger
    runner: CommandRunner
    progress: Progress
    run_id: str
    run_dir: Path
    allow_active: bool
    budget: BudgetManager | None = None
    db_writer: DatabaseWriter | None = None

    def next_requested(self) -> bool:
        callback = getattr(self.runner, "next_check", None)
        return bool(callback()) if callable(callback) else False

    @property
    def current(self) -> Path:
        path = self.run_dir / "current"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def changes(self) -> Path:
        path = self.run_dir / "changes"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def events_path(self) -> Path:
        return self.changes / "events.jsonl"


def emit_event(ctx: StageContext, category: str, item: str, title: str, details: Mapping[str, Any] | None = None) -> None:
    details = dict(details or {})
    ignore_rule = ctx.db.ignore_match(ctx.policy.name, category, item) or ctx.db.ignore_match(ctx.policy.name, "any", item)
    if ignore_rule:
        ctx.logger.info("Event ignored by rule", target=ctx.policy.name, category=category, item=item, rule_id=ignore_rule)
        return
    score, severity, reasons, change_class = explain_risk(category, item, details)
    if not ctx.policy.analysis.get("semantic_change_classification", True):
        change_class = category
    if not ctx.policy.analysis.get("explainable_risk", True):
        reasons = []
    dedup_key = sha256_text(json_dumps([category, item, details.get("stable_key", "")]))[:32]
    confirmations = int(ctx.policy.analysis.get("stable_confirmations", 2) or 2)
    volatile = category in {"dns_change", "fingerprint_change"}
    track_confirmation = bool(ctx.policy.analysis.get("track_confirmation_state", True))
    occurrence, confirmation_state = ctx.db.observe_event(
        ctx.policy.name,
        dedup_key,
        category,
        item,
        change_class,
        ctx.run_id,
        details,
        confirmations=confirmations,
        immediately_confirmed=(not track_confirmation or not volatile or score >= 70),
    )
    event = {
        "ts": utc_now(),
        "run_id": ctx.run_id,
        "target": ctx.policy.name,
        "category": category,
        "change_class": change_class,
        "confirmation_state": confirmation_state,
        "observation_count": occurrence,
        "item": item,
        "title": title,
        "details": details,
        "risk_score": score,
        "risk_reasons": reasons,
        "severity": severity,
        "dedup_key": dedup_key,
    }
    incident_id = ctx.db.correlate_event(ctx.policy.name, dedup_key, category, item, title, severity, score, ctx.run_id, details)
    event["incident_id"] = incident_id
    with ctx.events_path.open("a", encoding="utf-8") as handle:
        handle.write(json_dumps(event) + "\n")


def _scope_hosts(policy: TargetPolicy, hosts: Iterable[str]) -> list[str]:
    return sorted({host for value in hosts if (host := normalize_host(value)) and policy.host_in_scope(host)})


def _policy_headers_for_url(policy: TargetPolicy, url: str) -> dict[str, str]:
    """Return policy headers only for encrypted, in-process target transport."""
    try:
        parsed = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return {}
    if parsed.scheme.lower() != "https":
        return {}
    return {str(key): str(value) for key, value in policy.headers.items()}


def _parse_subfinder_row(row: Mapping[str, Any]) -> tuple[str, set[str]]:
    host = normalize_host(str(row.get("host") or row.get("name") or row.get("value") or ""))
    sources: set[str] = set()
    raw_sources = row.get("sources")
    if isinstance(raw_sources, list):
        sources.update(str(x) for x in raw_sources)
    elif raw_sources:
        sources.add(str(raw_sources))
    if row.get("source"):
        sources.add(str(row["source"]))
    return host, sources or {"subfinder"}


def stage_subdomains(ctx: StageContext) -> dict[str, Any]:
    discoveries: dict[str, set[str]] = {}
    raw_dir = ctx.current / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for root_index, root in enumerate(ctx.policy.roots, 1):
        discoveries.setdefault(root, set()).add("root")
        if tool_path("subfinder"):
            out = raw_dir / f"subfinder-{safe_filename(root)}.jsonl"
            args = [
                "subfinder", "-d", root, "-silent", "-oJ", "-cs", "-duc",
                "-rl", str(ctx.policy.limits.request_rate),
                "-max-time", str(max(1, ctx.policy.limits.timeout_seconds // 60)),
            ]
            result = ctx.runner.run(
                args,
                timeout=ctx.policy.limits.timeout_seconds,
                output_path=out,
                heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "subdomains"),
                line_callback=lambda _line, count: ctx.progress.update(count, 0, f"subfinder root {root_index}/{len(ctx.policy.roots)}"),
            )
            if result.returncode not in {0, 1}:
                ctx.logger.warn("subfinder failed; continuing with other sources", target=ctx.policy.name, root=root, exit=result.returncode)
            for row in read_jsonl(out):
                host, sources = _parse_subfinder_row(row)
                if host and ctx.policy.host_in_scope(host):
                    discoveries.setdefault(host, set()).update(sources)

        if tool_path("assetfinder"):
            out = raw_dir / f"assetfinder-{safe_filename(root)}.txt"
            result = ctx.runner.run(
                ["assetfinder", "--subs-only", root],
                timeout=ctx.policy.limits.timeout_seconds,
                output_path=out,
                heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "subdomains"),
                line_callback=lambda _line, count: ctx.progress.update(count, 0, f"assetfinder root {root_index}/{len(ctx.policy.roots)}"),
            )
            if result.returncode not in {0, 1}:
                ctx.logger.warn("assetfinder failed; continuing", target=ctx.policy.name, root=root, exit=result.returncode)
            if out.exists():
                for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                    host = normalize_host(line)
                    if ctx.policy.host_in_scope(host):
                        discoveries.setdefault(host, set()).add("assetfinder")

    rows: list[dict[str, Any]] = []
    new_hosts: list[str] = []
    new_count = 0
    for index, host in enumerate(sorted(discoveries), 1):
        sources = sorted(discoveries[host])
        is_new = ctx.db.upsert_asset(ctx.policy.name, host, sources, ctx.run_id)
        if ctx.policy.analysis.get("asset_graph", True):
            for root in ctx.policy.roots:
                if host == root or host.endswith("." + root):
                    ctx.db.upsert_edge(ctx.policy.name, "root", root, "contains", "host", host, ctx.run_id, {"sources": sources})
                    break
        rows.append({"host": host, "sources": sources, "confidence": min(100, len(sources) * 25)})
        if is_new:
            if ctx.budget:
                ctx.budget.consume("new_assets", 1)
            new_count += 1
            new_hosts.append(host)
            emit_event(ctx, "new_subdomain", host, "New subdomain discovered", {"sources": sources})
        ctx.progress.update(index, len(discoveries), f"new={new_count}")

    write_jsonl(ctx.current / "subdomains.jsonl", rows)
    atomic_write_text(ctx.current / "subdomains.txt", "".join(f"{row['host']}\n" for row in rows))
    atomic_write_text(ctx.changes / "new-subdomains.txt", "".join(f"{host}\n" for host in new_hosts))
    return {"discovered": len(rows), "new": new_count, "sources": len({s for values in discoveries.values() for s in values})}


def _dns_values(row: Mapping[str, Any], rrtype: str) -> tuple[str, set[str]]:
    host = normalize_host(str(row.get("host") or row.get("input") or row.get("name") or ""))
    values: set[str] = set()
    keys = {
        "A": ["a", "A", "ip", "ips"],
        "AAAA": ["aaaa", "AAAA"],
        "CNAME": ["cname", "CNAME"],
        "NS": ["ns", "NS"],
    }.get(rrtype, [rrtype.lower(), rrtype])
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            values.update(str(x).strip().rstrip(".") for x in value if str(x).strip())
        elif isinstance(value, str) and value.strip():
            values.add(value.strip().rstrip("."))
    # Some versions expose answers as a list of objects/strings.
    answers = row.get("answers") or row.get("answer")
    if isinstance(answers, list):
        for answer in answers:
            if isinstance(answer, dict):
                value = answer.get("data") or answer.get("value") or answer.get("answer")
                answer_type = str(answer.get("type") or rrtype).upper()
                if value and answer_type == rrtype:
                    values.add(str(value).strip().rstrip("."))
            elif answer:
                values.add(str(answer).strip().rstrip("."))
    return host, values


def stage_dns(ctx: StageContext) -> dict[str, Any]:
    hosts_path = ctx.current / "subdomains.txt"
    hosts = _scope_hosts(ctx.policy, hosts_path.read_text(encoding="utf-8", errors="replace").splitlines() if hosts_path.exists() else ctx.policy.roots)
    if not hosts:
        hosts = list(ctx.policy.roots)
    if ctx.budget:
        ctx.budget.consume("dns_queries", max(1, len(hosts) * 4))
    input_path = ctx.current / "dns-input.txt"
    atomic_write_text(input_path, "".join(f"{host}\n" for host in hosts))

    previous_rows = ctx.db.all("SELECT host,rrtype,value FROM dns_records WHERE target=? AND is_current=1", (ctx.policy.name,))
    previous = {(str(row["host"]), str(row["rrtype"]), str(row["value"])) for row in previous_rows}
    current_records: set[tuple[str, str, str]] = set()
    successful_rrtypes: set[str] = set()
    resolved_hosts: set[str] = set()
    wildcard_candidates: set[str] = set()
    wildcard_classification_complete = False

    filtered_hosts = set(hosts)
    if tool_path("dnsx"):
        wildcard_classification_complete = True
        filtered_hosts = set()
        for root in ctx.policy.roots:
            root_hosts = [host for host in hosts if host == root or host.endswith("." + root)]
            if not root_hosts:
                continue
            root_input = ctx.current / f"dns-{safe_filename(root)}-input.txt"
            root_output = ctx.current / f"dns-{safe_filename(root)}-filtered.txt"
            atomic_write_text(root_input, "".join(f"{host}\n" for host in root_hosts))
            result = ctx.runner.run(
                [
                    "dnsx", "-l", str(root_input), "-wd", root, "-silent", "-duc",
                    "-t", str(min(200, ctx.policy.limits.dns_rate)),
                    "-rl", str(ctx.policy.limits.dns_rate),
                ],
                timeout=ctx.policy.limits.timeout_seconds,
                output_path=root_output,
                heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "dns"),
                line_callback=lambda _line, count: ctx.progress.update(count, len(hosts), "wildcard filtering"),
            )
            if result.returncode == 0 and root_output.exists():
                filtered_hosts.update(_scope_hosts(ctx.policy, root_output.read_text(encoding="utf-8", errors="replace").splitlines()))
            else:
                wildcard_classification_complete = False
                filtered_hosts.update(root_hosts)
        wildcard_candidates = set(hosts) - filtered_hosts
        filtered_hosts.update(ctx.policy.roots)
        # Keep the non-wildcard set as classification metadata for stability
        # logic, but query every discovered host. Wildcard DNS is a property,
        # not a reason to discard a potentially distinct virtual host.
        filtered_path = ctx.current / "dns-filtered-hosts.txt"
        atomic_write_text(filtered_path, "".join(f"{host}\n" for host in sorted(filtered_hosts)))
        query_input = ctx.current / "dns-query-hosts.txt"
        atomic_write_text(query_input, "".join(f"{host}\n" for host in sorted(hosts)))

        root_query_input = ctx.current / "dns-root-hosts.txt"
        atomic_write_text(root_query_input, "".join(f"{root}\n" for root in ctx.policy.roots))
        for rrtype, flag in (("A", "-a"), ("AAAA", "-aaaa"), ("CNAME", "-cname"), ("NS", "-ns")):
            out = ctx.current / f"dns-{rrtype.lower()}.jsonl"
            rr_input = root_query_input if rrtype == "NS" else query_input
            result = ctx.runner.run(
                [
                    "dnsx", "-l", str(rr_input), "-silent", "-json", "-omit-raw", flag, "-resp", "-duc",
                    "-t", str(min(200, ctx.policy.limits.dns_rate)),
                    "-rl", str(ctx.policy.limits.dns_rate),
                ],
                timeout=ctx.policy.limits.timeout_seconds,
                output_path=out,
                heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "dns"),
                line_callback=lambda _line, count, t=rrtype: ctx.progress.update(count, len(hosts), f"query {t}"),
            )
            if result.returncode != 0:
                ctx.logger.warn("dnsx query failed; previous records of this type will not be retired", target=ctx.policy.name, rrtype=rrtype, exit=result.returncode)
                continue
            successful_rrtypes.add(rrtype)
            for row in read_jsonl(out):
                host, values = _dns_values(row, rrtype)
                if not host or not ctx.policy.host_in_scope(host):
                    continue
                for value in values:
                    current_records.add((host, rrtype, value))
                    if rrtype in {"A", "AAAA", "CNAME"}:
                        resolved_hosts.add(host)
    else:
        ctx.logger.warn("dnsx missing; using system resolver fallback", target=ctx.policy.name)
        successful_rrtypes.update({"A", "AAAA"})
        for index, host in enumerate(hosts, 1):
            values = query_host_records_fallback(host)
            for rrtype, records in values.items():
                for value in records:
                    current_records.add((host, rrtype, value))
                    resolved_hosts.add(host)
            ctx.progress.update(index, len(hosts), "system DNS")

    comparable_previous = {record for record in previous if record[1] in successful_rrtypes}
    comparable_current = {record for record in current_records if record[1] in successful_rrtypes}
    new_records = comparable_current - comparable_previous
    removed_records = comparable_previous - comparable_current
    for host, rrtype, value in sorted(current_records):
        ctx.db.upsert_dns(ctx.policy.name, host, rrtype, value, ctx.run_id)
        ctx.db.mark_asset_resolved(ctx.policy.name, host, ctx.run_id, True)
        if ctx.policy.analysis.get("asset_graph", True):
            destination_type = "ip" if rrtype in {"A", "AAAA"} else "host"
            relation = {"A": "resolves_to", "AAAA": "resolves_to", "CNAME": "aliases_to", "NS": "uses_nameserver"}.get(rrtype, "dns_record")
            ctx.db.upsert_edge(ctx.policy.name, "host", host, relation, destination_type, value, ctx.run_id, {"rrtype": rrtype})
    for host in wildcard_candidates:
        ctx.db.execute("UPDATE assets SET wildcard=1,last_run_id=? WHERE target=? AND host=?", (ctx.run_id, ctx.policy.name, host))
    if wildcard_classification_complete:
        for host in sorted(set(hosts) - wildcard_candidates):
            ctx.db.execute("UPDATE assets SET wildcard=0,last_run_id=? WHERE target=? AND host=?", (ctx.run_id, ctx.policy.name, host))
    ctx.db.finalize_dns_current(ctx.policy.name, ctx.run_id, successful_rrtypes)

    for host, rrtype, value in sorted(new_records):
        emit_event(ctx, "dns_change", f"{host} {rrtype} {value}", "New DNS record", {"action": "added", "host": host, "rrtype": rrtype, "value": value})
    for host, rrtype, value in sorted(removed_records):
        emit_event(ctx, "dns_change", f"{host} {rrtype} {value}", "DNS record disappeared", {"action": "removed", "host": host, "rrtype": rrtype, "value": value})

    rows = [{"host": h, "type": t, "value": v} for h, t, v in sorted(current_records)]
    write_jsonl(ctx.current / "dns-records.jsonl", rows)
    atomic_write_text(ctx.current / "resolved-hosts.txt", "".join(f"{host}\n" for host in sorted(resolved_hosts)))
    atomic_write_text(ctx.current / "wildcard-candidates.txt", "".join(f"{host}\n" for host in sorted(wildcard_candidates)))
    atomic_write_text(
        ctx.changes / "dns-changes.tsv",
        "".join(f"added\t{h}\t{t}\t{v}\n" for h, t, v in sorted(new_records))
        + "".join(f"removed\t{h}\t{t}\t{v}\n" for h, t, v in sorted(removed_records)),
    )
    return {
        "hosts": len(hosts),
        "resolved": len(resolved_hosts),
        "records": len(current_records),
        "new_records": len(new_records),
        "removed_records": len(removed_records),
        "wildcard_candidates": len(wildcard_candidates),
        "wildcard_resolved": len(wildcard_candidates & resolved_hosts),
        "wildcard_classification_complete": wildcard_classification_complete,
        "successful_rrtypes": sorted(successful_rrtypes),
    }


def _katana_candidate_malformed(value: str) -> bool:
    """Reject structurally malformed crawler URLs without reducing recall.

    Only path/authority backslashes are rejected here. Query-string values are
    intentionally left untouched because an encoded backslash may be legitimate
    application data rather than a malformed URL path.
    """
    raw = str(value or "").strip()

    if not raw:
        return True

    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return True

    try:
        decoded_path = urllib.parse.unquote(parsed.path)
        decoded_netloc = urllib.parse.unquote(parsed.netloc)
    except Exception:
        return True

    return (
        "\\" in decoded_path
        or "\\" in decoded_netloc
    )


_URL_PRIORITY_TOKENS = {
    "admin", "api", "auth", "oauth", "login", "graphql", "export", "upload",
    "payment", "billing", "debug", "internal", "private", "account", "user",
}


def _url_candidate_priority(url: str, sources: set[str]) -> int:
    parsed = urllib.parse.urlsplit(url)
    path_query = f"{parsed.path}?{parsed.query}".lower()
    kind = classify_url(url)
    score = len(sources) * 4
    if "katana" in sources:
        score += 30
    if "wayback" in sources:
        score += 14
    if "base" in sources:
        score += 4
    if kind == "api":
        score += 32
    elif kind == "javascript":
        score += 14
    if parsed.query:
        score += 10
    if any(token in path_query for token in _URL_PRIORITY_TOKENS):
        score += 24
    score += min(8, len([part for part in parsed.path.split("/") if part]))
    return score


def _select_diverse_urls(candidates: Mapping[str, set[str]], limit: int) -> list[str]:
    """Deterministically preserve host diversity before spending the URL budget."""
    if limit <= 0:
        return []
    by_host: dict[str, list[str]] = {}
    for url in candidates:
        parsed = urllib.parse.urlsplit(url)
        host_key = parsed.hostname or parsed.netloc or url
        by_host.setdefault(host_key, []).append(url)
    for host, values in by_host.items():
        values.sort(key=lambda url: (-_url_candidate_priority(url, candidates[url]), url))
    host_order = sorted(
        by_host,
        key=lambda host: (-_url_candidate_priority(by_host[host][0], candidates[by_host[host][0]]), host),
    )
    selected: list[str] = []
    offsets = {host: 0 for host in host_order}
    while len(selected) < limit:
        progressed = False
        for host in host_order:
            offset = offsets[host]
            values = by_host[host]
            if offset >= len(values):
                continue
            selected.append(values[offset])
            offsets[host] = offset + 1
            progressed = True
            if len(selected) >= limit:
                break
        if not progressed:
            break
    return selected


def _katana_scope_regex(base_urls: Iterable[str]) -> str:
    """Restrict Katana pre-request traversal to exact safe-probed origins."""
    origins: list[str] = []
    for value in base_urls:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            continue
        origin = f"{parsed.scheme.lower()}://{parsed.netloc}"
        if origin not in origins:
            origins.append(origin)
    if not origins:
        return r"(?!)"
    return r"^(?:" + "|".join(re.escape(origin) for origin in sorted(origins)) + r")(?:[/?#]|$)"


def _katana_crawl_plan(
    base_urls: Iterable[str],
    *,
    remaining_requests: int | None,
    request_rate: int,
    timeout_seconds: int,
    http_threads: int,
    max_urls: int,
) -> dict[str, Any]:
    """Build a deterministic conservative request envelope for external Katana."""
    ordered = list(dict.fromkeys(str(url) for url in base_urls if str(url).strip()))
    if not ordered:
        return {
            "origins": [],
            "reservation": 0,
            "rate_limit": 0,
            "crawl_seconds": 0,
            "concurrency": 1,
            "scope_regex": r"(?!)",
        }

    rate = max(1, int(request_rate or 1))
    timeout = max(1, int(timeout_seconds or 1))
    max_candidates = max(1, int(max_urls or 1))
    remaining = None if remaining_requests is None else max(0, int(remaining_requests))
    if remaining == 0:
        return {
            "origins": [],
            "reservation": 0,
            "rate_limit": 0,
            "crawl_seconds": 0,
            "concurrency": 1,
            "scope_regex": r"(?!)",
        }

    # The previous 30-second envelope allocated ~1 second per origin for
    # larger targets. Reserve against the existing configured global request
    # rate, stage timeout, URL cap and remaining HTTP budget instead. These
    # are conservative estimates, not a per-request audit of external Katana.
    desired = min(max_candidates, rate * timeout)
    reservation = desired if remaining is None else min(remaining, desired)
    origin_count = min(len(ordered), max(1, reservation))
    origins = ordered[:origin_count]

    per_origin_budget = max(1, reservation // max(1, len(origins)))
    effective_rate = max(1, min(rate, per_origin_budget))
    crawl_seconds = max(1, per_origin_budget // effective_rate)
    crawl_seconds = min(crawl_seconds, 30, timeout)

    # The product is kept below the reserved envelope. Any remainder stays
    # conservatively reserved instead of being spent through an external tool.
    while (
        effective_rate * crawl_seconds * len(origins) > reservation
        and effective_rate > 1
    ):
        effective_rate -= 1
    while (
        effective_rate * crawl_seconds * len(origins) > reservation
        and crawl_seconds > 1
    ):
        crawl_seconds -= 1

    return {
        "origins": origins,
        "reservation": reservation,
        "rate_limit": effective_rate,
        "crawl_seconds": crawl_seconds,
        "concurrency": min(5, max(1, int(http_threads or 1))),
        # The request envelope must also constrain the *wall-clock* time of
        # an external tool, which otherwise can keep sending requests even
        # after its nominal per-origin crawl duration has passed.
        "wall_seconds": min(timeout, max(1, reservation // effective_rate)),
        "scope_regex": _katana_scope_regex(origins),
    }


def _origin_probe_one(ctx: StageContext, url: str) -> dict[str, Any]:
    if ctx.budget:
        ctx.budget.consume("http_requests", 1)

    def observation(method: str, observed_url: str, status: int, headers: Any, _body: bytes, error: str = "") -> dict[str, Any]:
        content_type = ""
        location = ""
        if headers:
            with contextlib.suppress(Exception):
                content_type = str(headers.get("Content-Type", ""))[:200]
                location = str(headers.get("Location", ""))[:1000]
        return {
            "url": observed_url,
            "method": method,
            "status_code": int(status or 0),
            "content_type": content_type,
            "location": location,
            "live": bool(status),
            "error": "" if status else str(error or ""),
        }

    result, transport_status = perform_pinned_request(
        {"method": "HEAD", "url": url, "headers": _policy_headers_for_url(ctx.policy, url)},
        ctx.policy,
        safe_methods={"HEAD"},
        url_safety=lambda candidate, policy: (
            bool(policy.url_in_scope(candidate)),
            "outside_scope" if not policy.url_in_scope(candidate) else "",
        ),
        observation=observation,
        max_response_bytes=0,
        validation_version="recon-origin-probe-1",
    )
    result["transport_status"] = transport_status
    result["live"] = bool(result.get("status_code"))

    # Some origins reject/drop HEAD while serving GET normally. Retry once with
    # a one-byte ranged GET only when the HEAD result was inconclusive or a
    # method-specific rejection. Safety stops (scope/non-public/429) never retry.
    head_status = int(result.get("status_code") or 0)
    if (
        head_status in {0, 405, 501}
        and transport_status != "stopped_for_safety"
    ):
        if ctx.budget:
            ctx.budget.consume("http_requests", 1)
        fallback_headers = {
            **_policy_headers_for_url(ctx.policy, url),
            "Range": "bytes=0-0",
        }
        get_result, get_transport_status = perform_pinned_request(
            {"method": "GET", "url": url, "headers": fallback_headers},
            ctx.policy,
            safe_methods={"GET"},
            url_safety=lambda candidate, policy: (
                bool(policy.url_in_scope(candidate)),
                "outside_scope" if not policy.url_in_scope(candidate) else "",
            ),
            observation=observation,
            max_response_bytes=1,
            validation_version="recon-origin-probe-1",
        )
        get_result["transport_status"] = get_transport_status
        get_result["live"] = bool(get_result.get("status_code"))
        get_result["head_fallback"] = True
        get_result["head_status_code"] = head_status
        if get_result.get("live") or head_status == 0:
            return get_result
        result["head_fallback"] = True
        result["head_fallback_status_code"] = int(
            get_result.get("status_code") or 0
        )

    return result


def _probe_live_origins(ctx: StageContext, urls: Iterable[str]) -> tuple[list[str], list[dict[str, Any]]]:
    ordered = list(dict.fromkeys(str(url) for url in urls if str(url).strip()))
    if not ordered:
        return [], []
    workers = min(20, max(1, ctx.policy.limits.http_workers // 2))
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, result in enumerate(pool.map(lambda url: _origin_probe_one(ctx, url), ordered), 1):
            results.append(result)
            ctx.progress.update(index, len(ordered), f"origin-probe live={sum(1 for row in results if row.get('live'))}")
    live = [
        str(row["url"])
        for row in results
        if row.get("live")
        # A 429 or another transport safety stop must never be handed to
        # Katana just because the origin responded with an HTTP status.
        and row.get("transport_status") == "ok"
        and not row.get("redirect_outside_scope")
        and ctx.policy.url_in_scope(str(row.get("url") or ""))
    ]
    return list(dict.fromkeys(live)), results


def stage_urls(ctx: StageContext) -> dict[str, Any]:
    hosts_file = ctx.current / "resolved-hosts.txt"
    hosts = _scope_hosts(ctx.policy, hosts_file.read_text(encoding="utf-8", errors="replace").splitlines() if hosts_file.exists() else ctx.policy.roots)
    if not hosts:
        hosts = list(ctx.policy.roots)

    candidate_base_urls = {f"https://{host}" for host in hosts} | {f"http://{host}" for host in hosts}
    port_origins_path = ctx.current / "port-web-origins.txt"
    if port_origins_path.exists():
        for value in port_origins_path.read_text(encoding="utf-8", errors="replace").splitlines():
            normalized = normalize_url_preserving_semantics(value)
            if normalized and ctx.policy.url_in_scope(normalized):
                candidate_base_urls.add(normalized.rstrip("/"))
    candidate_base_urls = set(sorted(candidate_base_urls))
    candidate_base_path = ctx.current / "candidate-base-urls.txt"
    atomic_write_text(candidate_base_path, "".join(f"{url}\n" for url in sorted(candidate_base_urls)))

    origin_probe_enabled = bool(ctx.policy.raw.get("urls", {}).get("origin_probe", True))
    if origin_probe_enabled:
        base_urls, origin_results = _probe_live_origins(ctx, sorted(candidate_base_urls))
    else:
        base_urls = sorted(candidate_base_urls)
        origin_results = [{"url": url, "live": True, "transport_status": "probe_disabled"} for url in base_urls]
    base_path = ctx.current / "base-urls.txt"
    atomic_write_text(base_path, "".join(f"{url}\n" for url in base_urls))
    write_jsonl(ctx.current / "origin-probe.jsonl", origin_results)

    wildcard_hosts_path = ctx.current / "wildcard-candidates.txt"
    wildcard_hosts = set(
        _scope_hosts(ctx.policy, wildcard_hosts_path.read_text(encoding="utf-8", errors="replace").splitlines())
        if wildcard_hosts_path.exists()
        else []
    )
    wildcard_live = sum(
        1 for url in base_urls if (urllib.parse.urlsplit(url).hostname or "") in wildcard_hosts
    )
    origin_redirects_outside_scope = sum(
        1 for row in origin_results if row.get("redirect_outside_scope")
    )

    # Recon evidence keeps a security-preserving URL form while the database
    # continues to receive a canonical comparison key.
    candidates: dict[str, set[str]] = {}
    canonical_urls: dict[str, str] = {}
    katana_rejected_malformed = 0

    def add_candidate(value: str, source: str) -> None:
        raw_url = normalize_url_preserving_semantics(value)
        if not raw_url or not ctx.policy.url_in_scope(raw_url):
            return
        candidates.setdefault(raw_url, set()).add(source)
        canonical_urls[raw_url] = normalize_url(raw_url) or raw_url

    for url in base_urls:
        add_candidate(url + "/" if not url.endswith("/") else url, "base")

    if tool_path("waybackurls"):
        out = ctx.current / "wayback-urls.txt"
        result = ctx.runner.run(
            ["waybackurls"],
            timeout=ctx.policy.limits.timeout_seconds,
            output_path=out,
            input_text="".join(f"{host}\n" for host in hosts),
            heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "urls"),
            line_callback=lambda _line, count: ctx.progress.update(count, 0, "waybackurls"),
        )
        if result.returncode not in {0, 1}:
            ctx.logger.warn("waybackurls failed", target=ctx.policy.name, exit=result.returncode)
        if out.exists():
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                add_candidate(line, "wayback")

    katana_observed = 0
    katana_reserved_requests = 0
    katana_request_envelope = 0
    katana_crawl_origins = 0
    katana_rate_limit = 0
    katana_crawl_seconds = 0
    katana_status = (
        "tool_missing" if not tool_path("katana") else
        "no_live_origins" if not base_urls and candidate_base_urls else
        "no_input" if not base_urls else "not_run"
    )
    katana_stop_reason = katana_status
    katana_exit_code: int | None = None
    katana_timed_out = False
    katana_duration_seconds = 0.0
    katana_batches_attempted = 0
    katana_batches_completed = 0
    katana_origins_attempted = 0
    katana_origin_successes: list[str] = []
    # An unsuccessful live-origin probe is incomplete collection, not proof of
    # an empty attack surface. Preserve the candidate origins for re-check.
    katana_pending_origins = list(base_urls) if base_urls else sorted(candidate_base_urls)
    katana_batches_incomplete = 0
    # On --resume, continue only unfinished origins. Never truncate evidence
    # from an earlier partial collection in the same run.
    previous_metrics: dict[str, Any] = {}
    previous_outcomes: list[dict[str, Any]] = []
    previous_crawl_lines = ""
    previous_completed: list[str] = []
    prior_summary = ctx.current / "url-collection.json"
    prior_pending = ctx.current / "katana-pending-origins.txt"
    if prior_summary.is_file() and prior_pending.is_file():
        try:
            prior_data = json.loads(prior_summary.read_text(encoding="utf-8"))
            old_metrics = prior_data.get("metrics", {})
            if prior_data.get("run_id") == ctx.run_id and old_metrics.get("collection_status") == "partial":
                previous_metrics = old_metrics
                old_outcomes = read_jsonl(ctx.current / "katana-batches.jsonl")
                previous_outcomes = [x for x in old_outcomes if isinstance(x, dict)]
                old_urls = ctx.current / "katana-urls.txt"
                if old_urls.exists():
                    previous_crawl_lines = old_urls.read_text(encoding="utf-8", errors="replace")
                completed_file = ctx.current / "katana-completed-origins.txt"
                if completed_file.exists():
                    previous_completed = completed_file.read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError, TypeError, KeyError):
            previous_metrics = {}
            previous_outcomes = []
            previous_crawl_lines = ""
            previous_completed = []
    katana_origin_successes = [origin for origin in previous_completed if origin in base_urls]
    katana_global_deadline_seconds = 0
    katana_deadline_exhausted = False
    katana_budget_exhausted = False
    katana_budget_metric = ""
    batch_outcomes: list[dict[str, Any]] = list(previous_outcomes)
    # Keep the prior partial run's raw evidence while rechecking its backlog.
    atomic_write_text(ctx.current / "katana-urls.txt", previous_crawl_lines)
    atomic_write_text(ctx.current / "katana-base-urls.txt", "")
    write_jsonl(ctx.current / "katana-batches.jsonl", batch_outcomes)
    operator_next = ctx.next_requested()
    if tool_path("katana") and base_urls and not operator_next:
        remaining_requests: int | None = None
        if ctx.budget and hasattr(ctx.budget, "snapshot"):
            budget_row = ctx.budget.snapshot().get("http_requests", {})
            limit_value = int(budget_row.get("limit") or 0)
            used_value = int(budget_row.get("used") or 0)
            if limit_value:
                remaining_requests = max(0, limit_value - used_value)

        plan = _katana_crawl_plan(
            base_urls,
            remaining_requests=remaining_requests,
            request_rate=ctx.policy.limits.request_rate,
            timeout_seconds=ctx.policy.limits.timeout_seconds,
            http_threads=ctx.policy.limits.http_threads,
            max_urls=ctx.policy.limits.max_urls,
        )
        # A target with both cumulative ceilings explicitly disabled may crawl
        # its known origins until Katana exits naturally. Keep the configured
        # per-second rate and exact-origin scope; external requests are not
        # counted individually by Recon Monitor in this mode.
        uncapped_katana = (
            ctx.policy.limits.max_http_requests == 0
            and ctx.policy.limits.max_runtime_minutes == 0
        )
        if uncapped_katana:
            plan.update({
                "origins": list(dict.fromkeys(base_urls)),
                "reservation": 0,
                "rate_limit": ctx.policy.limits.request_rate,
                "crawl_seconds": 0,
                "wall_seconds": 0,
            })
        already_completed = set(katana_origin_successes)
        katana_origins = [
            origin for origin in plan["origins"] if origin not in already_completed
        ]
        katana_request_envelope = int(plan["reservation"] or 0)
        katana_crawl_origins = len(katana_origins)
        katana_rate_limit = int(plan["rate_limit"] or 0)
        katana_crawl_seconds = int(plan["crawl_seconds"] or 0)
        katana_global_deadline_seconds = int(plan.get("wall_seconds") or 0)
        katana_pending_origins = [
            origin for origin in base_urls if origin not in already_completed
        ]

        if katana_origins:
            katana_base_path = ctx.current / "katana-base-urls.txt"
            atomic_write_text(
                katana_base_path,
                "".join(f"{url}\n" for url in katana_origins),
            )
            # Sequential invocations preserve the configured global rate.
            # A failed batch is kept pending, but does not prevent *later*
            # batches from being attempted while the shared budget permits.
            # Successful here means the tool exited normally, NOT that every
            # reachable page on its origins was discovered.
            out = ctx.current / "katana-urls.txt"
            atomic_write_text(out, previous_crawl_lines)
            crawl_started = time.monotonic()
            requests_per_origin, extra_requests = divmod(
                katana_request_envelope, len(katana_origins),
            )
            for batch_offset in range(0, len(katana_origins), 5):
                if ctx.next_requested():
                    operator_next = True
                    break
                if not uncapped_katana:
                    remaining_seconds = (
                        katana_global_deadline_seconds -
                        (time.monotonic() - crawl_started)
                    )
                    if remaining_seconds <= 0:
                        katana_deadline_exhausted = True
                        break

                batch_origins = katana_origins[batch_offset:batch_offset + 5]
                if uncapped_katana:
                    batch_timeout = None
                    batch_reservation = 0
                    batch_crawl_seconds = 0
                else:
                    # The finite mode retains its existing conservative
                    # envelope. An unfinished origin must remain pending.
                    batch_allowance = requests_per_origin * len(batch_origins) + min(
                        len(batch_origins), max(0, extra_requests - batch_offset),
                    )
                    batch_timeout = min(120.0, remaining_seconds, batch_allowance / katana_rate_limit)
                    batch_reservation = min(batch_allowance, math.ceil(batch_timeout * katana_rate_limit))
                    batch_crawl_seconds = min(
                        katana_crawl_seconds, max(1, int(batch_timeout / len(batch_origins))),
                    )
                    if ctx.budget:
                        try:
                            ctx.budget.consume("http_requests", batch_reservation)
                        except BudgetExceeded as exc:
                            katana_budget_exhausted = True
                            katana_budget_metric = exc.metric
                            break
                katana_reserved_requests += batch_reservation
                batch_number = len(previous_outcomes) + (batch_offset // 5) + 1
                batch_input = ctx.current / f"katana-batch-{batch_number:03d}-base-urls.txt"
                batch_output = ctx.current / f"katana-batch-{batch_number:03d}-urls.txt"
                atomic_write_text(
                    batch_input,
                    "".join(f"{url}\n" for url in batch_origins),
                )
                args = [
                    "katana",
                    "-list", str(batch_input),
                    "-silent", "-duc", "-jc",
                    "-d", str(ctx.policy.limits.crawl_depth),
                    "-cs", _katana_scope_regex(batch_origins),
                    "-rl", str(katana_rate_limit),
                    "-mrs", str(ctx.policy.limits.max_js_bytes),
                    "-retry", "0",
                    "-c", str(plan["concurrency"]),
                    "-p", "1",
                    "-timeout", str(
                        min(30, max(5, ctx.policy.limits.timeout_seconds // 10))
                    ),
                ]
                # In the explicitly uncapped mode, do not impose an internal
                # crawl-duration limit or an outer process wall clock. A manual
                # interruption remains possible; an interactive Next action
                # is a separate feature and is not implied by this mode.
                if not uncapped_katana:
                    args.extend(["-ct", f"{batch_crawl_seconds}s"])
                # Policy credentials never cross into an external crawler.
                batch_started_at = utc_now()
                result = ctx.runner.run(
                    args,
                    timeout=batch_timeout,
                    output_path=batch_output,
                    heartbeat=lambda: ctx.db.stage_heartbeat(
                        ctx.run_id, ctx.policy.name, "urls",
                    ),
                    line_callback=lambda _line, count: ctx.progress.update(
                        katana_observed + count, 0,
                        f"katana batch {batch_number} crawling",
                    ),
                )
                katana_batches_attempted += 1
                katana_origins_attempted += len(batch_origins)
                katana_observed += int(getattr(result, "lines", 0) or 0)
                batch_exit = int(result.returncode)
                batch_timed_out = bool(getattr(result, "timed_out", False))
                if katana_exit_code in {None, 0} or batch_timed_out:
                    katana_exit_code = batch_exit
                katana_timed_out = katana_timed_out or batch_timed_out
                operator_next = operator_next or bool(getattr(result, "operator_next", False)) or ctx.next_requested()
                katana_duration_seconds += float(getattr(result, "duration", 0.0) or 0.0)
                batch_complete = batch_exit == 0 and not batch_timed_out and not bool(getattr(result, "operator_next", False))
                batch_outcomes.append({
                    "batch": batch_number,
                    "origins": len(batch_origins),
                    "origin_urls": batch_origins,
                    "started_at": batch_started_at,
                    "finished_at": utc_now(),
                    "timeout_seconds": round(batch_timeout, 6) if batch_timeout is not None else None,
                    "crawl_seconds_per_origin": batch_crawl_seconds,
                    "reserved_requests": batch_reservation,
                    "rate_limit": katana_rate_limit,
                    "exit_code": batch_exit,
                    "timed_out": batch_timed_out,
                    "duration_seconds": round(float(getattr(result, "duration", 0.0) or 0.0), 3),
                    "lines": int(getattr(result, "lines", 0) or 0),
                    "status": "completed" if batch_complete else (
                        "operator_next" if bool(getattr(result, "operator_next", False)) else
                        "timeout" if batch_timed_out else "nonzero_exit"
                    ),
                    "stop_reason": (
                        "operator_next" if bool(getattr(result, "operator_next", False)) else
                        "timeout" if batch_timed_out else
                        "nonzero_exit" if batch_exit else "completed"
                    ),
                })
                if not batch_complete:
                    katana_batches_incomplete += 1
                    if katana_exit_code is None:
                        katana_exit_code = batch_exit
                    ctx.logger.warn(
                        "katana batch incomplete",
                        target=ctx.policy.name,
                        batch=batch_number,
                        exit=batch_exit,
                        timed_out=batch_timed_out,
                    )
                else:
                    katana_batches_completed += 1
                    katana_origin_successes.extend(batch_origins)

                # Retain evidence even for a failed batch; do not interpret a
                # line of output as proof that its origin was fully crawled.
                if batch_output.exists():
                    with out.open("a", encoding="utf-8") as combined:
                        for line in batch_output.read_text(
                            encoding="utf-8", errors="replace",
                        ).splitlines():
                            combined.write(line + "\n")
                write_jsonl(ctx.current / "katana-batches.jsonl", batch_outcomes)
                successful = set(katana_origin_successes)
                atomic_write_text(
                    ctx.current / "katana-pending-origins.txt",
                    "".join(f"{url}\n" for url in base_urls if url not in successful),
                )
                atomic_write_text(
                    ctx.current / "katana-completed-origins.txt",
                    "".join(f"{url}\n" for url in katana_origin_successes),
                )
                if operator_next:
                    break

            successful = set(katana_origin_successes)
            katana_pending_origins = [
                origin for origin in katana_pending_origins if origin not in successful
            ]
            katana_status = (
                "operator_next" if operator_next else
                "timeout" if katana_timed_out else
                "nonzero_exit" if katana_batches_incomplete else
                "budget_exhausted" if katana_budget_exhausted else
                "partial" if katana_pending_origins or katana_deadline_exhausted else
                "completed"
            )
            katana_stop_reason = (
                "operator_next" if operator_next else
                "batch_timeout" if katana_timed_out else
                "nonzero_exit" if katana_batches_incomplete else
                "global_deadline" if katana_deadline_exhausted else
                "runtime_budget" if katana_budget_metric == "runtime_seconds" else
                "request_budget" if katana_pending_origins else
                "completed"
            )
            # Machine-readable per-batch evidence and explicit backlog remain
            # accessible even after this run's other stages complete.
            write_jsonl(ctx.current / "katana-batches.jsonl", batch_outcomes)
            if out.exists():
                for line in out.read_text(
                    encoding="utf-8", errors="replace",
                ).splitlines():
                    raw_candidate = line.strip()
                    if _katana_candidate_malformed(raw_candidate):
                        katana_rejected_malformed += 1
                        continue
                    add_candidate(raw_candidate, "katana")
        else:
            # A resumed stage can legitimately have no work left for Katana.
            katana_status = "completed" if not katana_pending_origins else "budget_exhausted"
            katana_stop_reason = "completed" if not katana_pending_origins else "request_budget"
            atomic_write_text(ctx.current / "katana-base-urls.txt", "")
    elif operator_next:
        katana_status = "operator_next"
        katana_stop_reason = "operator_next"

    # Do not silently discard origins that were not attempted, or those
    # belonging to an incomplete batch. They require a later authorized pass.
    atomic_write_text(
        ctx.current / "katana-pending-origins.txt",
        "".join(f"{url}\n" for url in katana_pending_origins),
    )
    atomic_write_text(
        ctx.current / "katana-completed-origins.txt",
        "".join(f"{url}\n" for url in katana_origin_successes),
    )

    urls = _select_diverse_urls(candidates, ctx.policy.limits.max_urls)
    new_count = 0
    classified_count = 0
    rows: list[dict[str, Any]] = []
    new_urls: list[str] = []
    for index, raw_url in enumerate(urls, 1):
        canonical_url = canonical_urls[raw_url]
        kind = classify_url(raw_url)
        source_list = sorted(candidates[raw_url])
        source = ",".join(source_list)
        is_new = ctx.db.upsert_url(ctx.policy.name, canonical_url, kind, source, ctx.run_id)
        endpoint_classification = classify_endpoint(raw_url, kind="url")
        if kind == "api" or endpoint_classification.get("primary_category") != "general":
            if ctx.db.upsert_endpoint_intelligence(ctx.policy.name, raw_url, "url", endpoint_classification, source, ctx.run_id):
                classified_count += 1
        if ctx.policy.analysis.get("asset_graph", True):
            host = urllib.parse.urlsplit(raw_url).hostname or ""
            ctx.db.upsert_edge(
                ctx.policy.name, "host", host, "serves", "url", raw_url, ctx.run_id,
                {"kind": kind, "sources": source_list, "canonical_url": canonical_url},
            )
        rows.append({
            "url": raw_url,
            "raw_url": raw_url,
            "canonical_url": canonical_url,
            "kind": kind,
            "sources": source_list,
            "selection_priority": _url_candidate_priority(raw_url, candidates[raw_url]),
        })
        if is_new:
            new_count += 1
            new_urls.append(raw_url)
            event_details: dict[str, Any] = {
                "kind": kind,
                "sources": source_list,
                "raw_url": raw_url,
                "canonical_url": canonical_url,
            }
            if kind == "api" or endpoint_classification.get("primary_category") != "general":
                event_details["endpoint_classification"] = endpoint_classification
            emit_event(ctx, "new_url", raw_url, "New URL discovered", event_details)
        ctx.progress.update(index, len(urls), f"new={new_count}")
    write_jsonl(ctx.current / "urls.jsonl", rows)
    atomic_write_text(ctx.current / "urls.txt", "".join(f"{url}\n" for url in urls))
    atomic_write_text(ctx.changes / "new-urls.txt", "".join(f"{url}\n" for url in new_urls))
    selected_hosts = {(urllib.parse.urlsplit(url).hostname or "") for url in urls}
    js_candidates = {url for url in candidates if classify_url(url) == "javascript"}
    js_selected = js_candidates.intersection(urls)
    selection = {
        "classification_method": "url_path_extension",
        "candidate_urls": len(candidates),
        "selected_urls": len(urls),
        "javascript_candidates": len(js_candidates),
        "javascript_selected": len(js_selected),
        "javascript_dropped": len(js_candidates - js_selected),
        "javascript_sources": {
            source: sum(source in candidates[url] for url in js_candidates)
            for source in ("base", "wayback", "katana")
        },
    }
    write_jsonl(ctx.current / "javascript-selection.jsonl", (
        {"url": url, "sources": sorted(candidates[url]), "selected": url in js_selected,
         "reason": "selected" if url in js_selected else "max_urls"}
        for url in sorted(js_candidates)
    ))
    metrics = {
        "hosts": len(hosts),
        "candidate_origins": len(candidate_base_urls),
        "live_origins": len(base_urls),
        "wildcard_live_origins": wildcard_live,
        "origin_redirects_outside_scope": origin_redirects_outside_scope,
        "urls": len(urls),
        "selected_hosts": len(selected_hosts),
        "canonical_urls": len({canonical_urls[url] for url in urls}),
        "raw_variants": len(urls),
        "new": new_count,
        "classified_endpoints": classified_count,
        "truncated": len(candidates) > len(urls),
        "url_selection": selection,
        "katana_rejected_malformed": katana_rejected_malformed,
        "katana_observed": katana_observed,
        "katana_reserved_requests": katana_reserved_requests,
        "katana_request_envelope": katana_request_envelope,
        "katana_request_accounting": (
            "rate_only_external_requests_unmetered"
            if ctx.policy.limits.max_http_requests == 0
            and ctx.policy.limits.max_runtime_minutes == 0
            else "rate_duration_reservation"
        ),
        "katana_crawl_origins": katana_crawl_origins,
        "katana_rate_limit": katana_rate_limit,
        "katana_crawl_seconds_per_origin": katana_crawl_seconds,
        "katana_status": katana_status,
        "katana_stop_reason": katana_stop_reason,
        "katana_input_origins": len(base_urls),
        "katana_batch_outcomes": batch_outcomes,
        "katana_exit_code": katana_exit_code,
        "katana_timed_out": katana_timed_out,
        "katana_duration_seconds": round(katana_duration_seconds, 3),
        "katana_batches_attempted": len(batch_outcomes),
        "katana_batches_this_attempt": katana_batches_attempted,
        "katana_batches_completed": sum(
            row.get("status") == "completed" for row in batch_outcomes
        ),
        "katana_origins_attempted": katana_origins_attempted,
        "katana_origins_completed": len(katana_origin_successes),
        "katana_pending_origins": len(katana_pending_origins),
        "katana_batches_incomplete": sum(
            row.get("status") != "completed" for row in batch_outcomes
        ),
        "katana_global_deadline_seconds": katana_global_deadline_seconds,
        "katana_deadline_exhausted": katana_deadline_exhausted,
        "katana_budget_metric": katana_budget_metric,
        "collection_status": "partial" if katana_status in {"operator_next", "timeout", "nonzero_exit", "budget_exhausted", "partial", "tool_missing", "no_live_origins"} else "completed",
    }
    atomic_write_text(ctx.current / "url-collection.json", json_dumps({
        "run_id": ctx.run_id, "target": ctx.policy.name, "metrics": metrics,
    }) + "\n")
    return metrics


def _download_url(ctx: StageContext, url: str, max_bytes: int) -> dict[str, Any]:
    """Download one in-scope resource through the pinned transport boundary."""
    headers = {
        "User-Agent": ctx.config.get(
            "USER_AGENT",
            "ReconMonitor/3.0 authorized security monitoring",
        ),
        **_policy_headers_for_url(ctx.policy, url),
    }
    started = time.monotonic()

    def before_request(_candidate: str) -> None:
        if ctx.budget:
            ctx.budget.consume("http_requests", 1)

    result = perform_pinned_download(
        url,
        ctx.policy,
        headers=headers,
        max_response_bytes=max_bytes,
        timeout=min(45, max(5, ctx.policy.limits.timeout_seconds)),
        max_redirects=3,
        user_agent=headers["User-Agent"],
        before_request=before_request,
    )
    duration = time.monotonic() - started
    status_code = int(result.get("status_code") or 0)
    response_headers = (
        result.get("headers")
        if isinstance(result.get("headers"), Mapping)
        else {}
    )
    error = str(result.get("error") or "")

    if error == "response_budget_exceeded":
        raise StageError(f"Content exceeded limit: {url}", retryable=False)

    if status_code in {404, 410}:
        return {
            "url": url,
            "final_url": str(result.get("final_url") or url),
            "status_code": status_code,
            "not_found": True,
            "duration": duration,
            "transport_status": str(result.get("transport_status") or ""),
            "transport_hops": list(result.get("transport_hops") or []),
            "dns_rebinding_protection": str(
                result.get("dns_rebinding_protection") or ""
            ),
        }

    data = result.get("data")
    if not error and isinstance(data, (bytes, bytearray)) and status_code:
        payload = bytes(data)
        if ctx.budget:
            ctx.budget.consume("download_bytes", len(payload))
        content_type = str(
            response_headers.get("Content-Type")
            or response_headers.get("content-type")
            or ""
        )
        return {
            "url": url,
            "final_url": str(result.get("final_url") or url),
            "status_code": status_code,
            "data": payload,
            "content_type": content_type,
            "etag": str(
                response_headers.get("ETag")
                or response_headers.get("etag")
                or ""
            ),
            "last_modified": str(
                response_headers.get("Last-Modified")
                or response_headers.get("last-modified")
                or ""
            ),
            "duration": duration,
            "transport_status": str(result.get("transport_status") or ""),
            "transport_hops": list(result.get("transport_hops") or []),
            "resolved_addresses": list(result.get("resolved_addresses") or []),
            "pinned_address": str(result.get("pinned_address") or ""),
            "dns_rebinding_protection": str(
                result.get("dns_rebinding_protection") or ""
            ),
            "environment_proxy_used": bool(
                result.get("environment_proxy_used", False)
            ),
            "safe_transport_version": str(
                result.get("safe_transport_version") or ""
            ),
        }

    return {
        "url": url,
        "final_url": str(result.get("final_url") or url),
        "status_code": status_code,
        "error": error or "download_failed",
        "duration": duration,
        "transport_status": str(result.get("transport_status") or ""),
        "transport_hops": list(result.get("transport_hops") or []),
        "resolved_addresses": list(result.get("resolved_addresses") or []),
        "pinned_address": str(result.get("pinned_address") or ""),
        "dns_rebinding_protection": str(
            result.get("dns_rebinding_protection") or ""
        ),
        "redirect_outside_scope": bool(
            result.get("redirect_outside_scope", False)
        ),
        "environment_proxy_used": bool(
            result.get("environment_proxy_used", False)
        ),
        "safe_transport_version": str(
            result.get("safe_transport_version") or ""
        ),
    }

def _find_source_map_url(js_url: str, text: str) -> str:
    matches = re.findall(r"(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)\s*$", text)
    if not matches:
        return ""
    candidate = urllib.parse.urljoin(js_url, matches[-1].strip().strip("\"'"))
    return normalize_url_preserving_semantics(candidate) or ""


def _resolve_source_map_source(source_map_url: str, source_root: str, source_name: str) -> str:
    """Resolve HTTP(S) source-map entries without treating virtual schemes as network URLs."""
    name = str(source_name or "").strip()
    if not name:
        return ""
    parsed_name = urllib.parse.urlsplit(name)
    if parsed_name.scheme and parsed_name.scheme.lower() not in {"http", "https"}:
        return ""

    root = str(source_root or "").strip()
    base_url = source_map_url
    if root:
        parsed_root = urllib.parse.urlsplit(root)
        if parsed_root.scheme and parsed_root.scheme.lower() not in {"http", "https"}:
            return ""
        if not root.endswith("/"):
            root += "/"
        base_url = urllib.parse.urljoin(source_map_url, root)

    candidate = urllib.parse.urljoin(base_url, name)
    return normalize_url_preserving_semantics(candidate) or ""


def _source_map_entries(source_map_url: str, source_map: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return bounded source metadata, including hashes for embedded sourcesContent."""
    sources = source_map.get("sources")
    if not isinstance(sources, list):
        return []
    raw_contents = source_map.get("sourcesContent")
    contents = raw_contents if isinstance(raw_contents, list) else []
    source_root = str(source_map.get("sourceRoot") or "")[:1000]
    entries: list[dict[str, Any]] = []
    for index, raw_name in enumerate(sources[:5000]):
        source_name = str(raw_name or "").strip().replace("\r", " ").replace("\n", " ").replace("\t", " ")[:1000]
        if not source_name:
            continue
        embedded_content = ""
        if index < len(contents) and isinstance(contents[index], str):
            embedded_content = str(contents[index])
        content_bytes = embedded_content.encode("utf-8") if embedded_content else b""
        entries.append(
            {
                "source_index": index,
                "source_name": source_name,
                "source_root": source_root,
                "source_identity": f"{source_map_url}#{index}:{source_name}",
                "resolved_source_url": _resolve_source_map_source(source_map_url, source_root, source_name),
                "embedded": bool(embedded_content),
                "content_size": len(content_bytes),
                "content_hash": sha256_bytes(content_bytes) if content_bytes else "",
                "semantic_hash": sha256_text(semantic_js_normalize(embedded_content)) if embedded_content else "",
                "embedded_content": embedded_content,
            }
        )
    return entries


def _extract_js_chunk_references(js_url: str, text: str) -> list[str]:
    """Extract quoted JavaScript chunk/module references without fetching them."""
    matches = re.findall(
        r"""["']([^"'\\\r\n]{1,1000}\.(?:m?js)(?:[?#][^"'\\\r\n]*)?)["']""",
        text,
        flags=re.IGNORECASE,
    )
    chunks: set[str] = set()
    for raw in matches[:10000]:
        value = str(raw or "").strip()
        if not value or value.lower().startswith(("data:", "blob:", "javascript:")):
            continue
        candidate = urllib.parse.urljoin(js_url, value)
        normalized = normalize_url_preserving_semantics(candidate)
        if normalized and normalized != normalize_url_preserving_semantics(js_url):
            chunks.add(normalized)
    return sorted(chunks)[:2000]


DERIVED_RECON_STATE_LIMIT = 20000
def _prepare_javascript_derived_differentials(
    ctx: StageContext,
    source_map_rows: Iterable[Mapping[str, Any]],
    chunk_edge_rows: Iterable[Mapping[str, Any]],
    *,
    source_maps_complete: bool,
    chunks_complete: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Prepare successful-snapshot-backed typed diffs for P2 JavaScript evidence."""
    replace_state = getattr(ctx.db, "replace_recon_derived_working_state", None)
    meta: dict[str, Any] = {
        "supported": callable(replace_state),
        "prepared_sets": 0,
        "initialized_sets": 0,
        "truncated_sets": 0,
    }
    signals: list[dict[str, Any]] = []
    if not callable(replace_state):
        return signals, meta

    specs: list[tuple[str, bool, dict[str, dict[str, Any]]]] = []

    source_items: dict[str, dict[str, Any]] = {}
    for row in source_map_rows:
        item_key = str(row.get("source_identity") or "").strip()
        if not item_key:
            continue
        source_items[item_key] = {
            "js_url": str(row.get("js_url") or ""),
            "source_map_url": str(row.get("source_map_url") or ""),
            "source_name": str(row.get("source_name") or ""),
            "source_root": str(row.get("source_root") or ""),
            "resolved_source_url": str(row.get("resolved_source_url") or ""),
            "embedded": bool(row.get("embedded")),
            "content_hash": str(row.get("content_hash") or ""),
            "semantic_hash": str(row.get("semantic_hash") or ""),
            "source_map_hash": str(row.get("source_map_hash") or ""),
        }
    source_items_bounded = len(source_items) <= DERIVED_RECON_STATE_LIMIT
    if not source_items_bounded:
        meta["truncated_sets"] += 1
    specs.append((
        "source_map_source",
        source_maps_complete and source_items_bounded,
        source_items,
    ))

    chunk_items: dict[str, dict[str, Any]] = {}
    for row in chunk_edge_rows:
        js_url = str(row.get("js_url") or "").strip()
        chunk_url = str(row.get("chunk_url") or "").strip()
        if not js_url or not chunk_url:
            continue
        item_key = sha256_text(json_dumps([js_url, chunk_url]))
        chunk_items[item_key] = {"js_url": js_url, "chunk_url": chunk_url}
    chunk_items_bounded = len(chunk_items) <= DERIVED_RECON_STATE_LIMIT
    if not chunk_items_bounded:
        meta["truncated_sets"] += 1
    specs.append((
        "javascript_chunk",
        chunks_complete and chunk_items_bounded,
        chunk_items,
    ))

    for state_type, complete, items in specs:
        if not complete:
            continue
        diff = replace_state(ctx.run_id, ctx.policy.name, state_type, items)
        meta["prepared_sets"] += 1
        if not bool(diff.get("baseline_exists")):
            meta["initialized_sets"] += 1
            continue
        baseline_run_id = str(diff.get("baseline_run_id") or "")
        for change in ("added", "removed", "changed"):
            for row in diff.get(change, []):
                item_key = str(row.get("item_key") or "")
                before = dict(row.get("before") or {})
                after = dict(row.get("after") or {})
                payload = after or before
                item = str(
                    payload.get("source_name")
                    or payload.get("chunk_url")
                    or item_key
                )
                signal = {
                    "signal_type": f"{state_type}_{change}",
                    "state_type": state_type,
                    "change": change,
                    "item_key": item_key,
                    "item": item,
                    "baseline_run_id": baseline_run_id,
                    "run_id": ctx.run_id,
                    "target": ctx.policy.name,
                    "before": before,
                    "after": after,
                }
                signals.append(signal)

    signals.sort(key=lambda row: (row["state_type"], row["change"], row["item_key"]))
    return signals, meta


def stage_javascript(ctx: StageContext) -> dict[str, Any]:
    urls_path = ctx.current / "urls.txt"
    urls: list[str] = []
    if urls_path.exists():
        urls = [line.strip() for line in urls_path.read_text(encoding="utf-8", errors="replace").splitlines()]
    classified_js_urls = sorted({url for url in urls if classify_url(url) == "javascript"})
    js_urls = classified_js_urls[: ctx.policy.limits.max_js_files]
    upstream_metrics: dict[str, Any] = {}
    try:
        upstream = json.loads((ctx.current / "url-collection.json").read_text(encoding="utf-8"))
        if (isinstance(upstream, dict) and upstream.get("run_id") == ctx.run_id
                and upstream.get("target") == ctx.policy.name and isinstance(upstream.get("metrics"), dict)):
            upstream_metrics = upstream["metrics"]
    except (OSError, ValueError, TypeError):
        pass
    selection = upstream_metrics.get("url_selection", {})
    if not isinstance(selection, dict):
        selection = {}
    dropped_js = selection.get("javascript_dropped", 0)
    dropped_js = dropped_js if isinstance(dropped_js, int) and dropped_js >= 0 else 0
    upstream_status = str(upstream_metrics.get("collection_status") or "not_recorded")
    input_issues = []
    if not urls_path.exists():
        input_issues.append("url_input_missing")
    if upstream_status == "partial":
        input_issues.append("upstream_url_collection_partial")
    if dropped_js:
        input_issues.append("url_selection_limit")
    if len(classified_js_urls) > len(js_urls):
        input_issues.append("javascript_file_limit")
    input_metrics = {
        "source_url_count": len([url for url in urls if url]),
        "input_url_count": len(classified_js_urls),
        "selected_input_count": len(js_urls),
        "url_collection_status": upstream_status,
        "classification_method": "url_path_extension",
        "javascript_discovered": selection.get("javascript_candidates"),
        "javascript_dropped_by_url_limit": dropped_js,
        "javascript_dropped_by_file_limit": len(classified_js_urls) - len(js_urls),
    }
    # Never turn missing/truncated upstream evidence into removals from a
    # previous complete JS/source-map snapshot.
    input_complete = upstream_status == "completed" and not input_issues
    atomic_write_text(ctx.current / "javascript-urls.txt", "".join(f"{url}\n" for url in js_urls))
    source_map_collection_enabled = bool(
        ctx.policy.raw.get("javascript", {}).get("download_source_maps", True)
    )
    if not js_urls:
        for filename in ("new-js-files.txt", "changed-js-files.txt", "semantic-js-changes.txt", "new-js-indicators.tsv", "not-found-js-files.txt"):
            atomic_write_text(ctx.changes / filename, "")
        write_jsonl(ctx.current / "javascript-errors.jsonl", [])
        write_jsonl(
            ctx.current / "javascript-not-found.jsonl",
            [],
        )
        write_jsonl(
            ctx.current / "javascript-availability.jsonl",
            [],
        )
        write_jsonl(
            ctx.current / "source-map-sources.jsonl",
            [],
        )
        write_jsonl(
            ctx.current / "javascript-chunk-edges.jsonl",
            [],
        )
        derived_signals, derived_meta = _prepare_javascript_derived_differentials(
            ctx,
            [],
            [],
            source_maps_complete=source_map_collection_enabled and input_complete,
            chunks_complete=input_complete,
        )
        write_jsonl(
            ctx.changes / "recon-derived-differentials.jsonl",
            derived_signals,
        )
        return {
            **input_metrics,
            "files": 0,
            "downloaded": 0,
            "collection_status": "partial" if input_issues else "no_input",
            "collection_reasons": input_issues or ["no_javascript_urls_classified"],
            "zero_download_reasons": input_issues or ["no_javascript_urls_classified"],
            "download_attempts": 0,
            "reused_work_items": 0,
            "new": 0,
            "raw_changed": 0,
            "semantic_changed": 0,
            "indicators": 0,
            "diffs": 0,
            "not_found": 0,
            "errors": 0,
            "availability_changes": 0,
            "reappeared": 0,
            "disappeared": 0,
            "source_maps": 0,
            "source_map_sources": 0,
            "embedded_sources": 0,
            "embedded_source_indicators": 0,
            "chunk_edges": 0,
            "derived_differentials": len(derived_signals),
            "derived_sets_prepared": int(derived_meta.get("prepared_sets", 0)),
            "derived_sets_initialized": int(derived_meta.get("initialized_sets", 0)),
        }

    workers = min(50, max(1, ctx.policy.limits.js_workers))
    work_queue = WorkQueue(ctx.db, ctx.run_id, ctx.policy.name, "javascript-items", ctx.db_writer)
    pending_urls = [url for url in js_urls if not work_queue.completed(url)]
    fresh_full_js_pass = len(pending_urls) == len(js_urls)
    work_ids = {url: work_queue.enqueue(url, {"kind": "download_url", "url": url, "allowed_roots": ctx.policy.roots}) for url in pending_urls}
    for url, work_id in work_ids.items():
        work_queue.start(work_id, "local-js")
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_download_url, ctx, url, ctx.policy.limits.max_js_bytes): url for url in pending_urls}
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                work_queue.fail(
                    work_ids[url],
                    str(exc),
                    retry=True,
                )
                result = {"url": url, "error": str(exc)}
            results.append(result)
            ctx.progress.update(index, len(js_urls), f"downloaded={sum(1 for x in results if 'data' in x)}")
            ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "javascript")

    new_files: list[str] = []
    changed_files: list[str] = []
    semantic_changes: list[str] = []
    indicator_lines: list[str] = []
    downloaded = 0
    indicator_count = 0
    maps_downloaded = 0
    diff_count = 0
    classified_endpoints = 0
    errors: list[dict[str, str]] = []
    not_found: list[dict[str, Any]] = []
    source_map_rows: list[dict[str, Any]] = []
    chunk_edge_rows: list[dict[str, str]] = []
    source_map_sources = 0
    embedded_sources = 0
    embedded_source_indicators = 0
    source_map_attempts = 0
    source_map_failures = 0
    unexpected_content_types = 0

    availability_rows: list[dict[str, Any]] = []
    availability_changes = 0
    reappeared = 0
    disappeared = 0

    def record_availability(
        url: str,
        state: str,
        *,
        status_code: int = 0,
        content_type: str = "",
        error: str = "",
        raw_hash: str = "",
        semantic_hash: str = "",
    ) -> None:
        nonlocal availability_changes
        nonlocal reappeared
        nonlocal disappeared

        history = ctx.db.record_js_availability(
            ctx.run_id,
            ctx.policy.name,
            url,
            state,
            status_code=status_code,
            content_type=content_type,
            error=error,
            raw_hash=raw_hash,
            semantic_hash=semantic_hash,
        )

        previous = history.get("previous")
        changed = bool(
            history.get("changed")
        )

        previous_state = (
            str(previous.get("state") or "")
            if previous
            else ""
        )

        previous_status = (
            int(
                previous.get("status_code")
                or 0
            )
            if previous
            else 0
        )

        availability_rows.append(
            {
                "url": url,
                "state": state,
                "status_code": int(
                    status_code or 0
                ),
                "content_type": content_type,
                "error": error,
                "raw_hash": raw_hash,
                "semantic_hash": semantic_hash,
                "previous_run_id": (
                    str(
                        previous.get("run_id")
                        or ""
                    )
                    if previous
                    else ""
                ),
                "previous_state": previous_state,
                "previous_status_code": (
                    previous_status
                ),
                "changed": changed,
            }
        )

        if not changed or not previous:
            return

        availability_changes += 1

        details = {
            "previous_run_id": str(
                previous.get("run_id")
                or ""
            ),
            "previous_state": previous_state,
            "previous_status_code": (
                previous_status
            ),
            "state": state,
            "status_code": int(
                status_code or 0
            ),
        }

        if (
            previous_state == "not_found"
            and state == "live"
        ):
            reappeared += 1
            emit_event(
                ctx,
                "js_reappeared",
                url,
                "JavaScript asset became reachable",
                details,
            )

        elif (
            previous_state == "live"
            and state == "not_found"
        ):
            disappeared += 1
            emit_event(
                ctx,
                "js_disappeared",
                url,
                "JavaScript asset became unavailable",
                details,
            )

    diff_dir = ctx.changes / "js-diffs"
    diff_dir.mkdir(parents=True, exist_ok=True)

    for result in sorted(results, key=lambda x: x["url"]):
        url = result["url"]
        if "data" not in result:
            if result.get("not_found"):
                status_code = int(
                    result.get("status_code") or 0
                )

                not_found.append(
                    {
                        "url": url,
                        "status_code": status_code,
                    }
                )

                record_availability(
                    url,
                    "not_found",
                    status_code=status_code,
                )

                if url in work_ids:
                    work_queue.finish(
                        work_ids[url],
                        {
                            "status": "not_found",
                            "status_code": status_code,
                        },
                    )

                continue

            error_text = str(
                result.get(
                    "error",
                    "download failed",
                )
            )

            errors.append(
                {
                    "url": url,
                    "error": error_text,
                }
            )

            record_availability(
                url,
                "error",
                status_code=int(
                    result.get(
                        "status_code"
                    )
                    or 0
                ),
                error=error_text,
            )

            if url in work_ids:
                work_queue.fail(
                    work_ids[url],
                    str(
                        result.get(
                            "error",
                            "download failed",
                        )
                    ),
                    retry=True,
                )

            continue
        data = result["data"]
        content_type = str(result.get("content_type", "")).lower()
        if content_type and not any(
            token in content_type
            for token in (
                "javascript",
                "ecmascript",
                "text/plain",
                "application/octet-stream",
                "application/json",
            )
        ):
            unexpected_content_types += 1
            error_text = (
                f"unexpected content-type: "
                f"{content_type}"
            )

            errors.append(
                {
                    "url": url,
                    "error": error_text,
                }
            )

            record_availability(
                url,
                "unexpected_content_type",
                status_code=int(
                    result.get(
                        "status_code"
                    )
                    or 0
                ),
                content_type=content_type,
                error=error_text,
            )
            if url in work_ids:
                work_queue.fail(work_ids[url], error_text, retry=True)
            continue
        downloaded += 1
        raw_hash = sha256_bytes(data)
        text = data.decode("utf-8", "replace")
        semantic_hash = sha256_text(
            semantic_js_normalize(text)
        )

        record_availability(
            url,
            "live",
            status_code=int(
                result.get("status_code")
                or 0
            ),
            content_type=content_type,
            raw_hash=raw_hash,
            semantic_hash=semantic_hash,
        )

        current_indicators = extract_js_indicators(text)
        old_row = ctx.db.one(
            "SELECT raw_hash,semantic_hash,blob_path FROM js_files WHERE target=? AND url=?",
            (ctx.policy.name, url),
        )
        old_text = ""
        if old_row and old_row["blob_path"]:
            old_path = Path(str(old_row["blob_path"]))
            if old_path.exists():
                with contextlib.suppress(OSError):
                    old_text = old_path.read_text(encoding="utf-8", errors="replace")

        store = ContentAddressedStore(ctx.paths, ctx.db)
        object_hash, blob_path, _object_created = store.put(data, content_type=content_type or "application/javascript")
        source_map_url = _find_source_map_url(url, text)
        is_new, raw_changed, semantic_changed = ctx.db.upsert_js(
            ctx.policy.name,
            url,
            raw_hash,
            semantic_hash,
            str(blob_path),
            len(data),
            ctx.run_id,
            etag=str(result.get("etag", "")),
            last_modified=str(result.get("last_modified", "")),
            source_map_url=source_map_url,
        )
        js_owner_key = f"{ctx.policy.name}\n{url}"
        source_map_source_prefix = js_owner_key + "\n"
        store.set_reference("js_file", js_owner_key, object_hash)
        if ctx.policy.analysis.get("asset_graph", True):
            host = urllib.parse.urlsplit(url).hostname or ""
            ctx.db.upsert_edge(ctx.policy.name, "host", host, "serves_javascript", "javascript", url, ctx.run_id, {"semantic_hash": semantic_hash})

        diff_summary: dict[str, Any] = {}
        diff_id = 0
        diff_path = ""
        if raw_changed and old_text:
            diff_text, diff_summary = build_js_diff(old_text, text)
            diff_path_obj = diff_dir / f"{safe_filename(url)}.diff"
            atomic_write_text(diff_path_obj, diff_text or "No normalized textual difference.\n")
            diff_path = str(diff_path_obj)
            diff_id = ctx.db.record_js_diff(
                ctx.run_id,
                ctx.policy.name,
                url,
                str(old_row["raw_hash"] if old_row else ""),
                raw_hash,
                str(old_row["semantic_hash"] if old_row else ""),
                semantic_hash,
                diff_summary,
                diff_text,
                diff_path,
            )
            diff_count += 1

        if is_new:
            new_files.append(url)
            emit_event(ctx, "new_js", url, "New JavaScript file", {"raw_hash": raw_hash, "semantic_hash": semantic_hash})
        elif raw_changed:
            changed_files.append(url)
            details: dict[str, Any] = {
                "raw_changed": True,
                "semantic_changed": semantic_changed,
                "raw_hash": raw_hash,
                "semantic_hash": semantic_hash,
                "old_raw_hash": str(old_row["raw_hash"] if old_row else ""),
                "old_semantic_hash": str(old_row["semantic_hash"] if old_row else ""),
                "diff_id": diff_id,
                "diff_path": diff_path,
                "diff_summary": diff_summary,
            }
            emit_event(ctx, "changed_js", url, "JavaScript file changed", details)
        if semantic_changed:
            semantic_changes.append(url)

        for kind, value, redacted in current_indicators:
            is_new_indicator = ctx.db.upsert_js_indicator(ctx.policy.name, url, kind, value, redacted, ctx.run_id)
            classification: dict[str, Any] | None = None
            if kind in {"endpoint", "absolute_url", "graphql_operation"}:
                classification = classify_endpoint(value, kind=kind, context={"redacted": redacted})
                if ctx.db.upsert_endpoint_intelligence(ctx.policy.name, value, kind, classification, url, ctx.run_id):
                    classified_endpoints += 1
            if ctx.policy.analysis.get("asset_graph", True):
                metadata: dict[str, Any] = {"redacted": redacted}
                if classification:
                    metadata["classification"] = classification
                ctx.db.upsert_edge(ctx.policy.name, "javascript", url, "references", kind, value, ctx.run_id, metadata)
            if is_new_indicator:
                indicator_count += 1
                indicator_lines.append(f"{kind}\t{value}\t{url}")
                details = {"kind": kind, "value": value, "js_url": url, "redacted": redacted}
                if classification:
                    details["endpoint_classification"] = classification
                emit_event(ctx, "js_indicator", f"{kind}:{value}@{url}", "New JavaScript intelligence", details)

        for chunk_url in _extract_js_chunk_references(url, text):
            if not ctx.policy.url_in_scope(chunk_url):
                continue
            chunk_edge_rows.append({"js_url": url, "chunk_url": chunk_url})
            if ctx.policy.analysis.get("asset_graph", True):
                ctx.db.upsert_edge(
                    ctx.policy.name,
                    "javascript",
                    url,
                    "references_chunk",
                    "javascript",
                    chunk_url,
                    ctx.run_id,
                    {"discovery": "static_string"},
                )

        if not source_map_url and source_map_collection_enabled:
            store.drop_reference("source_map", js_owner_key)
            store.sync_references(
                "source_map_source",
                {},
                owner_prefix=source_map_source_prefix,
            )

        if source_map_url and ctx.policy.url_in_scope(source_map_url) and source_map_collection_enabled:
            source_map_attempts += 1
            map_result = _download_url(ctx, source_map_url, ctx.policy.limits.max_js_bytes)
            if "data" in map_result:
                map_data = map_result["data"]
                map_hash, map_path, _ = store.put(map_data, content_type="application/json")
                store.set_reference("source_map", js_owner_key, map_hash)
                current_embedded_refs: dict[str, str] = {}
                maps_downloaded += 1
                if ctx.policy.analysis.get("asset_graph", True):
                    ctx.db.upsert_edge(
                        ctx.policy.name,
                        "javascript",
                        url,
                        "has_source_map",
                        "source_map",
                        source_map_url,
                        ctx.run_id,
                        {"content_hash": map_hash, "blob_path": str(map_path)},
                    )
                try:
                    parsed_source_map = json.loads(map_data.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    parsed_source_map = None
                if not isinstance(parsed_source_map, dict):
                    source_map_failures += 1
                with contextlib.suppress(json.JSONDecodeError):
                    source_map = json.loads(map_data.decode("utf-8", "replace"))
                    if isinstance(source_map, dict):
                        entries = _source_map_entries(source_map_url, source_map)
                        source_map_sources += len(entries)
                        for entry in entries:
                            embedded_content = str(entry.pop("embedded_content", "") or "")
                            source_name = str(entry["source_name"])
                            source_identity = str(entry["source_identity"])
                            resolved_source_url = str(entry.get("resolved_source_url") or "")
                            source_value = source_name[:500]
                            if ctx.db.upsert_js_indicator(ctx.policy.name, url, "source_map_source", source_value, False, ctx.run_id):
                                indicator_count += 1
                                indicator_lines.append(f"source_map_source\t{source_value}\t{url}")

                            if embedded_content:
                                embedded_sources += 1
                                source_bytes = embedded_content.encode("utf-8")
                                source_hash, source_path, _ = store.put(source_bytes, content_type="text/plain")
                                current_embedded_refs[
                                    source_map_source_prefix + source_identity
                                ] = source_hash
                                entry["object_hash"] = source_hash
                                entry["blob_path"] = str(source_path)
                                embedded_indicators = extract_js_indicators(embedded_content)
                                embedded_source_indicators += len(embedded_indicators)
                                for kind, value, redacted in embedded_indicators:
                                    is_new_indicator = ctx.db.upsert_js_indicator(
                                        ctx.policy.name,
                                        url,
                                        kind,
                                        value,
                                        redacted,
                                        ctx.run_id,
                                    )
                                    classification: dict[str, Any] | None = None
                                    if kind in {"endpoint", "absolute_url", "graphql_operation"}:
                                        classification = classify_endpoint(
                                            value,
                                            kind=kind,
                                            context={
                                                "redacted": redacted,
                                                "source_map_source": source_name,
                                            },
                                        )
                                        if ctx.db.upsert_endpoint_intelligence(
                                            ctx.policy.name,
                                            value,
                                            kind,
                                            classification,
                                            source_identity,
                                            ctx.run_id,
                                        ):
                                            classified_endpoints += 1
                                    if ctx.policy.analysis.get("asset_graph", True):
                                        metadata: dict[str, Any] = {
                                            "redacted": redacted,
                                            "embedded_source": True,
                                        }
                                        if classification:
                                            metadata["classification"] = classification
                                        ctx.db.upsert_edge(
                                            ctx.policy.name,
                                            "source_map_source",
                                            source_identity,
                                            "references",
                                            kind,
                                            value,
                                            ctx.run_id,
                                            metadata,
                                        )
                                    if is_new_indicator:
                                        indicator_count += 1
                                        indicator_lines.append(f"{kind}\t{value}\t{source_identity}")
                                        details = {
                                            "kind": kind,
                                            "value": value,
                                            "js_url": url,
                                            "redacted": redacted,
                                            "source_map_url": source_map_url,
                                            "source_map_source": source_name,
                                            "embedded_source": True,
                                        }
                                        if classification:
                                            details["endpoint_classification"] = classification
                                        emit_event(
                                            ctx,
                                            "js_indicator",
                                            f"{kind}:{value}@{source_identity}",
                                            "New embedded source-map intelligence",
                                            details,
                                        )

                            if ctx.policy.analysis.get("asset_graph", True):
                                ctx.db.upsert_edge(
                                    ctx.policy.name,
                                    "source_map",
                                    source_map_url,
                                    "contains_source",
                                    "source_map_source",
                                    source_identity,
                                    ctx.run_id,
                                    {
                                        "source_name": source_name,
                                        "resolved_source_url": resolved_source_url,
                                        "embedded": bool(entry.get("embedded")),
                                        "content_hash": str(entry.get("content_hash") or ""),
                                    },
                                )
                            source_map_rows.append(
                                {
                                    "js_url": url,
                                    "source_map_url": source_map_url,
                                    "source_map_hash": map_hash,
                                    **entry,
                                }
                            )
                store.sync_references(
                    "source_map_source",
                    current_embedded_refs,
                    owner_prefix=source_map_source_prefix,
                )
            else:
                source_map_failures += 1
        if url in work_ids:
            work_queue.finish(
                work_ids[url],
                {
                    "raw_hash": raw_hash,
                    "semantic_hash": semantic_hash,
                    "object_hash": object_hash,
                },
            )

    atomic_write_text(ctx.changes / "new-js-files.txt", "".join(f"{x}\n" for x in new_files))
    atomic_write_text(ctx.changes / "changed-js-files.txt", "".join(f"{x}\n" for x in changed_files))
    atomic_write_text(ctx.changes / "semantic-js-changes.txt", "".join(f"{x}\n" for x in semantic_changes))
    atomic_write_text(ctx.changes / "new-js-indicators.tsv", "".join(f"{x}\n" for x in sorted(indicator_lines)))
    write_jsonl(
        ctx.current / "javascript-errors.jsonl",
        errors,
    )
    write_jsonl(
        ctx.current / "javascript-not-found.jsonl",
        not_found,
    )
    write_jsonl(
        ctx.current / "javascript-availability.jsonl",
        availability_rows,
    )
    write_jsonl(
        ctx.current / "source-map-sources.jsonl",
        source_map_rows,
    )
    write_jsonl(
        ctx.current / "javascript-chunk-edges.jsonl",
        sorted(chunk_edge_rows, key=lambda row: (row["js_url"], row["chunk_url"])),
    )

    chunks_complete = fresh_full_js_pass and not errors and input_complete
    source_maps_complete = (
        fresh_full_js_pass
        and input_complete
        and not errors
        and source_map_collection_enabled
        and source_map_failures == 0
    )
    derived_signals, derived_meta = _prepare_javascript_derived_differentials(
        ctx,
        source_map_rows,
        chunk_edge_rows,
        source_maps_complete=source_maps_complete,
        chunks_complete=chunks_complete,
    )
    write_jsonl(
        ctx.changes / "recon-derived-differentials.jsonl",
        derived_signals,
    )

    atomic_write_text(
        ctx.changes / "not-found-js-files.txt",
        "".join(
            f"{row['url']}\n"
            for row in not_found
        ),
    )

    collection_reasons = list(input_issues)
    if len(errors) > unexpected_content_types:
        collection_reasons.append("download_errors")
    if unexpected_content_types:
        collection_reasons.append("unexpected_content_type")
    if source_map_failures:
        collection_reasons.append("source_map_download_errors")
    zero_download_reasons = []
    if downloaded == 0:
        zero_download_reasons.extend(collection_reasons)
        if not_found:
            zero_download_reasons.append("not_found")
        if len(pending_urls) < len(js_urls):
            zero_download_reasons.append("already_processed")
    return {
        **input_metrics,
        "collection_status": "partial" if collection_reasons else "completed",
        "collection_reasons": collection_reasons,
        "zero_download_reasons": zero_download_reasons,
        "download_attempts": len(pending_urls),
        "reused_work_items": len(js_urls) - len(pending_urls),
        "unexpected_content_types": unexpected_content_types,
        "files": len(js_urls),
        "downloaded": downloaded,
        "new": len(new_files),
        "raw_changed": len(changed_files),
        "semantic_changed": len(semantic_changes),
        "indicators": indicator_count,
        "classified_endpoints": classified_endpoints,
        "diffs": diff_count,
        "source_maps": maps_downloaded,
        "source_map_sources": source_map_sources,
        "embedded_sources": embedded_sources,
        "embedded_source_indicators": embedded_source_indicators,
        "chunk_edges": len(chunk_edge_rows),
        "source_map_attempts": source_map_attempts,
        "source_map_failures": source_map_failures,
        "derived_differentials": len(derived_signals),
        "derived_sets_prepared": int(derived_meta.get("prepared_sets", 0)),
        "derived_sets_initialized": int(derived_meta.get("initialized_sets", 0)),
        "derived_sets_truncated": int(derived_meta.get("truncated_sets", 0)),
        "errors": len(errors),
        "not_found": len(not_found),
        "availability_changes": (
            availability_changes
        ),
        "reappeared": reappeared,
        "disappeared": disappeared,
    }



def _endpoint_candidate_urls(ctx: StageContext, endpoint: str, sources: Iterable[str] = ()) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(value: str, method: str, source: str = "") -> None:
        normalized = normalize_url_preserving_semantics(value)
        if not normalized or not ctx.policy.url_in_scope(normalized) or normalized in seen:
            return
        seen.add(normalized)
        candidates.append((normalized, method, source))

    add(endpoint, "absolute_endpoint")

    # Relative references extracted from JavaScript must be resolved against
    # the document/chunk origin that exposed them, not blindly against the
    # policy root. endpoint_intelligence.sources_json already retains that
    # provenance for JavaScript-derived indicators.
    if not normalize_url_preserving_semantics(endpoint):
        for source in sources:
            source_url = normalize_url_preserving_semantics(str(source))
            if not source_url or not ctx.policy.url_in_scope(source_url):
                continue
            add(urllib.parse.urljoin(source_url, endpoint), "source_origin", source_url)

    # Root fallback preserves previous behaviour for endpoints whose collector
    # did not retain an absolute source URL.
    if not candidates and endpoint.startswith("/"):
        for root in ctx.policy.roots:
            add(f"https://{root}{endpoint}", "root_fallback", root)

    return candidates


def _safe_validate_endpoint(ctx: StageContext, endpoint: str, sources: Iterable[str] = ()) -> dict[str, Any]:
    candidates = _endpoint_candidate_urls(ctx, endpoint, sources)
    if not candidates:
        return {"endpoint": endpoint, "skipped": "not a safe in-scope HTTP endpoint"}

    last_result: dict[str, Any] = {}
    for url, resolution_method, resolution_source in candidates[:3]:
        if ctx.budget:
            ctx.budget.consume("http_requests", 1)

        def observation(method: str, observed_url: str, status: int, headers: Any, _body: bytes, error: str = "") -> dict[str, Any]:
            content_type = ""
            if headers:
                with contextlib.suppress(Exception):
                    content_type = str(headers.get("Content-Type", ""))[:200]
            reachable = bool(status)
            confidence = 90 if 200 <= int(status or 0) < 400 else 80 if reachable else 30
            return {
                "endpoint": endpoint,
                "resolved_url": observed_url,
                "method": method,
                "status_code": int(status or 0),
                "content_type": content_type,
                "reachable": reachable,
                "confidence": confidence,
                "error": "" if reachable else str(error or ""),
            }

        result, transport_status = perform_pinned_request(
            {"method": "HEAD", "url": url, "headers": _policy_headers_for_url(ctx.policy, url)},
            ctx.policy,
            safe_methods={"HEAD"},
            url_safety=lambda candidate, policy: (
                bool(policy.url_in_scope(candidate)),
                "outside_scope" if not policy.url_in_scope(candidate) else "",
            ),
            observation=observation,
            max_response_bytes=0,
            validation_version="recon-endpoint-1",
        )
        result["resolution_method"] = resolution_method
        result["resolution_source"] = resolution_source
        result["transport_status"] = transport_status
        last_result = result
        if result.get("reachable") or transport_status == "stopped_for_safety":
            return result

    return last_result or {
        "endpoint": endpoint,
        "resolved_url": candidates[0][0],
        "method": "HEAD",
        "status_code": 0,
        "content_type": "",
        "reachable": False,
        "confidence": 30,
        "error": "endpoint validation failed",
    }


def stage_endpoint_validation(ctx: StageContext) -> dict[str, Any]:
    if not ctx.policy.modules.get("endpoint_validation", False):
        return {"skipped": "disabled"}
    rows = ctx.db.all(
        "SELECT endpoint,kind,confidence,sources_json FROM endpoint_intelligence WHERE target=? ORDER BY confidence DESC LIMIT ?",
        (ctx.policy.name, min(1000, ctx.policy.limits.max_urls)),
    )
    queue = WorkQueue(ctx.db, ctx.run_id, ctx.policy.name, "endpoint-validation-items", ctx.db_writer)
    pending: list[tuple[str, list[str]]] = []
    for row in rows:
        endpoint = str(row["endpoint"])
        if queue.completed(endpoint):
            continue
        try:
            raw_sources = json.loads(str(row["sources_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            raw_sources = []
        sources = [str(value) for value in raw_sources] if isinstance(raw_sources, list) else []
        pending.append((endpoint, sources))

    workers = min(10, max(1, ctx.policy.limits.http_workers // 4))
    results: list[dict[str, Any]] = []

    def run(item: tuple[str, list[str]]) -> dict[str, Any]:
        endpoint, sources = item
        work_id = queue.enqueue(
            endpoint,
            {
                "kind": "http_head",
                "url": endpoint,
                "sources": sources,
                "allowed_roots": ctx.policy.roots,
            },
        )
        queue.start(work_id, "local-validation")
        try:
            result = _safe_validate_endpoint(ctx, endpoint, sources)
            queue.finish(work_id, result)
            return result
        except Exception as exc:
            queue.fail(work_id, str(exc), retry=True)
            return {"endpoint": endpoint, "error": str(exc), "reachable": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, result in enumerate(pool.map(run, pending), 1):
            results.append(result)
            ctx.progress.update(index, len(pending), f"reachable={sum(1 for r in results if r.get('reachable'))}")

    now = utc_now()
    for result in results:
        if result.get("skipped"):
            continue
        ctx.db.execute(
            "INSERT INTO endpoint_validations(target,endpoint,resolved_url,method,status_code,content_type,reachable,confidence,checked_at,last_run_id,error) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(target,endpoint,resolved_url) DO UPDATE SET method=excluded.method,status_code=excluded.status_code,content_type=excluded.content_type,reachable=excluded.reachable,confidence=excluded.confidence,checked_at=excluded.checked_at,last_run_id=excluded.last_run_id,error=excluded.error",
            (
                ctx.policy.name, result.get("endpoint", ""), result.get("resolved_url", ""),
                result.get("method", "HEAD"), result.get("status_code", 0), result.get("content_type", ""),
                int(bool(result.get("reachable"))), result.get("confidence", 0), now, ctx.run_id, result.get("error", ""),
            ),
        )
        if result.get("reachable") and int(result.get("status_code", 0)) in {200, 201, 202, 204, 401, 403, 405}:
            emit_event(ctx, "validated_endpoint", str(result.get("resolved_url")), "Extracted endpoint validated", result)
    write_jsonl(ctx.current / "endpoint-validations.jsonl", results)
    return {
        "candidates": len(rows),
        "checked": len(results),
        "reachable": sum(1 for r in results if r.get("reachable")),
        "errors": sum(1 for r in results if r.get("error")),
    }

def _tls_certificate_info(
    ctx: StageContext,
    url: str,
    timeout: float = 5.0,
) -> dict[str, Any]:
    transport = fetch_pinned_tls_peer(
        url,
        ctx.policy,
        timeout=timeout,
    )
    cert = (
        transport.get("certificate")
        if isinstance(transport.get("certificate"), Mapping)
        else {}
    )
    if not cert:
        return {}

    def flatten_name(value: Any) -> str:
        parts: list[str] = []
        for group in value or []:
            for key, item in group:
                parts.append(f"{key}={item}")
        return ", ".join(parts)

    sans = [
        str(item)
        for kind, item in cert.get("subjectAltName", [])
        if kind == "DNS"
    ]
    return {
        "tls_issuer": flatten_name(cert.get("issuer")),
        "tls_expiry": str(cert.get("notAfter") or ""),
        "tls_sans": sorted(sans),
        "tls_serial": str(cert.get("serialNumber") or ""),
        "tls_pinned_address": str(transport.get("pinned_address") or ""),
        "tls_dns_rebinding_protection": str(
            transport.get("dns_rebinding_protection") or ""
        ),
        "tls_safe_transport_version": str(
            transport.get("safe_transport_version") or ""
        ),
    }


_PERSISTED_RESPONSE_HEADER_NAMES = frozenset({
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
})


_HTTPX_XML_ROOT_EXTRACT_REGEX = (
    # httpx applies -er to resp.Raw, which includes the HTTP status line and
    # headers. Match either a body-only fixture or the first element strictly
    # after the HTTP header/body separator; do not scan arbitrary header text.
    r"(?is)(?:^|\r?\n\r?\n)\s*(?:<\?xml[^>]*>\s*)?"
    r"<\s*(?:[A-Za-z_][\w.-]*:)?[A-Za-z_][\w.-]*\b"
)


def _httpx_response_xml_root(row: Mapping[str, Any]) -> str:
    """Extract only the first XML element name from bounded httpx metadata."""

    samples: list[str] = []
    extracts = row.get("extracts")
    if isinstance(extracts, Mapping):
        for values in extracts.values():
            if isinstance(values, (list, tuple, set)):
                samples.extend(str(value) for value in values if value is not None)
            elif values is not None:
                samples.append(str(values))
    for key in ("body_preview", "body"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            samples.append(value[:8192])

    root_re = re.compile(r"<\s*(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\b")
    for sample in samples:
        match = root_re.search(sample)
        if match:
            return str(match.group(1) or "").strip().lower()[:128]
    return ""


def _persistable_response_headers(raw: Any) -> dict[str, str]:
    """Return a bounded allow-listed response-header snapshot.

    The fingerprint stage never persists cookies, authorization material, or
    arbitrary vendor headers. Header names are normalized to lower case and
    values are flattened to short single-line strings for deterministic JSON
    persistence and later passive evidence extraction.
    """

    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key or "").strip().lower()
        if name not in _PERSISTED_RESPONSE_HEADER_NAMES:
            continue
        if isinstance(value, (list, tuple, set)):
            text = ", ".join(str(item) for item in value if item is not None)
        elif isinstance(value, Mapping):
            continue
        else:
            text = str(value or "")
        text = re.sub(r"[\r\n]+", " ", text).strip()
        if text:
            result[name] = text[:2048]
    return result


def _httpx_record(row: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    url = normalize_url(str(row.get("url") or row.get("input") or "")) or ""
    tech = row.get("tech") or row.get("technologies") or []
    if isinstance(tech, str):
        tech = [tech]
    hashes = row.get("hash") or {}
    body_hash = ""
    if isinstance(hashes, dict):
        body_hash = str(hashes.get("body_sha256") or hashes.get("sha256") or "")
    elif isinstance(hashes, str):
        body_hash = hashes
    cname = row.get("cname") or ""
    if isinstance(cname, list):
        cname = ",".join(str(x) for x in cname)
    ip = row.get("host_ip") or row.get("ip") or ""
    chain = row.get("chain") or row.get("redirect_chain") or []
    if not isinstance(chain, list):
        chain = [chain] if chain else []
    response_headers_raw = row.get("header")
    response_headers_observed = isinstance(response_headers_raw, Mapping)
    response_headers = _persistable_response_headers(response_headers_raw)
    content_type = str(row.get("content_type") or "")[:200]
    response_xml_root = (
        _httpx_response_xml_root(row)
        if "xml" in content_type.lower()
        else ""
    )
    record = {
        "status_code": int(row.get("status_code") or 0),
        "title": str(row.get("title") or "")[:500],
        "webserver": str(row.get("webserver") or row.get("web_server") or "")[:300],
        "technologies": sorted(str(x) for x in tech),
        "content_type": content_type,
        "content_length": int(row.get("content_length") or 0),
        "response_headers": response_headers,
        "response_headers_observed": response_headers_observed,
        "response_xml_root": response_xml_root,
        "body_hash": body_hash,
        "favicon_hash": str(row.get("favicon") or row.get("favicon_hash") or ""),
        "jarm": str(row.get("jarm") or ""),
        "ip": str(ip),
        "cname": str(cname),
        "cdn": str(row.get("cdn_name") or row.get("cdn") or ""),
        "final_url": url,
        "redirect_chain": chain,
        "http2": bool(row.get("http2") or row.get("http2_pipeline")),
        "tls_issuer": "",
        "tls_expiry": "",
        "tls_sans": [],
        "tls_serial": "",
        "screenshot_path": row.get("screenshot_path") or row.get("screenshot") or None,
        "screenshot_hash": "",
    }
    return url, record


def stage_fingerprint(ctx: StageContext) -> dict[str, Any]:
    base_path = ctx.current / "base-urls.txt"
    if not base_path.exists():
        return {"probed": 0, "live": 0, "new": 0, "changed": 0}
    if not tool_path("httpx"):
        ctx.logger.warn("ProjectDiscovery httpx missing; fingerprint stage skipped", target=ctx.policy.name)
        return {"probed": 0, "live": 0, "new": 0, "changed": 0, "skipped": "httpx missing"}

    base_count = sum(1 for line in base_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    if ctx.budget:
        ctx.budget.consume("http_requests", base_count)
    out = ctx.current / "httpx.jsonl"
    args = [
        "httpx", "-l", str(base_path), "-silent", "-json", "-duc", "-no-color", "-irh",
        "-sc", "-cl", "-ct", "-location", "-title", "-server", "-td", "-ip", "-cname", "-cdn",
        "-hash", "sha256", "-jarm", "-http2", "-include-chain",
        "-er", _HTTPX_XML_ROOT_EXTRACT_REGEX,
        "-t", str(ctx.policy.limits.http_threads),
        "-rl", str(ctx.policy.limits.request_rate),
        "-timeout", str(min(30, max(5, ctx.policy.limits.timeout_seconds // 20))),
        "-retries", "1",
    ]
    # Policy credentials are confined to the in-process pinned transport.
    if ctx.policy.modules.get("screenshots"):
        screenshot_dir = ctx.run_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        args.extend(["-ss", "-esb", "-ehb", "-srd", str(screenshot_dir)])
    result = ctx.runner.run(
        args,
        timeout=ctx.policy.limits.timeout_seconds,
        output_path=out,
        heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "fingerprint"),
        line_callback=lambda _line, count: ctx.progress.update(count, 0, "httpx probes"),
    )
    if result.returncode not in {0, 1}:
        ctx.logger.warn("Full httpx fingerprint failed; retrying minimal probes", target=ctx.policy.name, exit=result.returncode)
        args = [
            "httpx", "-l", str(base_path), "-silent", "-json", "-duc", "-no-color",
            "-sc", "-cl", "-ct", "-title", "-server", "-td", "-ip", "-cname", "-cdn",
            "-er", _HTTPX_XML_ROOT_EXTRACT_REGEX,
            "-t", str(ctx.policy.limits.http_threads), "-rl", str(ctx.policy.limits.request_rate),
            "-timeout", "10", "-retries", "1",
        ]
        result = ctx.runner.run(
            args,
            timeout=ctx.policy.limits.timeout_seconds,
            output_path=out,
            heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "fingerprint"),
            line_callback=lambda _line, count: ctx.progress.update(count, 0, "httpx fallback"),
        )
    if result.returncode not in {0, 1}:
        raise StageError(f"httpx failed with exit code {result.returncode}", exit_code=result.returncode)

    new_live: list[str] = []
    changed: list[str] = []
    live = 0
    for index, row in enumerate(read_jsonl(out), 1):
        url, record = _httpx_record(row)
        if not url or not ctx.policy.url_in_scope(url):
            continue
        live += 1
        if ctx.policy.raw.get("fingerprint", {}).get("collect_tls", True):
            record.update(_tls_certificate_info(ctx, url))
        screenshot_path = record.get("screenshot_path")
        if screenshot_path:
            screenshot_file = Path(str(screenshot_path)).expanduser()
            if not screenshot_file.is_absolute():
                screenshot_file = ctx.run_dir / screenshot_file
            if screenshot_file.exists() and screenshot_file.is_file():
                with contextlib.suppress(OSError):
                    record["screenshot_hash"] = sha256_bytes(screenshot_file.read_bytes())
                    record["screenshot_path"] = str(screenshot_file)
        record["technology_confidence"] = [technology_confidence(str(technology), record) for technology in record.get("technologies", [])]
        for observation in record["technology_confidence"]:
            ctx.db.upsert_technology_observation(ctx.policy.name, url, str(observation["technology"]), observation, ctx.run_id)
        ctx.db.finalize_technology_observations(ctx.policy.name, url, ctx.run_id)
        canonical = {
            key: record.get(key)
            for key in (
                "status_code", "title", "webserver", "technologies", "content_type", "response_xml_root", "body_hash",
                "favicon_hash", "jarm", "ip", "cname", "cdn", "final_url", "http2",
                "tls_issuer", "tls_expiry", "tls_sans", "tls_serial", "screenshot_hash",
            )
        }
        fp_hash = sha256_text(json_dumps(canonical))
        is_new, is_changed, old = ctx.db.upsert_fingerprint(ctx.policy.name, url, record, fp_hash, ctx.run_id)
        if ctx.policy.analysis.get("asset_graph", True):
            if record.get("ip"):
                ctx.db.upsert_edge(ctx.policy.name, "url", url, "hosted_on", "ip", str(record.get("ip")), ctx.run_id)
            for technology in record.get("technologies", []):
                observation = next((item for item in record.get("technology_confidence", []) if item.get("technology") == technology), {})
                ctx.db.upsert_edge(ctx.policy.name, "url", url, "uses_technology", "technology", str(technology), ctx.run_id, observation)
        if is_new:
            new_live.append(url)
            emit_event(ctx, "new_live_http", url, "New live HTTP service", record)
        elif is_changed:
            changed.append(url)
            emit_event(ctx, "fingerprint_change", url, "HTTP fingerprint changed", {"old": old or {}, "new": record})
        ctx.progress.update(index, 0, f"live={live} new={len(new_live)} changed={len(changed)}")

    atomic_write_text(ctx.changes / "new-live-http.txt", "".join(f"{x}\n" for x in new_live))
    atomic_write_text(ctx.changes / "changed-fingerprints.txt", "".join(f"{x}\n" for x in changed))
    return {"probed": result.lines, "live": live, "new": len(new_live), "changed": len(changed), "screenshots": bool(ctx.policy.modules.get("screenshots"))}


_HTTP_WEB_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8888}
_HTTPS_WEB_PORTS = {443, 4443, 8443, 9443, 10443}


def _web_origin_for_port(host: str, port: int) -> str:
    host = normalize_host(host)
    if not host or port <= 0:
        return ""
    if port in _HTTPS_WEB_PORTS:
        scheme = "https"
    elif port in _HTTP_WEB_PORTS:
        scheme = "http"
    else:
        return ""
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{display_host}" if default else f"{scheme}://{display_host}:{port}"

def stage_ports(ctx: StageContext) -> dict[str, Any]:
    if not ctx.policy.modules.get("ports"):
        return {"skipped": "disabled"}
    if not ctx.policy.active_allowed(ctx.config, ctx.allow_active):
        return {"skipped": "active authorization gate not satisfied"}
    if not tool_path("naabu"):
        return {"skipped": "naabu missing"}
    hosts_path = ctx.current / "resolved-hosts.txt"
    if not hosts_path.exists() or not hosts_path.read_text(encoding="utf-8", errors="replace").strip():
        return {"skipped": "no resolved hosts"}
    ports = str(ctx.policy.active.get("naabu_ports", "80,443,8080,8443"))
    out = ctx.current / "naabu.jsonl"
    args = [
        "naabu", "-list", str(hosts_path), "-p", ports, "-s", "c", "-json", "-silent", "-duc",
        "-rate", str(ctx.policy.limits.naabu_rate), "-c", "10", "-exclude-cdn",
    ]
    result = ctx.runner.run(
        args,
        timeout=ctx.policy.limits.timeout_seconds,
        output_path=out,
        heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "ports"),
        line_callback=lambda _line, count: ctx.progress.update(count, 0, "authorized port checks"),
    )
    if result.returncode not in {0, 1}:
        raise StageError(f"naabu failed with exit code {result.returncode}", exit_code=result.returncode)
    new_ports = 0
    total = 0
    web_origins: set[str] = set()
    for row in read_jsonl(out):
        host = normalize_host(str(row.get("host") or row.get("input") or ""))
        ip = str(row.get("ip") or "")
        port = int(row.get("port") or 0)
        protocol = str(row.get("protocol") or "tcp")
        if not host:
            host = ip
        if not port or (host and not ctx.policy.host_in_scope(host) and host not in ctx.policy.roots):
            continue
        total += 1
        if protocol.lower() == "tcp":
            origin = _web_origin_for_port(host, port)
            if origin and ctx.policy.url_in_scope(origin):
                web_origins.add(origin)
        if ctx.db.upsert_port(ctx.policy.name, host, ip, port, protocol, ctx.run_id):
            new_ports += 1
            emit_event(ctx, "new_port", f"{host}:{port}/{protocol}", "New open port", {"host": host, "ip": ip, "port": port, "protocol": protocol})
    ctx.db.finalize_ports_current(ctx.policy.name, ctx.run_id)
    atomic_write_text(ctx.current / "port-web-origins.txt", "".join(f"{url}\n" for url in sorted(web_origins)))
    return {"open_ports": total, "new": new_ports, "ports": ports, "web_origins": len(web_origins)}


def stage_nuclei(ctx: StageContext) -> dict[str, Any]:
    if not ctx.policy.modules.get("nuclei"):
        return {"skipped": "disabled"}
    if not ctx.policy.active_allowed(ctx.config, ctx.allow_active):
        return {"skipped": "active authorization gate not satisfied"}
    if not tool_path("nuclei"):
        return {"skipped": "nuclei missing"}
    template_ids = [str(x) for x in ctx.policy.active.get("nuclei_template_ids", []) if str(x).strip()]
    if not template_ids:
        return {"skipped": "no template allowlist configured"}
    candidates: set[str] = set()
    for filename in ("new-live-http.txt", "changed-fingerprints.txt"):
        path = ctx.changes / filename
        if path.exists():
            candidates.update(line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    candidates = {url for url in candidates if ctx.policy.url_in_scope(url)}
    if not candidates:
        return {"skipped": "no new or changed live URLs"}
    input_path = ctx.current / "nuclei-input.txt"
    atomic_write_text(input_path, "".join(f"{url}\n" for url in sorted(candidates)))
    out = ctx.current / "nuclei.jsonl"
    severity = ",".join(str(x) for x in ctx.policy.active.get("nuclei_severity", ["info", "low", "medium", "high", "critical"]))
    args = [
        "nuclei", "-list", str(input_path), "-id", ",".join(template_ids), "-severity", severity,
        "-pt", "http,ssl,dns", "-dut", "-jsonl", "-silent", "-nc", "-duc",
        "-rl", str(ctx.policy.limits.nuclei_rate), "-bs", "5", "-c", "5", "-o", str(out),
    ]
    # Do not delegate policy credentials to external active tools.
    result = ctx.runner.run(
        args,
        timeout=ctx.policy.limits.timeout_seconds,
        output_path=None,
        heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "nuclei"),
        line_callback=lambda _line, count: ctx.progress.update(count, 0, "allowlisted templates"),
    )
    if result.returncode not in {0, 1}:
        raise StageError(f"nuclei failed with exit code {result.returncode}", exit_code=result.returncode)
    findings = 0
    new_findings = 0
    for row in read_jsonl(out):
        template_id = str(row.get("template-id") or row.get("template_id") or row.get("template") or "")
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        name = str(info.get("name") or row.get("name") or template_id)
        sev = str(info.get("severity") or row.get("severity") or "info")
        matched_at = str(row.get("matched-at") or row.get("matched_at") or row.get("host") or "")
        dedup = sha256_text(json_dumps([template_id, matched_at]))[:40]
        record = {"template_id": template_id, "name": name, "severity": sev, "matched_at": matched_at, "raw": row}
        findings += 1
        if ctx.db.upsert_finding(ctx.policy.name, dedup, record, ctx.run_id):
            new_findings += 1
            emit_event(ctx, "nuclei_finding", f"{template_id}@{matched_at}", f"Nuclei finding: {name}", record)
    return {"targets": len(candidates), "templates": len(template_ids), "findings": findings, "new": new_findings}


STAGE_FUNCTIONS: dict[str, Callable[[StageContext], dict[str, Any]]] = {
    "subdomains": stage_subdomains,
    "dns": stage_dns,
    "urls": stage_urls,
    "javascript": stage_javascript,
    "endpoint_validation": stage_endpoint_validation,
    "fingerprint": stage_fingerprint,
    "ports": stage_ports,
    "nuclei": stage_nuclei,
}
