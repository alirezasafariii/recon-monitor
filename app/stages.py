from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
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
    header_args,
    json_dumps,
    normalize_host,
    normalize_url,
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

    filtered_hosts = set(hosts)
    if tool_path("dnsx"):
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
                filtered_hosts.update(root_hosts)
        wildcard_candidates = set(hosts) - filtered_hosts
        filtered_hosts.update(ctx.policy.roots)
        query_input = ctx.current / "dns-filtered-hosts.txt"
        atomic_write_text(query_input, "".join(f"{host}\n" for host in sorted(filtered_hosts)))

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
                line_callback=lambda _line, count, t=rrtype: ctx.progress.update(count, len(filtered_hosts), f"query {t}"),
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
        "successful_rrtypes": sorted(successful_rrtypes),
    }


def stage_urls(ctx: StageContext) -> dict[str, Any]:
    hosts_file = ctx.current / "resolved-hosts.txt"
    hosts = _scope_hosts(ctx.policy, hosts_file.read_text(encoding="utf-8", errors="replace").splitlines() if hosts_file.exists() else ctx.policy.roots)
    if not hosts:
        hosts = list(ctx.policy.roots)
    base_urls = sorted({f"https://{host}" for host in hosts} | {f"http://{host}" for host in hosts})
    base_path = ctx.current / "base-urls.txt"
    atomic_write_text(base_path, "".join(f"{url}\n" for url in base_urls))

    candidates: dict[str, set[str]] = {}
    for url in base_urls:
        candidates.setdefault(url + "/" if not url.endswith("/") else url, set()).add("base")

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
                normalized = normalize_url(line)
                if normalized and ctx.policy.url_in_scope(normalized):
                    candidates.setdefault(normalized, set()).add("wayback")

    if tool_path("katana"):
        out = ctx.current / "katana-urls.txt"
        args = [
            "katana", "-list", str(base_path), "-silent", "-duc", "-jc",
            "-d", str(ctx.policy.limits.crawl_depth),
            "-rl", str(ctx.policy.limits.request_rate),
            "-timeout", str(min(30, max(5, ctx.policy.limits.timeout_seconds // 10))),
        ]
        for key, value in ctx.policy.headers.items():
            args.extend(["-H", f"{key}: {value}"])
        result = ctx.runner.run(
            args,
            timeout=ctx.policy.limits.timeout_seconds,
            output_path=out,
            heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "urls"),
            line_callback=lambda _line, count: ctx.progress.update(count, 0, "katana crawling"),
        )
        if result.returncode not in {0, 1}:
            ctx.logger.warn("katana failed", target=ctx.policy.name, exit=result.returncode)
        if out.exists():
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                normalized = normalize_url(line)
                if normalized and ctx.policy.url_in_scope(normalized):
                    candidates.setdefault(normalized, set()).add("katana")

    urls = sorted(candidates)[: ctx.policy.limits.max_urls]
    if ctx.budget:
        # Katana request counts are not emitted consistently; account for the
        # observable crawl output as a conservative request estimate.
        ctx.budget.consume("http_requests", max(len(base_urls), min(len(urls), ctx.policy.limits.max_http_requests)))
    new_count = 0
    classified_count = 0
    rows: list[dict[str, Any]] = []
    new_urls: list[str] = []
    for index, url in enumerate(urls, 1):
        kind = classify_url(url)
        source = ",".join(sorted(candidates[url]))
        is_new = ctx.db.upsert_url(ctx.policy.name, url, kind, source, ctx.run_id)
        endpoint_classification = classify_endpoint(url, kind="url")
        if kind == "api" or endpoint_classification.get("primary_category") != "general":
            if ctx.db.upsert_endpoint_intelligence(ctx.policy.name, url, "url", endpoint_classification, source, ctx.run_id):
                classified_count += 1
        if ctx.policy.analysis.get("asset_graph", True):
            host = urllib.parse.urlsplit(url).hostname or ""
            ctx.db.upsert_edge(ctx.policy.name, "host", host, "serves", "url", url, ctx.run_id, {"kind": kind, "sources": sorted(candidates[url])})
        rows.append({"url": url, "kind": kind, "sources": sorted(candidates[url])})
        if is_new:
            new_count += 1
            new_urls.append(url)
            event_details: dict[str, Any] = {"kind": kind, "sources": sorted(candidates[url])}
            if kind == "api" or endpoint_classification.get("primary_category") != "general":
                event_details["endpoint_classification"] = endpoint_classification
            emit_event(ctx, "new_url", url, "New URL discovered", event_details)
        ctx.progress.update(index, len(urls), f"new={new_count}")
    write_jsonl(ctx.current / "urls.jsonl", rows)
    atomic_write_text(ctx.current / "urls.txt", "".join(f"{url}\n" for url in urls))
    atomic_write_text(ctx.changes / "new-urls.txt", "".join(f"{url}\n" for url in new_urls))
    return {"hosts": len(hosts), "urls": len(urls), "new": new_count, "classified_endpoints": classified_count, "truncated": len(candidates) > len(urls)}


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: TargetPolicy):
        super().__init__()
        self.policy = policy

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> urllib.request.Request | None:
        normalized = normalize_url(newurl)
        if not normalized or not self.policy.url_in_scope(normalized):
            raise urllib.error.HTTPError(newurl, 403, "redirect left authorized scope", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download_url(ctx: StageContext, url: str, max_bytes: int) -> dict[str, Any]:
    headers = {"User-Agent": ctx.config.get("USER_AGENT", "ReconMonitor/3.0 authorized security monitoring"), **ctx.policy.headers}
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(_ScopedRedirectHandler(ctx.policy))
    ssl_context = ssl.create_default_context()
    # HTTPSHandler cannot be mixed into an already-built opener cleanly after creation,
    # so standard verification is retained by urllib's default HTTPS handler.
    started = time.monotonic()
    if ctx.budget:
        ctx.budget.consume("http_requests", 1)
    try:
        with opener.open(request, timeout=min(45, max(5, ctx.policy.limits.timeout_seconds))) as response:
            final_url = normalize_url(response.geturl()) or url
            if not ctx.policy.url_in_scope(final_url):
                raise StageError(f"Redirect left scope: {url} -> {final_url}", retryable=False)
            content_type = response.headers.get("Content-Type", "")
            length_header = response.headers.get("Content-Length")
            if length_header and int(length_header) > max_bytes:
                raise StageError(f"Content too large: {url}", retryable=False)
            data = response.read(max_bytes + 1)
            if ctx.budget:
                ctx.budget.consume("download_bytes", len(data))
            if len(data) > max_bytes:
                raise StageError(f"Content exceeded limit: {url}", retryable=False)
            return {
                "url": url,
                "final_url": final_url,
                "data": data,
                "content_type": content_type,
                "etag": response.headers.get("ETag", ""),
                "last_modified": response.headers.get("Last-Modified", ""),
                "duration": time.monotonic() - started,
            }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout, ValueError) as exc:
        return {"url": url, "error": str(exc), "duration": time.monotonic() - started}


def _find_source_map_url(js_url: str, text: str) -> str:
    matches = re.findall(r"(?m)//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)\s*$", text)
    if not matches:
        return ""
    candidate = urllib.parse.urljoin(js_url, matches[-1].strip().strip("\"'"))
    return normalize_url(candidate) or ""


def stage_javascript(ctx: StageContext) -> dict[str, Any]:
    urls_path = ctx.current / "urls.txt"
    urls: list[str] = []
    if urls_path.exists():
        urls = [line.strip() for line in urls_path.read_text(encoding="utf-8", errors="replace").splitlines()]
    js_urls = sorted({url for url in urls if classify_url(url) == "javascript"})[: ctx.policy.limits.max_js_files]
    atomic_write_text(ctx.current / "javascript-urls.txt", "".join(f"{url}\n" for url in js_urls))
    if not js_urls:
        for filename in ("new-js-files.txt", "changed-js-files.txt", "semantic-js-changes.txt", "new-js-indicators.tsv"):
            atomic_write_text(ctx.changes / filename, "")
        return {"files": 0, "downloaded": 0, "new": 0, "raw_changed": 0, "semantic_changed": 0, "indicators": 0, "diffs": 0}

    workers = min(50, max(1, ctx.policy.limits.js_workers))
    work_queue = WorkQueue(ctx.db, ctx.run_id, ctx.policy.name, "javascript-items", ctx.db_writer)
    pending_urls = [url for url in js_urls if not work_queue.completed(url)]
    work_ids = {url: work_queue.enqueue(url, {"kind": "download_url", "url": url, "allowed_roots": ctx.policy.roots}) for url in pending_urls}
    for url, work_id in work_ids.items():
        ctx.db.work_start(work_id, "local-js")
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_download_url, ctx, url, ctx.policy.limits.max_js_bytes): url for url in pending_urls}
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                ctx.db.work_fail(work_ids[url], str(exc), retry=True)
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
    diff_dir = ctx.changes / "js-diffs"
    diff_dir.mkdir(parents=True, exist_ok=True)

    for result in sorted(results, key=lambda x: x["url"]):
        url = result["url"]
        if "data" not in result:
            errors.append({"url": url, "error": str(result.get("error", "download failed"))})
            if url in work_ids:
                ctx.db.work_fail(work_ids[url], str(result.get("error", "download failed")), retry=True)
            continue
        data = result["data"]
        content_type = str(result.get("content_type", "")).lower()
        if content_type and not any(token in content_type for token in ("javascript", "ecmascript", "text/plain", "application/octet-stream", "application/json")):
            errors.append({"url": url, "error": f"unexpected content-type: {content_type}"})
            continue
        downloaded += 1
        raw_hash = sha256_bytes(data)
        text = data.decode("utf-8", "replace")
        semantic_hash = sha256_text(semantic_js_normalize(text))
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

        if source_map_url and ctx.policy.url_in_scope(source_map_url) and ctx.policy.raw.get("javascript", {}).get("download_source_maps", True):
            map_result = _download_url(ctx, source_map_url, ctx.policy.limits.max_js_bytes)
            if "data" in map_result:
                map_data = map_result["data"]
                map_hash, map_path, _ = ContentAddressedStore(ctx.paths, ctx.db).put(map_data, content_type="application/json")
                maps_downloaded += 1
                with contextlib.suppress(json.JSONDecodeError):
                    source_map = json.loads(map_data.decode("utf-8", "replace"))
                    for source_name in source_map.get("sources", [])[:5000]:
                        value = str(source_name)[:500]
                        if ctx.db.upsert_js_indicator(ctx.policy.name, url, "source_map_source", value, False, ctx.run_id):
                            indicator_count += 1
                            indicator_lines.append(f"source_map_source\t{value}\t{url}")
        if url in work_ids:
            ctx.db.work_finish(work_ids[url], {"raw_hash": raw_hash, "semantic_hash": semantic_hash, "object_hash": object_hash})

    atomic_write_text(ctx.changes / "new-js-files.txt", "".join(f"{x}\n" for x in new_files))
    atomic_write_text(ctx.changes / "changed-js-files.txt", "".join(f"{x}\n" for x in changed_files))
    atomic_write_text(ctx.changes / "semantic-js-changes.txt", "".join(f"{x}\n" for x in semantic_changes))
    atomic_write_text(ctx.changes / "new-js-indicators.tsv", "".join(f"{x}\n" for x in sorted(indicator_lines)))
    write_jsonl(ctx.current / "javascript-errors.jsonl", errors)
    return {
        "files": len(js_urls),
        "downloaded": downloaded,
        "new": len(new_files),
        "raw_changed": len(changed_files),
        "semantic_changed": len(semantic_changes),
        "indicators": indicator_count,
        "classified_endpoints": classified_endpoints,
        "diffs": diff_count,
        "source_maps": maps_downloaded,
        "errors": len(errors),
    }



def _safe_validate_endpoint(ctx: StageContext, endpoint: str) -> dict[str, Any]:
    candidates: list[str] = []
    normalized = normalize_url(endpoint)
    if normalized and ctx.policy.url_in_scope(normalized):
        candidates.append(normalized)
    elif endpoint.startswith("/"):
        for root in ctx.policy.roots:
            candidates.append(normalize_url(f"https://{root}{endpoint}") or "")
    candidates = [url for url in candidates if url and ctx.policy.url_in_scope(url)]
    if not candidates:
        return {"endpoint": endpoint, "skipped": "not a safe in-scope HTTP endpoint"}
    last_error = ""
    for url in candidates[:3]:
        if ctx.budget:
            ctx.budget.consume("http_requests", 1)
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Recon-Monitor/3.0", **ctx.policy.headers})
        try:
            with urllib.request.urlopen(request, timeout=min(10, ctx.policy.limits.timeout_seconds)) as response:
                status = int(getattr(response, "status", 0) or 0)
                ctype = str(response.headers.get("Content-Type", ""))[:200]
                return {"endpoint": endpoint, "resolved_url": url, "method": "HEAD", "status_code": status, "content_type": ctype, "reachable": True, "confidence": 90}
        except urllib.error.HTTPError as exc:
            status = int(exc.code or 0)
            return {"endpoint": endpoint, "resolved_url": url, "method": "HEAD", "status_code": status, "content_type": str(exc.headers.get("Content-Type", ""))[:200] if exc.headers else "", "reachable": True, "confidence": 80}
        except Exception as exc:
            last_error = str(exc)
    return {"endpoint": endpoint, "resolved_url": candidates[0], "method": "HEAD", "status_code": 0, "content_type": "", "reachable": False, "confidence": 30, "error": last_error}

def stage_endpoint_validation(ctx: StageContext) -> dict[str, Any]:
    if not ctx.policy.modules.get("endpoint_validation", False):
        return {"skipped": "disabled"}
    rows = ctx.db.all("SELECT endpoint,kind,confidence FROM endpoint_intelligence WHERE target=? ORDER BY confidence DESC LIMIT ?", (ctx.policy.name, min(1000, ctx.policy.limits.max_urls)))
    queue = WorkQueue(ctx.db, ctx.run_id, ctx.policy.name, "endpoint-validation-items", ctx.db_writer)
    pending = [str(r["endpoint"]) for r in rows if not queue.completed(str(r["endpoint"]))]
    workers = min(10, max(1, ctx.policy.limits.http_workers // 4))
    results: list[dict[str, Any]] = []
    def run(endpoint: str) -> dict[str, Any]:
        work_id = queue.enqueue(endpoint, {"kind": "http_head", "url": endpoint, "allowed_roots": ctx.policy.roots})
        ctx.db.work_start(work_id, "local-validation")
        try:
            result = _safe_validate_endpoint(ctx, endpoint)
            ctx.db.work_finish(work_id, result)
            return result
        except Exception as exc:
            ctx.db.work_fail(work_id, str(exc), retry=True)
            return {"endpoint": endpoint, "error": str(exc), "reachable": False}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for index, result in enumerate(pool.map(run, pending), 1):
            results.append(result); ctx.progress.update(index, len(pending), f"reachable={sum(1 for r in results if r.get('reachable'))}")
    now = utc_now()
    for result in results:
        if result.get("skipped"): continue
        ctx.db.execute("INSERT INTO endpoint_validations(target,endpoint,resolved_url,method,status_code,content_type,reachable,confidence,checked_at,last_run_id,error) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(target,endpoint,resolved_url) DO UPDATE SET method=excluded.method,status_code=excluded.status_code,content_type=excluded.content_type,reachable=excluded.reachable,confidence=excluded.confidence,checked_at=excluded.checked_at,last_run_id=excluded.last_run_id,error=excluded.error", (ctx.policy.name,result.get("endpoint",""),result.get("resolved_url",""),result.get("method","HEAD"),result.get("status_code",0),result.get("content_type",""),int(bool(result.get("reachable"))),result.get("confidence",0),now,ctx.run_id,result.get("error","")))
        if result.get("reachable") and int(result.get("status_code",0)) in {200,201,202,204,401,403,405}:
            emit_event(ctx, "validated_endpoint", str(result.get("resolved_url")), "Extracted endpoint validated", result)
    write_jsonl(ctx.current / "endpoint-validations.jsonl", results)
    return {"candidates": len(rows), "checked": len(results), "reachable": sum(1 for r in results if r.get("reachable")), "errors": sum(1 for r in results if r.get("error"))}

def _tls_certificate_info(url: str, timeout: float = 5.0) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {}
    host = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
    except (OSError, ssl.SSLError, socket.timeout):
        return {}
    def flatten_name(value: Any) -> str:
        parts: list[str] = []
        for group in value or []:
            for key, item in group:
                parts.append(f"{key}={item}")
        return ", ".join(parts)
    sans = [str(item) for kind, item in cert.get("subjectAltName", []) if kind == "DNS"]
    return {
        "tls_issuer": flatten_name(cert.get("issuer")),
        "tls_expiry": str(cert.get("notAfter") or ""),
        "tls_sans": sorted(sans),
        "tls_serial": str(cert.get("serialNumber") or ""),
    }


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
    record = {
        "status_code": int(row.get("status_code") or 0),
        "title": str(row.get("title") or "")[:500],
        "webserver": str(row.get("webserver") or row.get("web_server") or "")[:300],
        "technologies": sorted(str(x) for x in tech),
        "content_type": str(row.get("content_type") or "")[:200],
        "content_length": int(row.get("content_length") or 0),
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
        "httpx", "-l", str(base_path), "-silent", "-json", "-duc", "-no-color",
        "-sc", "-cl", "-ct", "-location", "-title", "-server", "-td", "-ip", "-cname", "-cdn",
        "-hash", "sha256", "-jarm", "-http2", "-include-chain", "-fr",
        "-t", str(ctx.policy.limits.http_threads),
        "-rl", str(ctx.policy.limits.request_rate),
        "-timeout", str(min(30, max(5, ctx.policy.limits.timeout_seconds // 20))),
        "-retries", "1",
    ]
    args.extend(header_args(ctx.policy.headers))
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
            "-t", str(ctx.policy.limits.http_threads), "-rl", str(ctx.policy.limits.request_rate),
            "-timeout", "10", "-retries", "1",
        ] + header_args(ctx.policy.headers)
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
            record.update(_tls_certificate_info(url))
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
                "status_code", "title", "webserver", "technologies", "content_type", "body_hash",
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
        if ctx.db.upsert_port(ctx.policy.name, host, ip, port, protocol, ctx.run_id):
            new_ports += 1
            emit_event(ctx, "new_port", f"{host}:{port}/{protocol}", "New open port", {"host": host, "ip": ip, "port": port, "protocol": protocol})
    ctx.db.finalize_ports_current(ctx.policy.name, ctx.run_id)
    return {"open_ports": total, "new": new_ports, "ports": ports}


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
    args.extend(header_args(ctx.policy.headers))
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
