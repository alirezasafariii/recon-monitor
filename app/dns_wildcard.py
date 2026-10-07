"""Bounded DNS wildcard candidates from explicit random-name observations.

Candidate means a host shares an observed wildcard response, not that the host
is nonexistent. Nothing here retires DNS records or excludes downstream input.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
from collections import defaultdict
from pathlib import Path

from core import atomic_write_text, normalize_host, valid_domain, write_jsonl
from execution import BudgetExceeded
from dns_explicit import RESOLVER, fill_missing

TYPES = (("A", "-a"), ("AAAA", "-aaaa"), ("CNAME", "-cname"))
CONTROL_COUNT = 3
ROUNDS = 2
MAX_PARENTS = 16
MAX_HOSTS = 128


def observations(path: Path, expected: set[str], rrtype: str):
    """Missing, malformed and conflicting rows are unknown, never negative."""
    rows = defaultdict(set)
    invalid = set()
    warnings = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError()
        except (ValueError, TypeError):
            warnings += 1
            continue
        host = normalize_host(str(row.get("host") or row.get("input") or ""))
        if host not in expected:
            warnings += 1
            continue
        status = str(row.get("status_code") or row.get("rcode") or "").upper()
        raw = row.get(rrtype.lower(), row.get(rrtype, []))
        if isinstance(raw, str):
            raw = [raw]
        try:
            if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
                raise ValueError()
            values = tuple(sorted(set(x.strip().lower().rstrip(".") for x in raw)))
            if rrtype in {"A", "AAAA"}:
                values = tuple(sorted({str(ipaddress.ip_address(x)) for x in values}))
                if any(ipaddress.ip_address(x).version != (4 if rrtype == "A" else 6) for x in values):
                    raise ValueError()
            elif any(not valid_domain(x) for x in values):
                raise ValueError()
            if row.get("error") or status not in {"", "NOERROR", "NODATA", "NXDOMAIN"}:
                raise ValueError()
            if status in {"NXDOMAIN", "NODATA"} and values:
                raise ValueError()
            if not values and status not in {"NOERROR", "NODATA", "NXDOMAIN"}:
                raise ValueError()
            rows[host].add(values)
        except ValueError:
            invalid.add(host)
    # Any collector warning makes this query's evidence unsuitable to classify.
    return ({h: next(iter(v)) for h, v in rows.items()
             if len(v) == 1 and h not in invalid} if not warnings else {}), warnings


def classify(host: str, controls: list[str], rounds: list[dict]):
    def stable(name, rrtype):
        values = [r.get(rrtype, {}).get(name) for r in rounds]
        return values[0] if len(values) == ROUNDS and None not in values and len(set(values)) == 1 else None
    candidate = {t: stable(host, t) for t, _ in TYPES}
    baseline = {}
    for t, _ in TYPES:
        values = [stable(c, t) for c in controls]
        baseline[t] = values[0] if None not in values and len(set(values)) == 1 else None
    if all(baseline[t] == () for t, _ in TYPES) and any(candidate[t] for t, _ in TYPES):
        return "non_wildcard", "explicit_negative_controls"
    # A known distinct CNAME prevents an address-only match on shared CDN IPs.
    if (candidate["CNAME"] is not None and baseline["CNAME"] is not None
            and candidate["CNAME"] != baseline["CNAME"]):
        return "unknown", "distinct_cname_with_shared_surface"
    if candidate["CNAME"] and candidate["CNAME"] == baseline["CNAME"]:
        return "wildcard_candidate", "stable_random_control_cname_match"
    if any(candidate[t] is not None and baseline[t] is not None
           and candidate[t] != baseline[t] for t, _ in TYPES):
        return "unknown", "distinct_known_response_profile"
    for t in ("A", "AAAA"):
        if candidate[t] and candidate[t] == baseline[t]:
            # Multiple independent random names, repeated observations and an
            # exact RRset match are required, not merely a shared IP overlap.
            return "wildcard_candidate", "stable_random_control_address_match"
    return "unknown", "missing_conflicting_or_variable_observations"


def detect(ctx, hosts):
    reports = {h: {"host": h, "state": "unknown", "reason": "not_probed"} for h in hosts}
    outcomes = []
    grouped = defaultdict(list)
    for host in sorted(hosts):
        if host in ctx.policy.roots:
            reports[host].update(reason="root_not_a_wildcard_synthesis_candidate", state="not_applicable")
            continue
        parent = host.split(".", 1)[1]
        if any(parent == r or parent.endswith("." + r) for r in ctx.policy.roots):
            grouped[parent].append(host)
    reserved = 0
    fallback_state = {'used': 0, 'reserved': 0}
    local_limit = max(0, ctx.policy.limits.max_dns_queries - len(hosts) * 4)
    used_hosts = 0
    for index, (parent, members) in enumerate(sorted(grouped.items())):
        if index >= MAX_PARENTS or used_hosts + len(members) > MAX_HOSTS:
            for h in members:
                reports[h]["reason"] = "probe_limit"
            continue
        controls = [f"recon-wc-{secrets.token_hex(12)}.{parent}" for _ in range(CONTROL_COUNT)]
        expected = set(members + controls)
        if any(not valid_domain(h) or not ctx.policy.host_in_scope(h) for h in expected) or len(expected) != len(members) + CONTROL_COUNT:
            for h in members:
                reports[h]["reason"] = "control_scope_or_collision"
            continue
        cost = len(expected) * len(TYPES) * ROUNDS
        remaining = local_limit - reserved
        if ctx.budget:
            budget = ctx.budget.snapshot().get("dns_queries", {})
            limit = budget.get("limit", ctx.policy.limits.max_dns_queries)
            remaining = limit - budget.get("used", 0) if limit else cost
        if cost > remaining:
            for h in members:
                reports[h]["reason"] = "probe_budget"
            continue
        try:
            if ctx.budget:
                ctx.budget.consume("dns_queries", cost)
        except BudgetExceeded:
            for h in members:
                reports[h]["reason"] = "probe_budget"
            continue
        reserved += cost
        fallback_state['reserved'] = len(hosts) * 4 + reserved
        used_hosts += len(members)
        input_path = ctx.current / f"dns-wildcard-{index}-input.txt"
        atomic_write_text(input_path, "".join(h + "\n" for h in sorted(expected)))
        rounds = []
        runtime_exhausted = False
        for repeat in range(ROUNDS):
            evidence = {}
            for rrtype, flag in TYPES:
                output = ctx.current / f"dns-wildcard-{index}-{repeat}-{rrtype.lower()}.jsonl"
                if ctx.budget and not runtime_exhausted:
                    try:
                        ctx.budget.check_runtime()
                    except BudgetExceeded:
                        runtime_exhausted = True
                if runtime_exhausted:
                    evidence[rrtype] = {}
                    outcomes.append({"parent": parent, "round": repeat, "rrtype": rrtype, "stop_reason": "runtime_budget"})
                    continue
                output.unlink(missing_ok=True)
                result = ctx.runner.run(
                    ["dnsx", "-l", str(input_path), "-silent", "-json", "-omit-raw", flag,
                     "-rcode", "noerror,nxdomain", "-retry", "1", "-duc", "-r", RESOLVER,
                     "-t", str(min(200, ctx.policy.limits.dns_rate)), "-rl", str(ctx.policy.limits.dns_rate)],
                    timeout=ctx.policy.limits.timeout_seconds, output_path=output,
                    heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, "dns"),
                )
                stop = "completed" if result.returncode == 0 and not getattr(result, "timed_out", False) and output.is_file() else "collector_failure"
                values, warnings = observations(output, expected, rrtype) if stop == "completed" else ({}, 0)
                # Retry only omissions from an otherwise clean collector invocation.
                # Warning/timeout/failure remains unknown rather than being concealed.
                if stop == 'completed' and not warnings and not ctx.next_requested():
                    reported = set()
                    for line in output.read_text(errors='replace').splitlines():
                        try:
                            row = json.loads(line)
                            if isinstance(row, dict):
                                reported.add(normalize_host(str(row.get('host') or row.get('input') or '')))
                        except ValueError:
                            pass
                    # Explicit error/conflict/malformed rows must stay unknown.
                    # A fallback is only for names omitted entirely by dnsx.
                    extra, cost_used = fill_missing(ctx, expected - reported, rrtype, values,
                                                    index, repeat, fallback_state)
                    outcomes.extend(extra)
                    reserved += cost_used
                evidence[rrtype] = values
                outcomes.append({"parent": parent, "round": repeat, "rrtype": rrtype,
                                 "stop_reason": stop, "exit_code": result.returncode,
                                 "timed_out": bool(getattr(result, "timed_out", False)),
                                 "duration_seconds": float(getattr(result, "duration", 0)),
                                 "input_hosts": len(expected), "observed_hosts": len(values), "collector_warnings": warnings})
            rounds.append(evidence)
        for host in members:
            state, reason = classify(host, controls, rounds)
            reports[host].update(state=state, reason=reason, parent=parent,
                                 controls=controls, observations=[
                                     {t: {name: value for name, value in r.get(t, {}).items()
                                          if name in controls or name == host} for t, _ in TYPES}
                                     for r in rounds
                                 ])
    rows = [reports[h] for h in sorted(reports)]
    write_jsonl(ctx.current / "dns-wildcard-evidence.jsonl", rows)
    return rows, outcomes, reserved
