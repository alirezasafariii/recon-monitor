"""Strict, bounded dig observations for optional wildcard enrichment only."""
from __future__ import annotations

import ipaddress
import re
import time

from core import normalize_host, tool_path, valid_domain
from execution import BudgetExceeded

RESOLVER = "8.8.8.8"
MAX_QUERIES = 128


def parse_response(text: str, host: str, rrtype: str):
    """Return an RRset only for a complete matching response; None is unknown."""
    if len(text) > 65536:
        return None
    headers = re.findall(r'^;; ->>HEADER<<- opcode: QUERY, status: ([A-Z]+), id: \d+\s*$', text, re.M)
    flags = re.findall(r'^;; flags: ([^;]+);', text, re.M)
    questions = re.findall(r'^;([^;\s]+)\s+IN\s+([A-Z]+)\s*$', text, re.M)
    server = re.findall(r'^;; SERVER: (\S+)', text, re.M)
    counts = re.findall(r'QUERY: (\d+), ANSWER: (\d+), AUTHORITY: (\d+), ADDITIONAL: (\d+)', text)
    if (len(headers) != 1 or len(flags) != 1 or 'qr' not in flags[0].split()
            or 'tc' in flags[0].split() or len(questions) != 1
            or normalize_host(questions[0][0]) != host or questions[0][1] != rrtype
            or server != [RESOLVER + '#53(' + RESOLVER + ')']
            or headers[0] not in {'NOERROR', 'NXDOMAIN'}
            or len(counts) != 1 or counts[0][0] != '1'):
        return None
    section = ''
    answers = []
    soa = []
    authority_count = 0
    for line in text.splitlines():
        if line.startswith(';; ') and line.endswith(' SECTION:'):
            section = line[3:-9]
        elif line and not line.startswith(';'):
            fields = line.split()
            if section not in {'ANSWER', 'AUTHORITY'}:
                return None
            if section in {'ANSWER', 'AUTHORITY'}:
                if len(fields) < 5 or not fields[1].isdigit() or fields[2] != 'IN':
                    return None
                owner = normalize_host(fields[0])
                if not valid_domain(owner):
                    return None
                if section == 'ANSWER':
                    answers.append((owner, fields[3], fields[4:]))
                else:
                    authority_count += 1
                    if fields[3] == 'SOA':
                        if (len(fields) != 11 or not all(v.isdigit() for v in fields[6:])
                                or not valid_domain(normalize_host(fields[4]))):
                            return None
                        soa.append(owner)
    if int(counts[0][1]) != len(answers) or int(counts[0][2]) != authority_count:
        return None
    terminal = host
    seen = set()
    for _ in range(16):
        links = [v for owner, typ, v in answers if owner == terminal and typ == 'CNAME']
        if not links:
            break
        if len(links) != 1 or len(links[0]) != 1:
            return None
        if rrtype == 'CNAME':
            value = normalize_host(links[0][0])
            return (value,) if headers[0] == 'NOERROR' and valid_domain(value) else None
        if terminal in seen:
            return None
        seen.add(terminal)
        terminal = normalize_host(links[0][0])
        if not valid_domain(terminal):
            return None
    else:
        return None
    values = []
    for owner, typ, raw in answers:
        if owner != terminal or typ != rrtype:
            continue
        if len(raw) != 1:
            return None
        try:
            ip = ipaddress.ip_address(raw[0])
            if ip.version != (4 if rrtype == 'A' else 6):
                return None
            values.append(str(ip))
        except ValueError:
            return None
    if values:
        return tuple(sorted(set(values))) if headers[0] == 'NOERROR' else None
    # Negative observations require the resolver's explicit authority evidence.
    if any(terminal == zone or terminal.endswith('.' + zone) for zone in soa):
        return ()
    return None


def fill_missing(ctx, expected, rrtype, values, index, repeat, state):
    outcomes = []
    dig = tool_path('dig')
    if not dig:
        return outcomes, 0
    used = 0
    for host in sorted(expected - values.keys()):
        if state['used'] >= MAX_QUERIES or ctx.next_requested():
            break
        if not ctx.policy.host_in_scope(host):
            continue
        if not ctx.budget and state['reserved'] >= ctx.policy.limits.max_dns_queries:
            break
        try:
            if ctx.budget:
                ctx.budget.consume('dns_queries', 1)
        except BudgetExceeded:
            break
        state['used'] += 1
        state['reserved'] += 1
        used += 1
        interval = 1 / max(1, ctx.policy.limits.dns_rate)
        delay = interval - (time.monotonic() - state.get('last', 0))
        if delay > 0:
            time.sleep(delay)
        state['last'] = time.monotonic()
        output = ctx.current / f'dns-explicit-{index}-{repeat}-{rrtype.lower()}-{state["used"]}.txt'
        result = ctx.runner.run(
            [dig, '@' + RESOLVER, host, rrtype, '+tries=1', '+timeout=2',
             '+ignore', '+noall', '+comments', '+question', '+answer', '+authority', '+stats'],
            timeout=min(5, ctx.policy.limits.timeout_seconds), output_path=output,
            # BIND/Apple dig reads ~/.digrc only when HOME is present. Remove
            # it in the child environment, without touching the parent or file.
            env_unset=('HOME',),
            heartbeat=lambda: ctx.db.stage_heartbeat(ctx.run_id, ctx.policy.name, 'dns'),
        )
        observation = None
        if (result.returncode == 0 and not getattr(result, 'timed_out', False)
                and output.is_file() and output.stat().st_size <= 65536):
            observation = parse_response(output.read_text(errors='replace'), host, rrtype)
        if observation is not None:
            values[host] = observation
        outcomes.append({'source': 'dig', 'host': host, 'rrtype': rrtype,
                         'round': repeat, 'resolver': RESOLVER, 'raw_artifact': output.name,
                         'exit_code': result.returncode,
                         'timed_out': bool(getattr(result, 'timed_out', False)),
                         'stop_reason': 'completed' if observation is not None else 'unknown',
                         'observation': observation})
    return outcomes, used
