from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT

VERSION = '1.0.3'
RULE_VERSION = '2026.08.15.6.32.v8.33'
SHORTLIST = ROOT / 'benchmarks/raw/sources/v8_shortlist.json'
OUTPUT = ROOT / 'benchmarks/raw/sources/v8_literal_source_research.json'
GHSA_RE = re.compile(r'^GHSA-[0-9a-z-]+$', re.I)
MAX_BYTES = 2 * 1024 * 1024


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _api_url(reference: str) -> str | None:
    parsed = urlparse(reference)
    if parsed.scheme != 'https' or parsed.netloc.casefold() != 'github.com':
        return None
    parts = [value for value in parsed.path.split('/') if value]
    if len(parts) == 2 and parts[0].casefold() == 'advisories' and GHSA_RE.fullmatch(parts[1]):
        return f'https://api.github.com/advisories/{parts[1]}'
    if len(parts) >= 4:
        owner, repo = parts[0], parts[1]
        if parts[2] == 'issues' and parts[3].isdigit():
            return f'https://api.github.com/repos/{owner}/{repo}/issues/{parts[3]}'
        if parts[2] == 'pull' and parts[3].isdigit():
            return f'https://api.github.com/repos/{owner}/{repo}/pulls/{parts[3]}'
        if parts[2] == 'commit' and parts[3]:
            return f'https://api.github.com/repos/{owner}/{repo}/commits/{parts[3]}'
        if len(parts) >= 5 and parts[2] == 'security' and parts[3] == 'advisories' and GHSA_RE.fullmatch(parts[4]):
            return f'https://api.github.com/repos/{owner}/{repo}/security-advisories/{parts[4]}'
    return None


def _request(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'recon-monitor-analysis-632-v8-passive-research',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                return int(response.status), None, 'snapshot too large'
            return int(response.status), json.loads(raw.decode('utf-8')), None
    except urllib.error.HTTPError as exc:
        return int(exc.code), None, f'HTTP {exc.code}: ' + exc.read().decode('utf-8', errors='replace')[:1500]
    except Exception as exc:
        return 0, None, f'{type(exc).__name__}: {exc}'


def _links(payload: Mapping[str, Any]) -> list[str]:
    out: set[str] = set()
    for key in ('html_url', 'repository_advisory_url', 'source_code_location'):
        value = payload.get(key)
        if isinstance(value, str) and value.startswith('https://'):
            out.add(value)
    for value in payload.get('references') or []:
        if isinstance(value, str) and value.startswith('https://'):
            out.add(value)
    body = str(payload.get('body') or payload.get('description') or '')
    for match in re.findall(r"https://[^\s)\]>'\"]+", body):
        out.add(match.rstrip('.,;:'))
    return sorted(out)


def build(token: str | None = None) -> dict[str, Any]:
    shortlist = json.loads(SHORTLIST.read_text())
    if shortlist.get('scoring_executed') is not False or shortlist.get('first_blind_consumed') is not False:
        raise RuntimeError('v8 shortlist must remain unscored/unconsumed')
    if shortlist.get('selection_uses_v6_first_blind_score') is not False or shortlist.get('selection_uses_v6_first_blind_case_errors') is not False:
        raise RuntimeError('v8 shortlist contaminated by v6 result')
    rows = [dict(item) for item in shortlist.get('selected') or [] if isinstance(item, Mapping)]
    if len(rows) != 36:
        raise RuntimeError(f'expected 36 v8 sources, got {len(rows)}')

    entries = []
    for row in sorted(rows, key=lambda item: str(item.get('family') or '')):
        reference = str(row.get('canonical_advisory_url') or row.get('repository_advisory_url') or row.get('source_code_location') or '').strip()
        upstream = str(row.get('upstream_repository_reference') or '').strip()
        if not upstream.startswith('https://github.com/'):
            raise RuntimeError(f"{row.get('family')}: selected v8 source lacks upstream repository reference")
        api = _api_url(reference)
        if not api:
            status, payload, error = 0, None, 'v8 canonical source is not a supported GitHub reference'
        else:
            status, payload, error = _request(api, token)
            if status == 403 and token:
                status, payload, error = _request(api, None)
        payload_map = payload if isinstance(payload, Mapping) else {}
        entries.append({
            'family': row.get('family'),
            'source_root': row.get('source_root'),
            'source_project': row.get('source_project'),
            'canonical_reference': reference,
            'upstream_repository_reference': upstream,
            'github_api_reference': api,
            'fetch_status': status,
            'fetch_error': error,
            'snapshot_payload': payload,
            'snapshot_sha256': _sha(payload) if payload is not None else None,
            'discovered_upstream_links': _links(payload_map),
            'has_body_or_description': bool(payload_map.get('body') or payload_map.get('description')),
            'detector_output_used': False,
            'admission_output_used': False,
            'ranking_output_used': False,
            'v6_first_blind_score_used': False,
            'v6_first_blind_case_errors_used': False,
            'scoring_executed': False,
        })

    good = [item for item in entries if item['fetch_status'] == 200 and item['snapshot_payload'] is not None]
    bad = [item for item in entries if item not in good]
    return {
        'version': VERSION,
        'rule_version': RULE_VERSION,
        'evaluation_kind': 'fresh_blind_v8_passive_public_source_research_unscored',
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'family_count': 36,
        'successful_snapshot_count': len(good),
        'successful_families': sorted(str(item['family']) for item in good),
        'unresolved_snapshot_count': len(bad),
        'unresolved_sources': [
            {key: item.get(key) for key in ('family', 'source_root', 'source_project', 'canonical_reference', 'fetch_status', 'fetch_error')}
            for item in bad
        ],
        'entries': entries,
        'active_target_validation_performed': False,
        'detector_output_used': False,
        'admission_output_used': False,
        'ranking_output_used': False,
        'v6_first_blind_score_used': False,
        'v6_first_blind_case_errors_used': False,
        'scoring_executed': False,
        'first_blind_consumed': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-all', action='store_true')
    args = parser.parse_args()
    report = build(os.environ.get('GITHUB_TOKEN'))
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    summary = {key: report[key] for key in ('family_count', 'successful_snapshot_count', 'unresolved_snapshot_count', 'scoring_executed')}
    print(json.dumps(summary, sort_keys=True))
    if report['unresolved_sources']:
        print(json.dumps({'unresolved_sources': report['unresolved_sources']}, indent=2, sort_keys=True))
    return 1 if args.require_all and report['successful_snapshot_count'] != 36 else 0


if __name__ == '__main__':
    raise SystemExit(main())
