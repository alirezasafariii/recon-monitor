from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT

VERSION = '1.0.0'
RULE_VERSION = '2026.08.14.6.32.v7.1'
SHORTLIST = ROOT / 'benchmarks/raw/sources/v7_shortlist.json'
OUTPUT = ROOT / 'benchmarks/raw/sources/v7_literal_source_research.json'
GHSA_RE = re.compile(r'^GHSA-[0-9a-z-]+$', re.I)
MAX_BYTES = 2 * 1024 * 1024


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def _api_url(reference: str) -> str | None:
    parsed=urlparse(reference)
    if parsed.scheme!='https' or parsed.netloc.casefold()!='github.com':
        return None
    p=[x for x in parsed.path.split('/') if x]
    if len(p)==2 and p[0].casefold()=='advisories' and GHSA_RE.fullmatch(p[1]):
        return f'https://api.github.com/advisories/{p[1]}'
    if len(p)>=4:
        owner,repo=p[0],p[1]
        if p[2]=='issues' and p[3].isdigit(): return f'https://api.github.com/repos/{owner}/{repo}/issues/{p[3]}'
        if p[2]=='pull' and p[3].isdigit(): return f'https://api.github.com/repos/{owner}/{repo}/pulls/{p[3]}'
        if p[2]=='commit' and p[3]: return f'https://api.github.com/repos/{owner}/{repo}/commits/{p[3]}'
        if len(p)>=5 and p[2]=='security' and p[3]=='advisories' and GHSA_RE.fullmatch(p[4]):
            return f'https://api.github.com/repos/{owner}/{repo}/security-advisories/{p[4]}'
    return None


def _request(url: str, token: str | None) -> tuple[int, Any, str | None]:
    headers={'Accept':'application/vnd.github+json','User-Agent':'recon-monitor-analysis-632-v7-passive-research','X-GitHub-Api-Version':'2022-11-28'}
    if token: headers['Authorization']=f'Bearer {token}'
    req=urllib.request.Request(url,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=30) as r:
            raw=r.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES: return int(r.status),None,'snapshot too large'
            return int(r.status),json.loads(raw.decode('utf-8')),None
    except urllib.error.HTTPError as exc:
        return int(exc.code),None,f'HTTP {exc.code}: '+exc.read().decode('utf-8',errors='replace')[:1500]
    except Exception as exc:
        return 0,None,f'{type(exc).__name__}: {exc}'


def _links(payload: Mapping[str, Any]) -> list[str]:
    out=set()
    for key in ('html_url','repository_advisory_url','source_code_location'):
        v=payload.get(key)
        if isinstance(v,str) and v.startswith('https://'): out.add(v)
    for v in payload.get('references') or []:
        if isinstance(v,str) and v.startswith('https://'): out.add(v)
    body=str(payload.get('body') or payload.get('description') or '')
    for m in re.findall(r'https://[^\s)\]>'\"]+',body): out.add(m.rstrip('.,;:'))
    return sorted(out)


def build(token: str | None=None) -> dict[str, Any]:
    shortlist=json.loads(SHORTLIST.read_text())
    if shortlist.get('scoring_executed') is not False or shortlist.get('first_blind_consumed') is not False:
        raise RuntimeError('v7 shortlist must remain unscored/unconsumed')
    if shortlist.get('selection_uses_v6_first_blind_score') is not False or shortlist.get('selection_uses_v6_first_blind_case_errors') is not False:
        raise RuntimeError('v7 shortlist contaminated by v6 result')
    rows=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)]
    if len(rows)!=36: raise RuntimeError(f'expected 36 v7 sources, got {len(rows)}')
    entries=[]
    for row in sorted(rows,key=lambda x:str(x.get('family') or '')):
        ref=str(row.get('canonical_advisory_url') or row.get('repository_advisory_url') or row.get('source_code_location') or '').strip()
        api=_api_url(ref)
        if not api:
            status,payload,error=0,None,'v7 canonical source is not a supported GitHub reference'
        else:
            status,payload,error=_request(api,token)
            if status==403 and token:
                status,payload,error=_request(api,None)
        pm=payload if isinstance(payload,Mapping) else {}
        entries.append({
            'family':row.get('family'),'source_root':row.get('source_root'),'source_project':row.get('source_project'),
            'canonical_reference':ref,'github_api_reference':api,'fetch_status':status,'fetch_error':error,
            'snapshot_payload':payload,'snapshot_sha256':_sha(payload) if payload is not None else None,
            'discovered_upstream_links':_links(pm),'has_body_or_description':bool(pm.get('body') or pm.get('description')),
            'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'scoring_executed':False,
        })
    good=[x for x in entries if x['fetch_status']==200 and x['snapshot_payload'] is not None]
    bad=[x for x in entries if x not in good]
    return {
        'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_passive_public_source_research_unscored',
        'collected_at':datetime.now(timezone.utc).isoformat(),'family_count':36,'successful_snapshot_count':len(good),
        'successful_families':sorted(str(x['family']) for x in good),'unresolved_snapshot_count':len(bad),
        'unresolved_sources':[{k:x.get(k) for k in ('family','source_root','source_project','canonical_reference','fetch_status','fetch_error')} for x in bad],
        'entries':entries,'active_target_validation_performed':False,'detector_output_used':False,'admission_output_used':False,
        'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,
        'scoring_executed':False,'first_blind_consumed':False,
    }


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('--require-all',action='store_true'); a=p.parse_args()
    r=build(os.environ.get('GITHUB_TOKEN')); OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:r[k] for k in ('family_count','successful_snapshot_count','unresolved_snapshot_count','scoring_executed')},sort_keys=True))
    return 1 if a.require_all and r['successful_snapshot_count']!=36 else 0


if __name__=='__main__': raise SystemExit(main())
