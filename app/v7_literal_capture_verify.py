from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import validate_shortlist
from v7_literal_capture_plan import ALLOWED_CAPTURE_METHODS, EVIDENCE_ROOT, VARIANTS

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.1'
SHORTLIST=ROOT/'benchmarks/raw/sources/v7_shortlist.json'
CAPTURES=ROOT/'benchmarks/raw/sources/v7_literal_captures.jsonl'
LABEL_SCHEMA=ROOT/'benchmarks/raw/sources/v7_literal_label_schema.json'
REPORT=ROOT/'benchmarks/raw/sources/v7_literal_capture_verification.json'
SHA_RE=re.compile(r'^[0-9a-f]{64}$')
ALLOWED_BASES={'source_observation','upstream_regression','patched_control','source_log_or_trace','repository_test_fixture'}


def _canon(v:Any)->str:return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def _sha_json(v:Any)->str:return hashlib.sha256(_canon(v).encode()).hexdigest()
def _sha_bytes(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _id(v:Any)->str:return str(v or '').strip().casefold()
def _ts(v:Any)->bool:
    raw=str(v or '').strip()
    try:return bool(raw and datetime.fromisoformat(raw.replace('Z','+00:00')).tzinfo)
    except:return False


def _selected()->tuple[dict[str,dict[str,Any]],dict[str,Any]]:
    doc=json.loads(SHORTLIST.read_text()); rows=[dict(x) for x in doc.get('selected') or [] if isinstance(x,Mapping)]
    by={str(x.get('family') or ''):x for x in rows}
    if len(rows)!=36 or set(by)!=set(DETECTOR_SPECS):raise RuntimeError('v7 shortlist must cover exactly 36 families')
    if doc.get('scoring_executed') is not False or doc.get('first_blind_consumed') is not False:raise RuntimeError('v7 shortlist must remain unscored')
    if doc.get('selection_uses_v6_first_blind_score') is not False or doc.get('selection_uses_v6_first_blind_case_errors') is not False:raise RuntimeError('v7 shortlist contaminated by v6 result')
    fw=validate_shortlist(rows)
    if not fw['passed']:raise RuntimeError('v7 shortlist no longer passes v1-v6 firewall: '+repr(fw['errors']))
    return by,doc


def _labels()->dict[str,set[str]]:
    doc=json.loads(LABEL_SCHEMA.read_text()); fams=doc.get('families') if isinstance(doc.get('families'),Mapping) else {}
    if doc.get('family_count')!=36 or set(fams)!=set(DETECTOR_SPECS):raise RuntimeError('v7 label schema drift')
    if doc.get('detector_output_used') is not False or doc.get('admission_output_used') is not False or doc.get('ranking_output_used') is not False:raise RuntimeError('v7 label schema contaminated by engine output')
    return {family:set(str(x) for x in (row.get('condition_signals') or [])) for family,row in fams.items() if isinstance(row,Mapping)}


def verify(*,require_complete:bool=True,write_report:bool=False)->dict[str,Any]:
    errors=[]
    if not CAPTURES.exists():
        result={'passed':not require_complete,'errors':['v7 literal captures missing'] if require_complete else [],'capture_count':0,'evidence_count':0,'family_count':0,'scoring_executed':False}
        if write_report:REPORT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return result
    selected,_=_selected(); labels=_labels(); rows=[json.loads(x) for x in CAPTURES.read_text().splitlines() if x.strip()]
    variants=defaultdict(set); raw_hashes=defaultdict(set); evidence_paths=set(); evidence_hashes=set(); manifest={}
    for i,row in enumerate(rows,1):
        family=str(row.get('family') or ''); kind=str(row.get('case_kind') or ''); cid=f'{family}/{kind}'
        if family not in selected or kind not in VARIANTS:errors.append(f'{cid}: invalid family/variant');continue
        if kind in variants[family]:errors.append(f'{cid}: duplicate variant')
        variants[family].add(kind); src=selected[family]
        if _id(row.get('source_root'))!=_id(src.get('source_root')):errors.append(f'{cid}: source_root drift')
        if _id(row.get('source_project'))!=_id(src.get('source_project')):errors.append(f'{cid}: source_project drift')
        raw=row.get('raw') if isinstance(row.get('raw'),Mapping) else None
        if not raw:errors.append(f'{cid}: raw missing');continue
        raw_sha=_sha_json(raw);raw_hashes[family].add(raw_sha)
        signals=[str(x) for x in row.get('expected_condition_signals') or [] if str(x)]
        if len(signals)!=len(set(signals)):errors.append(f'{cid}: duplicate expected signals')
        if set(signals)-labels[family]:errors.append(f'{cid}: noncanonical expected signal')
        if kind=='positive' and not signals:errors.append(f'{cid}: positive expected signals missing')
        if kind!='positive' and signals:errors.append(f'{cid}: non-positive expected signals forbidden')
        p=row.get('provenance') if isinstance(row.get('provenance'),Mapping) else {}
        for field in ('detector_output_used','admission_output_used','ranking_output_used','v6_first_blind_score_used','v6_first_blind_case_errors_used'):
            if p.get(field) is not False:errors.append(f'{cid}: provenance.{field} must be false')
        if p.get('literal_capture') is not True:errors.append(f'{cid}: literal_capture must be true')
        ref=str(p.get('capture_reference') or '');method=str(p.get('capture_method') or '');captured=str(p.get('captured_at') or '')
        if not ref.startswith('https://'):errors.append(f'{cid}: https capture reference required')
        if method not in ALLOWED_CAPTURE_METHODS:errors.append(f'{cid}: invalid capture method')
        if not _ts(captured):errors.append(f'{cid}: timezone timestamp required')
        declared=str(p.get('raw_sha256') or '').lower()
        if not SHA_RE.fullmatch(declared) or declared!=raw_sha:errors.append(f'{cid}: raw hash mismatch')
        rel=str(p.get('evidence_path') or ''); ep=(ROOT/rel).resolve()
        try:ep.relative_to(EVIDENCE_ROOT.resolve())
        except:errors.append(f'{cid}: evidence path escapes v7 root');continue
        if ep.suffix.lower()!='.json':errors.append(f'{cid}: evidence must be json');continue
        if rel in evidence_paths:errors.append(f'{cid}: evidence path reused')
        evidence_paths.add(rel)
        if not ep.exists():errors.append(f'{cid}: evidence file missing');continue
        eh=_sha_bytes(ep.read_bytes()); evidence_hashes.add(eh);manifest[rel]=eh
        if str(p.get('evidence_sha256') or '').lower()!=eh:errors.append(f'{cid}: evidence hash mismatch')
        evidence=json.loads(ep.read_text())
        if not isinstance(evidence,Mapping):errors.append(f'{cid}: evidence object required');continue
        for key,expected in [('family',family),('case_kind',kind),('source_root',row.get('source_root')),('source_project',row.get('source_project')),('capture_reference',ref),('capture_method',method)]:
            if _id(evidence.get(key))!=_id(expected):errors.append(f'{cid}: evidence.{key} drift')
        if _canon(evidence.get('raw'))!=_canon(raw) or evidence.get('raw_sha256')!=raw_sha:errors.append(f'{cid}: raw/evidence binding mismatch')
        adj=evidence.get('adjudication') if isinstance(evidence.get('adjudication'),Mapping) else {}
        if str(adj.get('basis') or '') not in ALLOWED_BASES:errors.append(f'{cid}: invalid adjudication basis')
        if not str(adj.get('notes') or '').strip():errors.append(f'{cid}: adjudication notes missing')
        for field in ('detector_output_used','admission_output_used','ranking_output_used','v6_first_blind_score_used','v6_first_blind_case_errors_used'):
            if adj.get(field) is not False:errors.append(f'{cid}: adjudication.{field} must be false')
        es=[str(x) for x in adj.get('expected_condition_signals') or [] if str(x)]
        if es!=signals:errors.append(f'{cid}: expected signals differ between capture/evidence')
        snap=evidence.get('source_snapshot') if isinstance(evidence.get('source_snapshot'),Mapping) else {}
        if _id(snap.get('reference'))!=_id(ref) or 'payload' not in snap:errors.append(f'{cid}: snapshot binding missing')
        ss=_sha_json(snap.get('payload')); declared_ss=str(snap.get('content_sha256') or '').lower()
        if ss!=declared_ss or not SHA_RE.fullmatch(declared_ss):errors.append(f'{cid}: snapshot hash mismatch')
        if str(p.get('source_snapshot_sha256') or '').lower()!=declared_ss:errors.append(f'{cid}: provenance snapshot hash mismatch')
    if require_complete:
        if len(rows)!=144:errors.append(f'v7 capture count must be 144: {len(rows)}')
        if set(variants)!=set(DETECTOR_SPECS):errors.append('v7 family coverage mismatch')
        for family in DETECTOR_SPECS:
            if variants.get(family,set())!=set(VARIANTS):errors.append(f'{family}: variant coverage mismatch')
            if len(raw_hashes.get(family,set()))!=4:errors.append(f'{family}: four distinct raw hashes required')
        if len(evidence_paths)!=144:errors.append(f'evidence path count must be 144: {len(evidence_paths)}')
        if len(evidence_hashes)!=144:errors.append(f'unique evidence hash count must be 144: {len(evidence_hashes)}')
    result={'verifier_version':VERSION,'verifier_rule_version':RULE_VERSION,'passed':not errors,'errors':errors,'capture_count':len(rows),'evidence_count':len(evidence_paths),'unique_evidence_hash_count':len(evidence_hashes),'family_count':len(variants),'evidence_manifest':dict(sorted(manifest.items())),'scoring_executed':False,'first_blind_consumed':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False}
    if write_report:REPORT.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--partial',action='store_true');p.add_argument('--write-report',action='store_true');a=p.parse_args();r=verify(require_complete=not a.partial,write_report=a.write_report);print(json.dumps({k:r[k] for k in ('passed','capture_count','evidence_count','family_count','scoring_executed')},sort_keys=True));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
