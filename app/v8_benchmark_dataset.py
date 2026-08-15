from __future__ import annotations

import copy, hashlib, json
from collections import defaultdict
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from family_reasoners import FAMILY_REASONER_PROFILES
from raw_recon_corpus import ROOT

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v8.1'
SHORTLIST=ROOT/'benchmarks/raw/sources/v8_shortlist.json'; CAPTURES=ROOT/'benchmarks/raw/sources/v8_literal_captures.jsonl'
CORPUS=ROOT/'benchmarks/raw/analysis_raw_v8.jsonl'; REPORT=ROOT/'benchmarks/raw/sources/v8_materialization_report.json'
VARIANTS=('positive','near_miss','secure_negative','sparse_noisy')

def _canon(v:Any)->str:return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def _sha_json(v:Any)->str:return hashlib.sha256(_canon(v).encode()).hexdigest()
def _id(v:Any)->str:return str(v or '').strip().casefold()
def _relation(a:str,b:str)->int:return 2*int(b in FAMILY_REASONER_PROFILES[a].confounders)+2*int(a in FAMILY_REASONER_PROFILES[b].confounders)
def _groups(size:int)->list[tuple[str,...]]:
    remaining=set(DETECTOR_SPECS);groups=[]
    while remaining:
        seed=max(sorted(remaining),key=lambda n:sum(_relation(n,o) for o in remaining if o!=n));chosen=[seed];remaining.remove(seed)
        while len(chosen)<size:
            c=max(sorted(remaining),key=lambda n:(sum(_relation(n,m) for m in chosen),n));chosen.append(c);remaining.remove(c)
        groups.append(tuple(chosen))
    return groups

def _load()->list[dict[str,Any]]:
    if not CAPTURES.exists():raise RuntimeError('v8 literal capture set missing')
    return [json.loads(x) for x in CAPTURES.read_text().splitlines() if x.strip()]

def _validate(row:Mapping[str,Any],selected:Mapping[str,Mapping[str,Any]])->dict[str,Any]:
    family=str(row.get('family') or '');kind=str(row.get('case_kind') or '')
    if family not in selected or kind not in VARIANTS:raise RuntimeError(f'v8 invalid capture {family}/{kind}')
    src=selected[family]
    if _id(row.get('source_root'))!=_id(src.get('source_root')) or _id(row.get('source_project'))!=_id(src.get('source_project')):raise RuntimeError(f'{family}/{kind}: shortlist drift')
    raw=row.get('raw') if isinstance(row.get('raw'),Mapping) else None
    if not raw:raise RuntimeError(f'{family}/{kind}: raw missing')
    for k in ('target','endpoint','method','endpoint_schema','details'):
        if k not in raw:raise RuntimeError(f'{family}/{kind}: raw.{k} required')
    prov=row.get('provenance') if isinstance(row.get('provenance'),Mapping) else {}
    if prov.get('literal_capture') is not True:raise RuntimeError(f'{family}/{kind}: literal provenance required')
    for field in ('detector_output_used','admission_output_used','ranking_output_used','v6_first_blind_score_used','v6_first_blind_case_errors_used'):
        if prov.get(field) is not False:raise RuntimeError(f'{family}/{kind}: provenance.{field} must be false')
    signals=[str(x) for x in row.get('expected_condition_signals') or [] if str(x)]
    if set(signals)-set(DETECTOR_SPECS[family].condition_signals):raise RuntimeError(f'{family}/{kind}: noncanonical signal')
    if kind=='positive' and not signals:raise RuntimeError(f'{family}: positive signal required')
    if kind!='positive' and signals:raise RuntimeError(f'{family}/{kind}: non-positive signal forbidden')
    n=dict(row);n['raw']=copy.deepcopy(dict(raw));n['provenance']={**dict(prov),'literal_capture':True,'capture_sha256':_sha_json(raw)};n['expected_condition_signals']=signals;return n

def _expected(families:list[str],pos:Mapping[str,Mapping[str,Any]])->dict[str,Any]:
    return {'admitted_families':list(families),'condition_signals':{f:list(pos[f].get('expected_condition_signals') or []) for f in families}}
def _single(c:Mapping[str,Any],pos:Mapping[str,Mapping[str,Any]])->dict[str,Any]:
    f=str(c['family']);k=str(c['case_kind']);expected=[f] if k=='positive' else []
    return {'id':f"v8-{c['source_root']}-{k}",'source_root':c['source_root'],'source_project':c['source_project'],'source_date':c.get('source_date') or c['provenance'].get('captured_at'),'family':f,'expected_families':expected,'case_kind':k,'case_mode':'single_family_fresh_v8','rank_required':k!='sparse_noisy','provenance':copy.deepcopy(c['provenance']),'raw':copy.deepcopy(c['raw']),'expected':_expected(expected,pos)}
def _composite(caps:Mapping[str,Mapping[str,Mapping[str,Any]]],pos:Mapping[str,Mapping[str,Any]],size:int)->list[dict[str,Any]]:
    groups=_groups(size);cases=[]
    variants=(('dual_positive',('positive','positive'),(0,1)),('a_only',('positive','secure_negative'),(0,)),('b_only',('secure_negative','positive'),(1,)),('dual_secure',('secure_negative','secure_negative'),())) if size==2 else (('triple_positive',('positive','positive','positive'),(0,1,2)),('ab_only',('positive','positive','secure_negative'),(0,1)),('c_only',('secure_negative','secure_negative','positive'),(2,)),('triple_secure',('secure_negative','secure_negative','secure_negative'),()),('sparse_interference',('near_miss','sparse_noisy','near_miss'),()))
    for idx,group in enumerate(groups,1):
        for kind,kinds,expected_idx in variants:
            selected=[caps[f][kinds[p]] for p,f in enumerate(group)];expected=[group[p] for p in expected_idx]
            cases.append({'id':f'v8-g{size}-{idx:02d}-{kind}','source_root':'+'.join(str(x['source_root']) for x in selected),'source_project':'+'.join(str(x['source_project']) for x in selected),'source_date':max(str(x.get('source_date') or x['provenance'].get('captured_at') or '') for x in selected),'family':group[0],('paired_families' if size==2 else 'triad_families'):list(group),'expected_families':expected,'case_kind':kind,'case_mode':f'{size}_family_interference_v8','rank_required':bool(expected),'provenance':{'composite':True,'literal_capture':True,'composition_only':True,'sources':[copy.deepcopy(x['provenance']) for x in selected]},'raw_observations':[copy.deepcopy(x['raw']) for x in selected],'expected':_expected(expected,pos)})
    return cases

def materialize()->dict[str,Any]:
    shortlist=json.loads(SHORTLIST.read_text());rows=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)];selected={str(x.get('family') or ''):x for x in rows}
    if len(rows)!=36 or set(selected)!=set(DETECTOR_SPECS) or shortlist.get('scoring_executed') is not False:raise RuntimeError('v8 shortlist invalid/unscored boundary failed')
    literal=[_validate(x,selected) for x in _load()];by=defaultdict(dict)
    for row in literal:
        f=str(row['family']);k=str(row['case_kind'])
        if k in by[f]:raise RuntimeError(f'{f}: duplicate {k}')
        by[f][k]=row
    if set(by)!=set(DETECTOR_SPECS):raise RuntimeError('v8 capture family coverage mismatch')
    for f,v in by.items():
        if set(v)!=set(VARIANTS) or len({_sha_json(v[k]['raw']) for k in VARIANTS})!=4:raise RuntimeError(f'{f}: four distinct variants required')
    pos={f:v['positive'] for f,v in by.items()};singles=[_single(by[f][k],pos) for f in sorted(by) for k in VARIANTS];pairs=_composite(by,pos,2);triads=_composite(by,pos,3);cases=singles+pairs+triads
    if (len(singles),len(pairs),len(triads),len(cases))!=(144,72,60,276):raise RuntimeError('v8 materialization cardinality failed')
    CORPUS.write_text('\n'.join(_canon(x) for x in cases)+'\n')
    r={'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v8_literal_raw_materialization_unscored','fresh_raw_claim':True,'raw_capture_mode':'literal_source_capture','literal_single_capture_count':144,'input_capture_count':len(literal),'single_case_count':144,'pair_case_count':72,'triad_case_count':60,'case_count':276,'family_count':36,'pair_groups':[list(x) for x in _groups(2)],'triad_groups':[list(x) for x in _groups(3)],'shortlist_sha256':hashlib.sha256(SHORTLIST.read_bytes()).hexdigest(),'literal_capture_input_sha256':hashlib.sha256(CAPTURES.read_bytes()).hexdigest(),'corpus_sha256':hashlib.sha256(CORPUS.read_bytes()).hexdigest(),'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False};REPORT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');return r

def main()->int:print(json.dumps(materialize(),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
