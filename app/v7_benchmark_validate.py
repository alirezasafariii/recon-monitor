from __future__ import annotations

import json,re
from collections import defaultdict
from typing import Any,Iterable,Mapping
from family_detectors.registry import DETECTOR_SPECS
from raw_recon_v4_corpus import V4_FORBIDDEN_RAW_KEYS,V4_VALID_METHODS
from raw_recon_v7_source_firewall import validate_shortlist

VERSION='1.0.0';RULE_VERSION='2026.08.14.6.32.v7.1'
SINGLE={'positive','near_miss','secure_negative','sparse_noisy'};PAIR={'dual_positive','a_only','b_only','dual_secure'};TRIAD={'triple_positive','ab_only','c_only','triple_secure','sparse_interference'}
SUSPICIOUS={'trace_id','fixture_id','label','family','expected_family','expected_families'}
def _n(v:Any)->str:return str(v or '').strip()
def _id(v:Any)->str:return _n(v).casefold()
def _canon(v:Any)->str:return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def _keys(v:Any)->set[str]:
    out=set()
    if isinstance(v,Mapping):
        for k,c in v.items():out.add(_n(k));out|=_keys(c)
    elif isinstance(v,list):
        for c in v:out|=_keys(c)
    return out
def _scalars(v:Any,path:tuple[str,...]=())->list[tuple[tuple[str,...],str]]:
    out=[]
    if isinstance(v,Mapping):
        for k,c in v.items():out+=_scalars(c,path+(_n(k),))
    elif isinstance(v,list):
        for i,c in enumerate(v):out+=_scalars(c,path+(str(i),))
    elif isinstance(v,(str,int,float,bool)):out.append((path,_n(v)))
    return out
def _marker(marker:str,text:str)->bool:
    m=_id(marker);t=_id(text);return bool(m and t and re.search(rf'(?<![a-z0-9]){re.escape(m)}(?![a-z0-9])',t))
def _observation(raw:Mapping[str,Any],cid:str,expected:set[str],errors:list[str],leakage:dict[str,list[str]])->None:
    if not _n(raw.get('target')):errors.append(f'{cid}: target missing')
    if not _n(raw.get('endpoint')):errors.append(f'{cid}: endpoint missing')
    if _n(raw.get('method')).upper() not in V4_VALID_METHODS:errors.append(f'{cid}: invalid method')
    if not isinstance(raw.get('endpoint_schema',{}),Mapping):errors.append(f'{cid}: endpoint_schema must object')
    if not isinstance(raw.get('details',{}),Mapping):errors.append(f'{cid}: details must object')
    hits=set();keys={_id(x) for x in _keys(raw)};hits|={f'key:{x}' for x in keys & {_id(x) for x in V4_FORBIDDEN_RAW_KEYS}}
    markers=set(DETECTOR_SPECS)
    for spec in DETECTOR_SPECS.values():markers.update(str(x) for x in spec.condition_signals)
    markers.update(expected)
    for path,scalar in _scalars(raw):
        leaf=_id(path[-1]) if path else ''
        for m in markers:
            if _marker(m,scalar):hits.add(f"value:{'.'.join(path)}:{m}")
        if leaf in SUSPICIOUS:
            for f in DETECTOR_SPECS:
                if f[:8] and f[:8] in _id(scalar):hits.add(f"derived-id:{'.'.join(path)}:{f[:8]}")
    if hits:leakage[cid]=sorted(hits);errors.append(f'{cid}: benchmark labels leaked into raw')
def _expected_source(by:Mapping[str,Mapping[str,Any]],group:list[str])->tuple[str,str]:return '+'.join(str(by[f]['source_root']) for f in group),'+'.join(str(by[f]['source_project']) for f in group)

def validate_v7_corpus(cases:Iterable[Mapping[str,Any]],shortlist:Mapping[str,Any],*,require_literal_single_capture:bool=True)->dict[str,Any]:
    rows=[dict(x) for x in cases];selected=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)];fw=validate_shortlist(selected,required_count=36);errors=list(fw.get('errors') or []);leakage={};seen=set();singles=defaultdict(list);pairs=defaultdict(list);triads=defaultdict(list);literal=0
    by={_n(x.get('family')):x for x in selected}
    if set(by)!=set(DETECTOR_SPECS):errors.append('v7 shortlist family coverage mismatch')
    for row in rows:
        cid=_n(row.get('id'))
        if not cid or cid in seen:errors.append(f'duplicate/missing id {cid!r}')
        seen.add(cid);expected=row.get('expected') if isinstance(row.get('expected'),Mapping) else {};ef={_n(x) for x in expected.get('admitted_families') or [] if _n(x)};top={_n(x) for x in row.get('expected_families') or [] if _n(x)}
        if top!=ef:errors.append(f'{cid}: expected family mismatch')
        cmap=expected.get('condition_signals') if isinstance(expected.get('condition_signals'),Mapping) else {}
        if {_n(x) for x in cmap}!=ef:errors.append(f'{cid}: expected condition family mismatch')
        conditions=set()
        for family,vals in cmap.items():
            f=_n(family);sup={_n(x) for x in vals or [] if _n(x)}
            if f not in DETECTOR_SPECS or sup-set(DETECTOR_SPECS[f].condition_signals):errors.append(f'{cid}: noncanonical expected condition')
            conditions|=sup
        mode=_n(row.get('case_mode'));kind=_n(row.get('case_kind'))
        if mode=='single_family_fresh_v7':
            f=_n(row.get('family'))
            if f not in by:errors.append(f'{cid}: family absent');continue
            if kind not in SINGLE:errors.append(f'{cid}: invalid single variant')
            if ef!=({f} if kind=='positive' else set()):errors.append(f'{cid}: single expected mismatch')
            if _id(row.get('source_root'))!=_id(by[f].get('source_root')) or _id(row.get('source_project'))!=_id(by[f].get('source_project')):errors.append(f'{cid}: single source drift')
            prov=row.get('provenance') if isinstance(row.get('provenance'),Mapping) else {}
            if prov.get('literal_capture') is True:literal+=1
            elif require_literal_single_capture:errors.append(f'{cid}: single is not literal capture')
            for fld in ('v6_first_blind_score_used','v6_first_blind_case_errors_used'):
                if prov.get(fld) is not False:errors.append(f'{cid}: provenance contamination {fld}')
            raw=row.get('raw') if isinstance(row.get('raw'),Mapping) else {};_observation(raw,cid,conditions,errors,leakage);singles[_id(row.get('source_root'))].append(row)
        elif mode=='2_family_interference_v7':
            group=[_n(x) for x in row.get('paired_families') or [] if _n(x)]
            if kind not in PAIR or len(group)!=2 or len(set(group))!=2 or any(f not in by for f in group):errors.append(f'{cid}: invalid pair')
            else:
                r,p=_expected_source(by,group)
                if _id(row.get('source_root'))!=_id(r) or _id(row.get('source_project'))!=_id(p):errors.append(f'{cid}: pair source drift')
            obs=[x for x in row.get('raw_observations') or [] if isinstance(x,Mapping)]
            if len(obs)!=2:errors.append(f'{cid}: pair needs 2 observations')
            for i,raw in enumerate(obs):_observation(raw,f'{cid}#obs{i+1}',conditions,errors,leakage)
            wanted={'dual_positive':set(group),'a_only':{group[0]} if len(group)==2 else set(),'b_only':{group[1]} if len(group)==2 else set(),'dual_secure':set()}
            if kind in wanted and ef!=wanted[kind]:errors.append(f'{cid}: pair expected mismatch')
            pairs['+'.join(group)].append(row)
        elif mode=='3_family_interference_v7':
            group=[_n(x) for x in row.get('triad_families') or [] if _n(x)]
            if kind not in TRIAD or len(group)!=3 or len(set(group))!=3 or any(f not in by for f in group):errors.append(f'{cid}: invalid triad')
            else:
                r,p=_expected_source(by,group)
                if _id(row.get('source_root'))!=_id(r) or _id(row.get('source_project'))!=_id(p):errors.append(f'{cid}: triad source drift')
            obs=[x for x in row.get('raw_observations') or [] if isinstance(x,Mapping)]
            if len(obs)!=3:errors.append(f'{cid}: triad needs 3 observations')
            for i,raw in enumerate(obs):_observation(raw,f'{cid}#obs{i+1}',conditions,errors,leakage)
            wanted={'triple_positive':set(group),'ab_only':set(group[:2]),'c_only':{group[2]} if len(group)==3 else set(),'triple_secure':set(),'sparse_interference':set()}
            if kind in wanted and ef!=wanted[kind]:errors.append(f'{cid}: triad expected mismatch')
            triads['+'.join(group)].append(row)
        else:errors.append(f'{cid}: invalid case_mode {mode!r}')
    for root,group in singles.items():
        if len(group)!=4 or {_n(x.get('case_kind')) for x in group}!=SINGLE:errors.append(f'{root}: single variant mismatch')
        if len({_canon(x.get('raw')) for x in group})!=len(group):errors.append(f'{root}: single raw collision')
    pair_members=[]
    for key,group in pairs.items():
        if len(group)!=4 or {_n(x.get('case_kind')) for x in group}!=PAIR:errors.append(f'{key}: pair variant mismatch')
        if group:pair_members += [_n(x) for x in group[0].get('paired_families') or []]
        if len({_canon(x.get('raw_observations')) for x in group})!=len(group):errors.append(f'{key}: pair collision')
    triad_members=[]
    for key,group in triads.items():
        if len(group)!=5 or {_n(x.get('case_kind')) for x in group}!=TRIAD:errors.append(f'{key}: triad variant mismatch')
        if group:triad_members += [_n(x) for x in group[0].get('triad_families') or []]
        if len({_canon(x.get('raw_observations')) for x in group})!=len(group):errors.append(f'{key}: triad collision')
    if sorted(pair_members)!=sorted(DETECTOR_SPECS):errors.append('v7 pairs must cover all families once')
    if sorted(triad_members)!=sorted(DETECTOR_SPECS):errors.append('v7 triads must cover all families once')
    if (len(rows),len(singles),len(pairs),len(triads))!=(276,36,18,12):errors.append('v7 corpus cardinality failed')
    if require_literal_single_capture and literal!=144:errors.append(f'v7 requires 144 literal singles: {literal}')
    return {'validator_version':VERSION,'validator_rule_version':RULE_VERSION,'passed':not errors,'errors':errors,'case_count':len(rows),'single_case_count':sum(len(x) for x in singles.values()),'pair_case_count':sum(len(x) for x in pairs.values()),'triad_case_count':sum(len(x) for x in triads.values()),'single_source_count':len(singles),'pair_group_count':len(pairs),'triad_group_count':len(triads),'literal_single_capture_count':literal,'literal_single_capture_required':require_literal_single_capture,'label_leakage_count':len(leakage),'label_leakage_cases':leakage,'source_firewall':fw,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False}
