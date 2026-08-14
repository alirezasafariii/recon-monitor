from __future__ import annotations

"""Shard pending Corpus V1 drafts into three balanced human-review packets.

Assignment is label blind and source-origin grouped: all variants from one
case_origin_id stay with one reviewer slot. Slots are placeholders only; this
module never claims that a human reviewer exists and never fills reviewer_id,
family, label, evidence quality, or human_verified.
"""

import argparse, hashlib, json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

VERSION="1.0.0"
RULE_VERSION="2026.08.14.14"
SLOTS=("reviewer_slot_1","reviewer_slot_2","reviewer_slot_3")


def text(v:Any)->str: return str(v or "").strip()

def stable_key(origin:str)->str: return hashlib.sha256(origin.encode()).hexdigest()


def shard(drafts:list[dict[str,Any]])->dict[str,Any]:
    by_origin:dict[str,list[dict[str,Any]]]=defaultdict(list)
    for row in drafts:
        origin=text(row.get("case_origin_id"))
        if not origin: raise ValueError("missing_case_origin_id")
        by_origin[origin].append(dict(row))
    assignments={slot:[] for slot in SLOTS}; counts={slot:0 for slot in SLOTS}
    for origin in sorted(by_origin,key=lambda x:(stable_key(x),x)):
        slot=min(SLOTS,key=lambda s:(counts[s],s))
        rows=sorted(by_origin[origin],key=lambda r:(text(r.get("variant")),text(r.get("draft_id"))))
        for row in rows:
            review=row.get("review") if isinstance(row.get("review"),Mapping) else {}
            if review.get("label") is not None or review.get("family") is not None or bool(review.get("human_verified")):
                raise ValueError("draft_already_reviewed")
            row["review_packet_slot"]=slot
            row["reviewer_id"]=None
            row["review_packet_assignment_is_human_identity"]=False
            assignments[slot].append(row)
        counts[slot]+=len(rows)
    origin_sets={slot:{text(r.get("case_origin_id")) for r in rows} for slot,rows in assignments.items()}
    overlap=set()
    for i,a in enumerate(SLOTS):
        for b in SLOTS[i+1:]: overlap |= origin_sets[a]&origin_sets[b]
    all_rows=[r for slot in SLOTS for r in assignments[slot]]
    total=len(all_rows); max_share=max(counts.values())/total if total else 0.0
    errors=[]
    if total!=len(drafts): errors.append("record_count_changed")
    if overlap: errors.append("origin_crosses_reviewer_slots")
    if max_share>0.40: errors.append("reviewer_slot_share_above_40_percent")
    if any(r.get("review",{}).get("label") is not None for r in all_rows): errors.append("label_prefilled")
    if any(bool(r.get("review",{}).get("human_verified")) for r in all_rows): errors.append("human_verified_prefilled")
    return {"version":VERSION,"rule_version":RULE_VERSION,"evaluation_kind":"real_world_corpus_v1_pending_human_review_shards","passed":not errors,"errors":errors,"slot_record_counts":counts,"slot_origin_counts":{s:len(origin_sets[s]) for s in SLOTS},"maximum_slot_record_share":round(max_share,6),"origin_overlap_count":len(overlap),"actual_human_reviewer_count":0,"human_labels_created":False,"assignments":assignments}


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--queue",default="benchmarks/real_world/v1/human_review_queue.json"); ap.add_argument("--output-dir",default="benchmarks/real_world/v1/review_packets"); ap.add_argument("--report",default="benchmarks/real_world/v1/review_packet_report.json"); args=ap.parse_args()
    payload=json.loads(Path(args.queue).read_text()); result=shard([dict(x) for x in payload["drafts"]]); out=Path(args.output_dir); out.mkdir(parents=True,exist_ok=True)
    for slot,rows in result["assignments"].items():
        packet={"slot":slot,"slot_is_not_human_identity":True,"human_verified_record_count":0,"review_instructions":{"fill_family_after_source_review":True,"fill_label_after_evidence_review":True,"fill_reviewer_id_with_real_human_identity":True,"fill_reviewed_at":True,"fill_all_seven_evidence_quality_dimensions":True,"do_not_change_evidence_snapshot_id":True},"drafts":rows}; (out/f"{slot}.json").write_text(json.dumps(packet,indent=2,sort_keys=True)+"\n")
    report={k:v for k,v in result.items() if k!="assignments"}; Path(args.report).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,sort_keys=True)); return 0 if result["passed"] else 1

if __name__=="__main__": raise SystemExit(main())
