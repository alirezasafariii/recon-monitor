from __future__ import annotations

import sys, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; APP=ROOT/'app'
if str(APP) not in sys.path: sys.path.insert(0,str(APP))
import real_world_corpus_v1_review_package as package


def drafts():
    rows=[]
    for i in range(100):
        for variant in ('positive','secure_negative','sparse_noisy'):
            rows.append({'draft_id':f'd{i}-{variant}','case_origin_id':f'origin-{i}','variant':variant,'review':{'family':None,'label':None,'human_verified':False}})
    return rows

class ReviewPackageTests(unittest.TestCase):
    def test_balances_300_records_across_three_slots(self):
        result=package.shard(drafts())
        self.assertTrue(result['passed'])
        self.assertEqual(sum(result['slot_record_counts'].values()),300)
        self.assertEqual(sum(result['slot_origin_counts'].values()),100)
        self.assertLessEqual(result['maximum_slot_record_share'],0.40)
        self.assertEqual(result['origin_overlap_count'],0)
        self.assertEqual(result['actual_human_reviewer_count'],0)

    def test_all_variants_of_origin_stay_together(self):
        result=package.shard(drafts())
        origin_slots={}
        for slot,rows in result['assignments'].items():
            for row in rows:
                origin_slots.setdefault(row['case_origin_id'],set()).add(slot)
        self.assertTrue(all(len(slots)==1 for slots in origin_slots.values()))

    def test_slots_do_not_claim_human_identity_or_labels(self):
        result=package.shard(drafts())
        for slot,rows in result['assignments'].items():
            for row in rows:
                self.assertEqual(row['review_packet_slot'],slot)
                self.assertIsNone(row['reviewer_id'])
                self.assertFalse(row['review_packet_assignment_is_human_identity'])
                self.assertIsNone(row['review']['label'])
                self.assertFalse(row['review']['human_verified'])

if __name__=='__main__': unittest.main()
