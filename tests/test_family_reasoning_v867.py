from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_path = Path(__file__).with_name("_family_reasoning_v867_legacy.py")
_spec = importlib.util.spec_from_file_location("_family_reasoning_v867_legacy", _path)
_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_mod)


def _test_catalog_exactly_covers_all_candidate_families(self):
    from bug_candidates import BUG_FAMILIES
    from family_reasoning import FAMILY_ORDER, FAMILY_REASONING, catalog_audit
    self.assertEqual(len(BUG_FAMILIES), len(FAMILY_ORDER))
    self.assertEqual(set(BUG_FAMILIES), set(FAMILY_ORDER))
    self.assertEqual(set(BUG_FAMILIES), set(FAMILY_REASONING))
    audit = catalog_audit(BUG_FAMILIES)
    self.assertTrue(audit["complete"], audit)
    self.assertEqual(audit["actual_count"], len(FAMILY_ORDER))
    self.assertEqual(audit["missing"], [])
    self.assertEqual(audit["unexpected"], [])
    self.assertEqual(audit["invalid"], [])

_mod.FamilyReasoningV867Tests.test_catalog_exactly_covers_all_candidate_families = _test_catalog_exactly_covers_all_candidate_families
FamilyReasoningV867Tests = _mod.FamilyReasoningV867Tests

if __name__ == "__main__": unittest.main()
