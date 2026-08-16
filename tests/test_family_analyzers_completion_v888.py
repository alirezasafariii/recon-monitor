from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_path = Path(__file__).with_name("_family_analyzers_completion_v888_legacy.py")
_spec = importlib.util.spec_from_file_location("_family_analyzers_completion_v888_legacy", _path)
_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_mod)


def _test_router_is_complete_without_fallback(self):
    from family_analyzers.router import analyzer_for_family, router_status
    from family_reasoning import FAMILY_ORDER
    status = router_status()
    self.assertEqual(status["registered_count"], len(FAMILY_ORDER))
    self.assertEqual(status["pending_count"], 0)
    self.assertEqual(status["registered"], list(FAMILY_ORDER))
    self.assertEqual(status["pending"], [])
    self.assertFalse(status["generic_family_analyzer_fallback"])
    for family in FAMILY_ORDER:
        self.assertIsNotNone(analyzer_for_family(family), family)

_mod.RemainingFamilyCompletionV888Tests.test_router_is_21_of_21_without_fallback = _test_router_is_complete_without_fallback
RemainingFamilyCompletionV888Tests = _mod.RemainingFamilyCompletionV888Tests

if __name__ == "__main__": unittest.main()
