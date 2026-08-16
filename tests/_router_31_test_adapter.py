from __future__ import annotations

"""Adapter for legacy family-analyzer tests after the canonical catalog expands.

The historical files still exercise each analyzer in detail. Only their duplicated
router-size assertion is replaced with the current single-source 31-family
contract, so the old behavior tests remain unchanged.
"""

import importlib.util
import unittest
from pathlib import Path
from typing import Any


def _router_catalog_contract(self: unittest.TestCase) -> None:
    from family_analyzers.router import analyzer_for_family, router_status
    from family_reasoning import FAMILY_ORDER

    status = router_status()
    self.assertEqual(status["target_family_count"], len(FAMILY_ORDER))
    self.assertEqual(status["registered_count"], len(FAMILY_ORDER))
    self.assertEqual(status["pending_count"], 0)
    self.assertEqual(status["registered"], list(FAMILY_ORDER))
    self.assertEqual(status["pending"], [])
    self.assertFalse(status["generic_family_analyzer_fallback"])
    for family in FAMILY_ORDER:
        self.assertIsNotNone(analyzer_for_family(family), family)


def load_adapted_tests(wrapper_file: str) -> dict[str, Any]:
    wrapper = Path(wrapper_file)
    legacy = wrapper.with_name(f"_{wrapper.stem}_legacy.py")
    module_name = f"_legacy_{wrapper.stem}"
    spec = importlib.util.spec_from_file_location(module_name, legacy)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load legacy test module: {legacy}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    exported: dict[str, Any] = {}
    for name, obj in vars(module).items():
        if not isinstance(obj, type) or not issubclass(obj, unittest.TestCase):
            continue
        if obj.__module__ != module.__name__:
            continue
        for method_name in list(vars(obj)):
            if method_name.startswith("test_router"):
                setattr(obj, method_name, _router_catalog_contract)
        exported[name] = obj
    return exported
