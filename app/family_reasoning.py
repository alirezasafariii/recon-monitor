from __future__ import annotations

"""Canonical Family Reasoning compatibility surface.

The original 21-family catalog lives in ``family_reasoning_core``. OWASP
expansion phase 1 and phase 2 extend that same catalog in place so every
existing consumer (admission, candidate schemas, case requirements and Safe
Validation) sees one canonical family source of truth.
"""

import family_reasoning_core as _core
from family_reasoning_final_analyzers import (
    FINAL_ANALYZER_REASONING_RULE_VERSION,
    FINAL_ANALYZER_REASONING_VERSION,
    apply_final_analyzer_reasoning,
)
from family_reasoning_owasp import (
    EXTENDED_FAMILY_REASONING,
    FAMILY_REASONING_EXTENSION_VERSION,
)
from family_reasoning_phase2 import (
    PHASE2_FAMILY_REASONING,
    FAMILY_REASONING_PHASE2_VERSION,
    FAMILY_REASONING_RULE_VERSION as _PHASE2_RULE_VERSION,
)
from owasp_family_catalog import NEW_FAMILY_ORDER
from owasp_phase2_catalog import PHASE2_FAMILY_ORDER

_existing = tuple(_core.FAMILY_ORDER)
_core.FAMILY_ORDER = _existing + tuple(
    family for family in tuple(NEW_FAMILY_ORDER) + tuple(PHASE2_FAMILY_ORDER)
    if family not in _existing
)
_core.FAMILY_REASONING.update(EXTENDED_FAMILY_REASONING)
_core.FAMILY_REASONING.update(PHASE2_FAMILY_REASONING)

# Families migrated into the final analyzer architecture may tighten historical
# admission contracts so Potential Findings require analyzer-owned target-side
# evidence rather than attack-surface structure alone.
apply_final_analyzer_reasoning(_core.FAMILY_REASONING)
_core.FAMILY_REASONING_VERSION = "3.1.0"
_core.FAMILY_REASONING_RULE_VERSION = FINAL_ANALYZER_REASONING_RULE_VERSION

for _name, _value in vars(_core).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

FAMILY_ORDER = _core.FAMILY_ORDER
FAMILY_REASONING = _core.FAMILY_REASONING
FAMILY_REASONING_VERSION = _core.FAMILY_REASONING_VERSION
FAMILY_REASONING_RULE_VERSION = _core.FAMILY_REASONING_RULE_VERSION

__all__ = [name for name in globals() if not name.startswith("__")]
