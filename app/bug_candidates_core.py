from __future__ import annotations

"""Canonical Candidate Engine compatibility surface.

The historical implementation is isolated in ``bug_candidates_legacy_core``.
Its runtime family-evidence schema is replaced immediately with the canonical
21-family map from ``family_reasoning`` before any candidate generation runs.

Dynamic proxies preserve the existing integration behavior: ``bug_candidates``
may replace ``record_hypothesis``, ``_evidence_strength`` and
``_static_candidates`` on this module, while functions defined in the legacy
implementation resolve those replacements through this compatibility surface.
"""

from typing import Any

import bug_candidates_legacy_core as _legacy
from family_reasoning import candidate_evidence_schema_map

for _name, _value in vars(_legacy).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

# Runtime single source of truth. The historical implementation never gets to
# use its embedded compatibility table.
FAMILY_EVIDENCE_SCHEMAS: dict[str, dict[str, Any]] = candidate_evidence_schema_map()
_legacy.FAMILY_EVIDENCE_SCHEMAS = FAMILY_EVIDENCE_SCHEMAS

_ORIGINAL_RECORD_HYPOTHESIS = record_hypothesis
_ORIGINAL_EVIDENCE_STRENGTH = _evidence_strength
_ORIGINAL_STATIC_CANDIDATES = _static_candidates


def _record_hypothesis_proxy(*args: Any, **kwargs: Any) -> Any:
    return globals()["record_hypothesis"](*args, **kwargs)


def _evidence_strength_proxy(*args: Any, **kwargs: Any) -> Any:
    return globals()["_evidence_strength"](*args, **kwargs)


def _static_candidates_proxy(*args: Any, **kwargs: Any) -> Any:
    return globals()["_static_candidates"](*args, **kwargs)


# Functions in bug_candidates_legacy_core keep that module as their globals.
# Route the three intentionally replaceable hooks back through this module so
# the existing dedicated-family integration continues to work unchanged.
_legacy.record_hypothesis = _record_hypothesis_proxy
_legacy._evidence_strength = _evidence_strength_proxy
_legacy._static_candidates = _static_candidates_proxy

__all__ = [name for name in globals() if not name.startswith("__")]
