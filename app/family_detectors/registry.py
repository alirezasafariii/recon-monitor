from __future__ import annotations

from importlib import import_module
from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from family_evidence_extractors import scope_family_evidence
from .base import DETECTOR_ENGINE_VERSION, DETECTOR_RULE_VERSION, FamilyDetectorSpec, annotate_target_evidence

FAMILY_MODULES = tuple(sorted(FAMILY_ADMISSION_POLICIES))


def _load_specs() -> dict[str, FamilyDetectorSpec]:
    specs: dict[str, FamilyDetectorSpec] = {}
    for family in FAMILY_MODULES:
        module = import_module(f"family_detectors.{family}")
        spec = module.SPEC
        if spec.family != family:
            raise RuntimeError(f"detector module mismatch: {family} != {spec.family}")
        specs[family] = spec
    return specs


DETECTOR_SPECS = _load_specs()


def validate_detector_registry() -> list[str]:
    errors: list[str] = []
    policies = set(FAMILY_ADMISSION_POLICIES)
    specs = set(DETECTOR_SPECS)
    if policies != specs:
        errors.append(f"coverage mismatch missing={sorted(policies-specs)} extra={sorted(specs-policies)}")
    strategies = [spec.strategy for spec in DETECTOR_SPECS.values()]
    if len(strategies) != len(set(strategies)):
        errors.append("detector strategies must be unique per family")
    for family, spec in DETECTOR_SPECS.items():
        if not spec.wstg_ids:
            errors.append(f"{family}:missing_wstg")
        if not spec.owasp_ids:
            errors.append(f"{family}:missing_owasp")
        if not spec.cwe_ids:
            errors.append(f"{family}:missing_cwe")
        if not spec.writeups:
            errors.append(f"{family}:missing_writeup")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"{family}:external_knowledge_counted_as_evidence")
        unknown = set(spec.confounders) - policies
        if unknown:
            errors.append(f"{family}:unknown_confounders={sorted(unknown)}")
    return errors


_ERRORS = validate_detector_registry()
if _ERRORS:
    raise RuntimeError("Physical family detector registry invalid: " + "; ".join(_ERRORS))


def get_detector_spec(family: str) -> FamilyDetectorSpec:
    return DETECTOR_SPECS[family]


def detector_rule_ids(family: str) -> list[str]:
    spec = get_detector_spec(family)
    return [
        f"physical-detector:{family}:{DETECTOR_RULE_VERSION}",
        *[f"wstg:{ref}" for ref in spec.wstg_ids],
        *[f"owasp:{ref}" for ref in spec.owasp_ids],
        *[f"cwe:{ref}" for ref in spec.cwe_ids],
        *[f"writeup:{ref.ref}" for ref in spec.writeups],
    ]


def evaluate_family_detector(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
    *,
    channel: str = "candidate",
) -> dict[str, Any]:
    """Apply the physical 6.9 detector contract before the 6.8 evidence firewall.

    WSTG, OWASP, CWE and write-up material define detector criteria and confounders only.
    None of it is inserted into target evidence, satisfies source-count requirements,
    or overrides target contradictions.
    """
    spec = get_detector_spec(family)
    support_rows = annotate_target_evidence(spec, support, contradiction=False)
    contradict_rows = annotate_target_evidence(spec, contradict or (), contradiction=True)
    extraction = scope_family_evidence(family, support_rows, contradict_rows, channel=channel)
    extraction["physical_detector"] = {
        "family": family,
        "strategy": spec.strategy,
        "version": DETECTOR_ENGINE_VERSION,
        "rule_version": DETECTOR_RULE_VERSION,
        "wstg_ids": list(spec.wstg_ids),
        "owasp_ids": list(spec.owasp_ids),
        "cwe_ids": list(spec.cwe_ids),
        "confounders": list(spec.confounders),
        "writeups": [
            {"ref": ref.ref, "url": ref.url, "relation": ref.relation, "source": ref.source, "lesson": ref.lesson, "counts_as_target_evidence": False}
            for ref in spec.writeups
        ],
    }
    return extraction
