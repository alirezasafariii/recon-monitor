from __future__ import annotations

"""Dedicated analyzers for OWASP/WSTG expansion phase 2.

All analyzers are evidence-preserving: they normalize stored target evidence and
never send network traffic, generate exploit payloads, mutate target state, or
turn knowledge material into evidence. Shared code is an implementation helper;
each family is still registered as a distinct analyzer class with its own
canonical evidence contract.
"""

from typing import Any, Iterable, Mapping

from owasp_phase2_catalog import PHASE2_FAMILY_ORDER, PHASE2_FAMILY_SPECS
from .base import FamilyAnalyzer, FamilyAnalyzerContext
from .remaining_common import add_unique, finalize_result, observations, scalar, truth

PHASE2_ANALYZER_VERSION = "1.0.0"


def _truth(details: Mapping[str, Any], key: str) -> bool:
    return truth(details.get(key)) is True


def _controlled_benign(item: Mapping[str, Any]) -> bool:
    controlled = truth(scalar(item, (
        "controlled_test_context", "authorized_test_context", "controlled_observation",
    ))) is True
    benign = truth(scalar(item, (
        "benign_test_marker", "safe_test_marker", "non_destructive_test", "harmless_test",
    ))) is True
    return bool(controlled and benign)


def _semantic_blob(
    endpoint: str,
    method: str,
    body_fields: Iterable[str],
    query_fields: Iterable[str],
    path_fields: Iterable[str],
    semantic_text: str,
) -> str:
    return " ".join([
        str(endpoint or ""),
        str(method or ""),
        " ".join(str(v) for v in body_fields),
        " ".join(str(v) for v in query_fields),
        " ".join(str(v) for v in path_fields),
        str(semantic_text or ""),
    ]).lower()


def analyze_phase2_family(
    *,
    analyzer: FamilyAnalyzer,
    family: str,
    endpoint: str,
    method: str,
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    path_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    semantic_text: str = "",
) -> dict[str, Any] | None:
    spec = PHASE2_FAMILY_SPECS[family]
    details = dict(details or {})
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    manual = spec["validation"] == "manual_only"

    explicit_context = False
    for evidence_type in spec["context"]:
        if _truth(details, evidence_type):
            explicit_context = True
            add_unique(support, {
                "type": evidence_type,
                "source": "stored_surface_context",
                "source_group": "stored_surface_context",
                "weight": 18,
                "text": f"Stored target context identifies {evidence_type.replace('_', ' ')}.",
            })

    blob = _semantic_blob(endpoint, method, body_fields, query_fields, path_fields, semantic_text)
    matched = [word for word in spec["keywords"] if str(word).lower() in blob]
    if matched and not explicit_context and spec["context"]:
        add_unique(support, {
            "type": spec["context"][0],
            "source": "structured_surface_semantics",
            "source_group": "structured_surface_semantics",
            "weight": 8,
            "text": f"Structured endpoint/schema semantics match {spec['label']} discovery context.",
        })

    for evidence_type in spec["unsafe"]:
        if _truth(details, evidence_type):
            add_unique(support, {
                "type": evidence_type,
                "source": "stored_target_evidence",
                "source_group": "stored_target_evidence",
                "weight": 30,
                "text": f"Stored target evidence records {evidence_type.replace('_', ' ')}.",
            })

    for evidence_type in spec["contradictions"]:
        if _truth(details, evidence_type):
            add_unique(contradict, {
                "type": evidence_type,
                "source": "stored_control_evidence",
                "source_group": "stored_control_evidence",
                "weight": -48,
                "text": f"Stored target evidence records {evidence_type.replace('_', ' ')}.",
            })

    # Manual-only families may accept direct evidence from the details envelope
    # only when it is explicitly marked authorized/controlled and benign.
    direct_allowed = (not manual) or _controlled_benign(details)
    if direct_allowed:
        for evidence_type in spec["direct"]:
            if _truth(details, evidence_type):
                add_unique(support, {
                    "type": evidence_type,
                    "source": "stored_controlled_direct_evidence" if manual else "stored_passive_direct_evidence",
                    "source_group": "stored_direct_evidence",
                    "weight": 62,
                    "text": f"Stored target evidence demonstrates {evidence_type.replace('_', ' ')}.",
                })

    runtime = observations(
        details,
        f"{family}_observations",
        "phase2_family_observations",
        "security_behavior_observations",
    )
    for index, item in enumerate(runtime[:50]):
        group = f"stored_observation:{index}"
        for evidence_type in spec["contradictions"]:
            if truth(scalar(item, (evidence_type,))) is True:
                add_unique(contradict, {
                    "type": evidence_type,
                    "source": "stored_runtime_control",
                    "source_group": group,
                    "weight": -50,
                    "text": f"Stored observation records {evidence_type.replace('_', ' ')}.",
                })
        if manual and not _controlled_benign(item):
            continue
        for evidence_type in spec["direct"]:
            if truth(scalar(item, (evidence_type,))) is True:
                add_unique(support, {
                    "type": evidence_type,
                    "source": "stored_controlled_observation" if manual else "stored_passive_observation",
                    "source_group": group,
                    "weight": 64,
                    "text": f"Stored observation demonstrates {evidence_type.replace('_', ' ')}.",
                })

    if not support and not contradict:
        return None

    # A pure contradiction record with no target-side context is not a finding.
    observed_support = {str(item.get("type") or "") for item in support}
    meaningful = set(spec["context"]) | set(spec["unsafe"]) | set(spec["direct"])
    if not (observed_support & meaningful):
        return None

    direct_types = set(spec["direct"])
    direct_hit = next((t for t in spec["direct"] if t in observed_support), "")
    unsafe_hit = next((t for t in spec["unsafe"] if t in observed_support), "")
    variant = direct_hit or unsafe_hit or "stored_surface"

    taxonomy = {
        "owasp": list(spec["owasp"]),
        "wstg": list(spec["wstg"]),
        "cwe": list(spec["cwe"]),
        "capec": list(spec["capec"]),
    }
    methodology = (
        {"id": f"{family}-surface", "principle": "Require a concrete target-side security surface or boundary."},
        {"id": f"{family}-evidence", "principle": "Promotion depends on stored target evidence, never taxonomy or write-up text."},
        {"id": f"{family}-controls", "principle": "Expected secure controls are contradiction evidence and must block unsupported promotion."},
        {"id": f"{family}-safe", "principle": spec["safe"]},
    )
    false_positive_checks = (
        "Keywords and route names alone are discovery context, not vulnerability evidence.",
        "OWASP/WSTG/CWE/CAPEC/write-up material is non-evidentiary.",
        "A missing defense-in-depth control is not decisive unless the family threat model makes it security-relevant.",
        "Direct evidence for manual-only families must be explicitly authorized, controlled, and benign.",
    )
    writeups = tuple(
        {
            "id": f"owasp-phase2-{family}-{idx}",
            "source": "OWASP/WSTG",
            "ref": ref,
            "principle": f"{spec['label']} analysis uses target evidence plus the expected secure invariant.",
        }
        for idx, ref in enumerate(spec["wstg"] or spec["owasp"], start=1)
    )

    return finalize_result(
        analyzer=analyzer,
        family=family,
        variant=variant,
        support=support,
        contradict=contradict,
        taxonomy=taxonomy,
        methodology=methodology,
        false_positive_checks=false_positive_checks,
        writeup_patterns=writeups,
        direct_types=direct_types,
        rule_ids=(
            f"family-{family}-surface",
            f"family-{family}-stored-evidence",
            f"family-{family}-safe-confirmation",
        ),
        summary=f"{spec['label']} hypothesis from stored target evidence; no active exploit action was performed.",
        base=24,
        extra_meta={
            "runtime_observation_count": len(runtime),
            "payload_generated": False,
            "active_request_performed": False,
            "state_changing_action_performed": False,
            "third_party_action_performed": False,
            "phase2_family": True,
        },
    )


class _Phase2ConfiguredAnalyzer(FamilyAnalyzer):
    analyzer_version = PHASE2_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_phase2_family(
            analyzer=self,
            family=self.family,
            endpoint=context.endpoint,
            method=context.method,
            details=context.details,
            body_fields=kwargs.get("body_fields", ()),
            query_fields=kwargs.get("query_fields", ()),
            path_fields=kwargs.get("path_fields", ()),
            semantic_text=str(kwargs.get("semantic_text", "") or ""),
        )



def _class_name(family: str) -> str:
    return "".join(part.title() for part in family.split("_")) + "FamilyAnalyzer"

# Distinct analyzer class per canonical family; shared normalization is implementation reuse, not a generic router fallback.
PHASE2_ANALYZER_TYPES = {}
for _family in PHASE2_FAMILY_ORDER:
    _cls = type(_class_name(_family), (_Phase2ConfiguredAnalyzer,), {"family": _family, "__module__": __name__})
    globals()[_cls.__name__] = _cls
    PHASE2_ANALYZER_TYPES[_family] = _cls

assert tuple(PHASE2_ANALYZER_TYPES) == PHASE2_FAMILY_ORDER
assert len(set(PHASE2_ANALYZER_TYPES.values())) == len(PHASE2_FAMILY_ORDER)
