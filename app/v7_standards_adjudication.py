from __future__ import annotations

"""Conservative standards-grounded semantic adjudication for Fresh Blind V7.

WSTG, OWASP, CWE and write-up lessons define the interpretation rubric only. They
never count as target/source evidence. Decisions are made only from frozen public-
source material already bound to each V7 capture. Ambiguous material fails closed.
"""

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis_standards import (
    CWE_REFERENCE_VERSION,
    OWASP_REFERENCE_VERSION,
    STANDARDS_ENGINE_VERSION,
    WSTG_REFERENCE_VERSION,
    standards_for_family,
)
from family_detectors.base import DETECTOR_ENGINE_VERSION, DETECTOR_RULE_VERSION
from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from researcher_logic import (
    RESEARCHER_LOGIC_RULE_VERSION,
    RESEARCHER_LOGIC_VERSION,
    researcher_logic_for_family,
)
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.1"
RULE_VERSION = "2026.08.15.6.33.v7.unseen.standards-adjudication.2"
PACKET = ROOT / "benchmarks/raw/sources/v7_semantic_review_packet_v2.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_standards_adjudication.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_standards_adjudication_report.json"
KINDS = ("positive", "near_miss", "secure_negative", "sparse_noisy")

# Metadata that describes our acquisition/review process is never allowed to prove
# semantics. Source snippets, paths, test names, commit messages and upstream prose
# remain eligible source material.
META_KEY_FRAGMENTS = (
    "adjudicat",
    "human_",
    "engine_",
    "scoring",
    "first_blind",
    "expected_",
    "review_status",
    "reviewer",
    "variant_purpose",
    "semantic_role",
    "rule_version",
    "evaluation_kind",
    "publication_authorized",
)

STOP = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "does", "for", "from",
    "in", "into", "is", "it", "of", "on", "or", "only", "the", "this", "to", "with",
    "without", "user", "controlled", "observed", "requires", "require", "condition",
    "surface", "surfaces", "failure", "weakness", "security", "application", "api",
}

SYNONYMS: dict[str, set[str]] = {
    "authorization": {"authorization", "authorize", "authorized", "permission", "permissions", "access", "acl"},
    "authentication": {"authentication", "authenticate", "authenticated", "login", "session", "token", "credential"},
    "unauthorized": {"unauthorized", "unauthorised", "forbidden", "permissionless", "unprivileged", "public"},
    "missing": {"missing", "absent", "without", "lack", "lacking", "omitted", "unset", "none", "nil"},
    "bypass": {"bypass", "bypassed", "circumvent", "circumvention", "skip", "skipped", "evade"},
    "exposure": {"exposure", "exposed", "leak", "leaked", "disclosure", "disclosed", "reveal", "revealed"},
    "unsafe": {"unsafe", "insecure", "dangerous", "untrusted", "unrestricted", "permissive"},
    "failure": {"failure", "fail", "failed", "broken", "incorrect", "improper", "invalid"},
    "differential": {"differential", "difference", "different", "distinct", "discrepancy", "mismatch"},
    "redirect": {"redirect", "redirected", "location", "navigation", "navigate"},
    "request": {"request", "fetch", "http", "client", "outbound"},
    "command": {"command", "shell", "exec", "execute", "process", "system", "spawn"},
    "query": {"query", "sql", "database", "filter", "operator"},
    "script": {"script", "javascript", "xss", "html", "dom", "sink", "innerhtml"},
    "upload": {"upload", "file", "multipart", "attachment", "mime"},
    "path": {"path", "pathname", "directory", "filesystem", "file"},
    "workflow": {"workflow", "flow", "state", "transition", "sequence", "step"},
    "frequency": {"frequency", "rate", "limit", "quota", "repeat", "replay", "automation", "automated"},
    "fixed": {"fixed", "fix", "patched", "patch", "mitigated", "prevented", "reject", "rejected", "deny", "denied"},
    "control": {"control", "validation", "validate", "check", "guard", "sanitize", "sanitizer", "enforce", "enforced"},
}

POLARITY_CONCEPTS = {
    "missing", "bypass", "exposure", "unsafe", "failure", "unauthorized", "unrestricted",
    "incorrect", "improper", "public", "weak", "dangerous", "permissive", "untrusted",
}
FIX_MARKERS = {"fixed", "fix", "patched", "patch", "mitigated", "prevented", "rejected", "denied", "guard", "validation"}
TEST_MARKERS = {"test", "tests", "spec", "assert", "expect", "fixture", "control"}
PARTIAL_MARKERS = {"advisory", "metadata", "changelog", "release", "readme", "partial", "reference"}


def text(value: Any) -> str:
    return str(value or "").strip()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected object")
    return value


def sha_json(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _tokens(value: Any) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text(value).casefold().replace("_", " ").replace("-", " ")))


def _concepts(value: Any) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", text(value).casefold().replace("_", " ").replace("-", " ")) if w not in STOP and len(w) > 2]


def _concept_present(concept: str, tokens: set[str]) -> bool:
    choices = SYNONYMS.get(concept, {concept})
    if choices & tokens:
        return True
    # Small morphology tolerance without fuzzy matching arbitrary strings.
    return any(len(concept) >= 5 and (tok.startswith(concept[:5]) or concept.startswith(tok[:5])) for tok in tokens if len(tok) >= 5)


def _term_match(term: str, tokens: set[str]) -> bool:
    concepts = _concepts(term)
    if not concepts:
        return False
    matched = sum(_concept_present(c, tokens) for c in concepts)
    required = 1 if len(concepts) == 1 else max(2, math.ceil(len(concepts) * 0.6))
    if matched < required:
        return False
    polar = [c for c in concepts if c in POLARITY_CONCEPTS]
    return not polar or any(_concept_present(c, tokens) for c in polar)


def _collect_source_strings(value: Any, *, key: str = "") -> list[str]:
    key_l = key.casefold()
    if any(fragment in key_l for fragment in META_KEY_FRAGMENTS):
        return []
    if isinstance(value, Mapping):
        rows: list[str] = []
        for k, v in value.items():
            rows.extend(_collect_source_strings(v, key=str(k)))
        return rows
    if isinstance(value, list):
        rows: list[str] = []
        for item in value:
            rows.extend(_collect_source_strings(item, key=key))
        return rows
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _find_capture_rows(value: Any, capture_id: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, Mapping):
        if text(value.get("capture_id")) == capture_id:
            found.append(dict(value))
        for child in value.values():
            found.extend(_find_capture_rows(child, capture_id))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_capture_rows(child, capture_id))
    return found


def _fingerprints(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, Mapping):
        for child in value.values():
            found |= _fingerprints(child)
    elif isinstance(value, list):
        for child in value:
            found |= _fingerprints(child)
    elif isinstance(value, str):
        scalar = value.strip()
        if len(scalar) >= 8:
            found.add(scalar)
    return found


def _find_fingerprint_rows(value: Any, fingerprints: set[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if not fingerprints:
        return found
    if isinstance(value, Mapping):
        direct = {
            text(v) for v in value.values()
            if isinstance(v, str) and len(text(v)) >= 8
        }
        if direct & fingerprints:
            found.append(dict(value))
        for child in value.values():
            found.extend(_find_fingerprint_rows(child, fingerprints))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_fingerprint_rows(child, fingerprints))
    deduped: dict[str, dict[str, Any]] = {}
    for row in found:
        deduped[sha_json(row)] = row
    return list(deduped.values())


def _material_payload(variant: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    capture_id = text(variant.get("capture_id"))
    material = variant.get("review_material") if isinstance(variant.get("review_material"), Mapping) else {}
    kind = text(material.get("material_kind"))
    provenance: dict[str, Any] = {"material_kind": kind}
    payload: Any
    if kind == "original_source_grounded_draft":
        path = ROOT / text(material.get("draft_path"))
        if not path.exists():
            raise RuntimeError(f"{capture_id}: missing draft {path}")
        payload = load(path)
        provenance.update({
            "artifact": str(path.relative_to(ROOT)),
            "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "binding_mode": "direct_capture_draft",
        })
    elif kind == "acquired_literal_candidate_material":
        path = ROOT / text(material.get("literal_material_artifact"))
        if not path.exists():
            raise RuntimeError(f"{capture_id}: missing literal material artifact {path}")
        doc = load(path)
        candidate_refs = list(material.get("candidate_refs") or [])
        rows = _find_capture_rows(doc, capture_id)
        binding_mode = "capture_id"
        if not rows:
            rows = _find_fingerprint_rows(doc, _fingerprints(candidate_refs))
            binding_mode = "frozen_candidate_fingerprint" if rows else "candidate_refs_only"
        payload = {"matched_rows": rows, "candidate_refs": candidate_refs}
        provenance.update({
            "artifact": str(path.relative_to(ROOT)),
            "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "matched_row_count": len(rows),
            "binding_mode": binding_mode,
            "resolution_stage": material.get("resolution_stage"),
        })
    else:
        raise RuntimeError(f"{capture_id}: unsupported review material kind {kind!r}")
    strings = _collect_source_strings(payload)
    return provenance, strings


def _hits(terms: Iterable[str], tokens: set[str]) -> list[str]:
    return sorted({text(term) for term in terms if text(term) and _term_match(text(term), tokens)})


def _family_alignment(family: str, tokens: set[str]) -> dict[str, Any]:
    spec = DETECTOR_SPECS[family]
    logic = researcher_logic_for_family(family)
    identity_hits = _hits(spec.identity_signals, tokens)
    surface_hits = sorted({term for term in spec.surface_terms if _term_match(term, tokens)})
    standard_titles = [
        text(item.get("title"))
        for group in ("wstg", "owasp", "cwe")
        for item in standards_for_family(family).get(group) or []
        if isinstance(item, Mapping) and text(item.get("title"))
    ]
    # Standard-title overlap is a consistency signal only; it never contributes to
    # the literal evidence count used for acceptance.
    standard_title_hits = _hits(standard_titles, tokens)
    confounder_hits = []
    for confounder in spec.confounders:
        other = DETECTOR_SPECS.get(confounder)
        if not other:
            continue
        if _hits(other.identity_signals, tokens) or sum(_term_match(t, tokens) for t in other.surface_terms) >= 2:
            confounder_hits.append(confounder)
    family_source_aligned = bool(identity_hits or surface_hits)
    return {
        "family_source_aligned": family_source_aligned,
        "identity_hits": identity_hits,
        "surface_hits": surface_hits[:20],
        "standards_title_consistency_hits": standard_title_hits[:20],
        "confounder_hits": sorted(set(confounder_hits)),
        "writeup_lesson_count": len(logic.get("writeup_logic") or []),
    }


def adjudicate_variant(family: str, variant: Mapping[str, Any]) -> dict[str, Any]:
    spec = DETECTOR_SPECS[family]
    logic = researcher_logic_for_family(family)
    provenance, strings = _material_payload(variant)
    tokens = _tokens("\n".join(strings))
    condition_hits = _hits(spec.condition_signals, tokens)
    control_hits = _hits(spec.blocking_controls, tokens)
    override_hits = _hits(spec.override_signals, tokens)
    alignment = _family_alignment(family, tokens)
    kind = text(variant.get("case_kind"))
    marker_tokens = tokens
    fixed_shape = bool(FIX_MARKERS & marker_tokens)
    test_shape = bool(TEST_MARKERS & marker_tokens)
    partial_shape = bool(PARTIAL_MARKERS & marker_tokens)
    blocked_by_control = bool(control_hits and not override_hits)
    wrong_family_risk = bool(alignment["confounder_hits"] and not alignment["family_source_aligned"])

    decision = "needs_additional_source_material"
    reason = "source material does not satisfy the frozen case-kind rubric"
    accepted = False
    if wrong_family_risk:
        decision = "reject_candidate"
        reason = "source material aligns with a frozen confounder more strongly than the target family"
    elif kind == "positive":
        if alignment["family_source_aligned"] and condition_hits and not blocked_by_control:
            accepted = True
            decision = "accept_candidate_as_variant"
            reason = "literal source supports family identity and a decisive condition without an unoverridden blocker"
    elif kind == "secure_negative":
        if alignment["family_source_aligned"] and not condition_hits and (control_hits or fixed_shape):
            accepted = True
            decision = "accept_candidate_as_variant"
            reason = "literal source supports the family and an implemented control/fixed state while the decisive condition is absent"
    elif kind == "near_miss":
        if alignment["family_source_aligned"] and not condition_hits and (control_hits or test_shape):
            accepted = True
            decision = "accept_candidate_as_variant"
            reason = "source is family-adjacent but does not satisfy the decisive condition and contains an independent control/test shape"
    elif kind == "sparse_noisy":
        if alignment["family_source_aligned"] and not condition_hits and (partial_shape or len(tokens) < 120):
            accepted = True
            decision = "accept_candidate_as_variant"
            reason = "source is family-adjacent and partial/noisy but lacks the decisive condition required for promotion"
    else:
        raise RuntimeError(f"{variant.get('capture_id')}: unexpected case kind {kind!r}")

    standards = standards_for_family(family)
    return {
        "capture_id": variant.get("capture_id"),
        "case_kind": kind,
        "decision": decision,
        "accepted_for_v7": accepted,
        "reason": reason,
        "source_material": provenance,
        "literal_source_layer": {
            **alignment,
            "condition_hits": condition_hits,
            "blocking_control_hits": control_hits,
            "override_hits": override_hits,
            "fixed_shape_observed": fixed_shape,
            "test_control_shape_observed": test_shape,
            "partial_shape_observed": partial_shape,
            "eligible_source_string_count": len(strings),
            "eligible_source_token_count": len(tokens),
        },
        "standards_rubric_layer": {
            "principle": standards.get("principle"),
            "wstg_ids": [x.get("id") for x in standards.get("wstg") or [] if isinstance(x, Mapping)],
            "owasp_ids": [x.get("id") for x in standards.get("owasp") or [] if isinstance(x, Mapping)],
            "cwe_ids": [x.get("id") for x in standards.get("cwe") or [] if isinstance(x, Mapping)],
            "counts_as_target_evidence": False,
        },
        "writeup_rubric_layer": {
            "lesson_count": len(logic.get("writeup_logic") or []),
            "lessons_sha256": sha_json(logic.get("writeup_logic") or []),
            "counts_as_target_evidence": False,
        },
        "engine_output_used": False,
        "human_verified": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }


def build_adjudication() -> dict[str, Any]:
    freeze = assert_capture_source_freeze()
    packet = load(PACKET)
    if packet.get("source_assignment_commit") != freeze["source_assignment_commit"]:
        raise RuntimeError("V7 standards adjudication source assignment drift")
    if packet.get("family_count") != 36 or packet.get("variant_count") != 144:
        raise RuntimeError("V7 standards adjudication packet coverage drift")
    if packet.get("review_material_available_count") != 144 or packet.get("review_material_missing_count") != 0:
        raise RuntimeError("V7 standards adjudication requires complete review material")
    if packet.get("scoring_executed") is not False or packet.get("first_blind_consumed") is not False:
        raise RuntimeError("V7 standards adjudication requires an unconsumed packet")

    families = []
    variant_counts: Counter[str] = Counter()
    standards_coverage = 0
    writeup_coverage = 0
    accepted_count = 0
    rejected_count = 0
    needs_more_count = 0
    required_family_count = 0
    confirmed_family_count = 0

    for packet_family in packet.get("packets") or []:
        if not isinstance(packet_family, Mapping):
            continue
        family = text(packet_family.get("family"))
        if family not in DETECTOR_SPECS:
            raise RuntimeError(f"V7 standards adjudication unknown family {family!r}")
        standards = standards_for_family(family)
        logic = researcher_logic_for_family(family)
        if not standards.get("wstg") or not standards.get("owasp") or not standards.get("cwe"):
            raise RuntimeError(f"{family}: incomplete WSTG/OWASP/CWE rubric")
        if not logic.get("writeup_logic"):
            raise RuntimeError(f"{family}: missing write-up reasoning rubric")
        standards_coverage += 1
        writeup_coverage += 1

        variants = []
        for variant in packet_family.get("variants") or []:
            if not isinstance(variant, Mapping):
                continue
            row = adjudicate_variant(family, variant)
            variants.append(row)
            variant_counts[row["case_kind"]] += 1
            if row["decision"] == "accept_candidate_as_variant":
                accepted_count += 1
            elif row["decision"] == "reject_candidate":
                rejected_count += 1
            else:
                needs_more_count += 1
        if len(variants) != 4 or {v["case_kind"] for v in variants} != set(KINDS):
            raise RuntimeError(f"{family}: standards adjudication variant coverage drift")

        family_required = packet_family.get("literal_family_adjudication_required") is True
        if family_required:
            required_family_count += 1
        positive = next(v for v in variants if v["case_kind"] == "positive")
        family_confirmed = bool(positive["accepted_for_v7"])
        if family_required and family_confirmed:
            confirmed_family_count += 1
        family_decision = (
            "confirm_family_mapping" if family_confirmed else "needs_additional_source_material"
        ) if family_required else "preexisting_mapping_retained_subject_to_variant_adjudication"

        families.append({
            "family": family,
            "source_root": packet_family.get("source_root"),
            "source_project": packet_family.get("source_project"),
            "literal_family_adjudication_required": family_required,
            "family_adjudication_decision": family_decision,
            "variants": variants,
        })

    if len(families) != 36 or sum(variant_counts.values()) != 144:
        raise RuntimeError("V7 standards adjudication total coverage drift")
    if dict(variant_counts) != {kind: 36 for kind in KINDS}:
        raise RuntimeError(f"V7 standards adjudication case-kind drift: {dict(variant_counts)}")

    unresolved = rejected_count + needs_more_count
    complete = unresolved == 0 and confirmed_family_count == required_family_count
    result = {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v7_standards_grounded_machine_semantic_adjudication_unscored",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "adjudication_kind": "standards_grounded_machine_semantic_adjudication",
        "quality_model": {
            "literal_source_layer": "frozen source material must satisfy family identity plus case-kind-specific condition/control requirements",
            "standards_rubric_layer": "WSTG + OWASP + CWE define taxonomy and interpretation criteria only",
            "writeup_rubric_layer": "frozen write-up lessons and confounders guide interpretation only",
            "fail_closed_on_ambiguity": True,
        },
        "reference_freeze": {
            "standards_engine_version": STANDARDS_ENGINE_VERSION,
            "wstg_reference_version": WSTG_REFERENCE_VERSION,
            "owasp_reference_version": OWASP_REFERENCE_VERSION,
            "cwe_reference_version": CWE_REFERENCE_VERSION,
            "detector_engine_version": DETECTOR_ENGINE_VERSION,
            "detector_rule_version": DETECTOR_RULE_VERSION,
            "researcher_logic_version": RESEARCHER_LOGIC_VERSION,
            "researcher_logic_rule_version": RESEARCHER_LOGIC_RULE_VERSION,
        },
        "family_count": 36,
        "variant_count": 144,
        "by_case_kind": dict(sorted(variant_counts.items())),
        "standards_coverage_family_count": standards_coverage,
        "writeup_coverage_family_count": writeup_coverage,
        "machine_adjudicated_variant_count": 144,
        "accepted_variant_count": accepted_count,
        "rejected_candidate_count": rejected_count,
        "needs_additional_source_material_count": needs_more_count,
        "unresolved_variant_count": unresolved,
        "family_adjudication_required_count": required_family_count,
        "family_mapping_confirmed_count": confirmed_family_count,
        "machine_semantic_adjudication_complete": complete,
        "human_review_required": False,
        "human_adjudication_performed": False,
        "human_verified_record_count": 0,
        "engine_output_allowed_as_evidence": False,
        "standards_count_as_target_evidence": False,
        "writeups_count_as_target_evidence": False,
        "source_assignment_locked": True,
        "source_replacement_allowed_during_adjudication": False,
        "synthetic_fixture_allowed": False,
        "evidence_published": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
        "engine_baseline_commit": freeze["engine_baseline_commit"],
        "source_assignment_commit": freeze["source_assignment_commit"],
        "semantic_review_packet_sha256": packet.get("packet_set_sha256"),
        "families": families,
    }
    result["adjudication_sha256"] = sha_json({k: v for k, v in result.items() if k != "adjudication_sha256"})
    return result


def main() -> int:
    result = build_adjudication()
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = {k: v for k, v in result.items() if k != "families"}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
