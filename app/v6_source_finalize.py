from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row
from raw_recon_v6_source_firewall import (
    RULE_VERSION as FIREWALL_RULE_VERSION,
    canonical_url,
    check_candidate,
    exposure_index,
)

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.31.3"
SRC = ROOT / "benchmarks/raw/sources"

BASE_HARD = {
    "business_logic", "cors_misconfiguration", "dom_xss", "graphql_data_exposure",
    "improper_inventory_management", "nosql_injection", "postmessage_trust",
    "sensitive_business_flow_abuse", "sensitive_caching", "software_supply_chain_failure",
}
EXTENSION_HARD = {
    "graphql_authorization", "source_map_exposure", "unsafe_api_consumption", "websocket_authorization",
}
HARD = BASE_HARD | EXTENSION_HARD
COMPLEMENT_OVERRIDE_FAMILIES = {
    "account_enumeration", "authentication_session", "broken_function_authorization",
    "command_injection", "cryptographic_failure", "exceptional_condition_mishandling",
    "file_upload", "mass_assignment", "race_condition",
    "server_side_template_injection", "unrestricted_resource_consumption",
}
LEGACY_DISCOVERY_FAMILIES = set(DETECTOR_SPECS) - HARD - COMPLEMENT_OVERRIDE_FAMILIES

CONTRACTS: dict[str, tuple[tuple[str, ...], ...]] = {
    "business_logic": (
        ("business logic", "business workflow", "approval workflow", "workflow"),
        ("invariant", "gate", "required approver", "state transition", "approval"),
        ("bypass", "self-approve", "skip", "invalid state transition", "incorrect transition", "untrusted accepted"),
    ),
    "cors_misconfiguration": (
        ("cors", "cross-origin"),
        ("origin", "untrusted origin", "origin restriction", "trusted origin"),
        ("credential", "sensitive", "state-changing", "data"),
    ),
    "dom_xss": (("dom xss", "client-side"), ("svg", "render", "browser", "sink"), ("sanit", "bypass")),
    "graphql_authorization": (("graphql",), ("authorization", "permission", "access control"), ("editor", "service", "manage", "operation", "role")),
    "graphql_data_exposure": (("graphql", "shop api"), ("sensitive", "non-public", "private", "restricted", "data exposure"), ("field", "entity", "query", "scope", "filter", "property")),
    "improper_inventory_management": (("old api", "older arm api", "legacy api"), ("version", "api"), ("still exploitable", "weaker authorization", "version drift")),
    "nosql_injection": (("nosql", "mongodb", "mongo"), ("query", "operator", "filter", "selector"), ("inject", "injection", "unvalidated", "alter", "semantics", "unintended")),
    "postmessage_trust": (("postmessage", "message event"), ("origin", "iframe source", "sender"), ("validation", "trust", "correct iframe")),
    "sensitive_business_flow_abuse": (("invite", "business"), ("duplicate", "flood", "repeat"), ("rate limit", "anti-abuse", "frequency")),
    "sensitive_caching": (("cache", "cached"), ("api key", "sensitive", "authenticated"), ("shared cache", "unauthenticated cache hit", "edge")),
    "software_supply_chain_failure": (("supply chain", "dependency"), ("compromised", "malicious"), ("package", "installation", "published")),
    "source_map_exposure": (("source map", "source-map"), ("source code", "non-compiled source", "original source", "debug artifact"), ("expose", "read", "disclosure", "obtainable")),
    "unsafe_api_consumption": (("external api", "http client", "remote service", "third-party"), ("redirect", "cross-host", "response"), ("credential", "proxy-authorization", "trust boundary", "forwarded")),
    "websocket_authorization": (("websocket", "real-time"), ("authorization", "authentication", "access control", "suspended user"), ("bypass", "sensitive updates", "http blocked")),
}


def _load(name: str) -> dict[str, Any]:
    return json.loads((SRC / name).read_text(encoding="utf-8"))


def _identity(value: Any) -> str:
    return str(value or "").strip().casefold()


def _grounding_urls(*docs: Mapping[str, Any]) -> set[str]:
    urls: set[str] = set()
    for doc in docs:
        for spec in (doc.get("families") or {}).values():
            if not isinstance(spec, Mapping):
                continue
            for key in ("owasp_anchor", "owasp_companion"):
                value = canonical_url(spec.get(key))
                if value:
                    urls.add(value)
            for raw in spec.get("writeups") or []:
                value = canonical_url(raw)
                if value:
                    urls.add(value)
    return urls


def _candidate_urls(row: Mapping[str, Any]) -> set[str]:
    values = [
        row.get("canonical_advisory_url"), row.get("repository_advisory_url"),
        row.get("source_code_location"), row.get("source_url"),
        *(row.get("references") or []), *(row.get("source_url_aliases") or []),
    ]
    return {url for value in values if (url := canonical_url(value))}


def _semantic_audit(family: str, row: Mapping[str, Any]) -> list[list[str]]:
    text = " ".join([
        str(row.get("summary") or ""), str(row.get("description") or ""),
        *[str(value) for value in row.get("semantic_facts") or []],
    ]).casefold()
    group_hits: list[list[str]] = []
    for group in CONTRACTS[family]:
        hits = sorted(term for term in group if term in text)
        if not hits:
            raise RuntimeError(f"{family}: OWASP semantic group missing: {group}")
        group_hits.append(hits)
    return group_hits


def _reserve_identity(
    family: str,
    row: Mapping[str, Any],
    used_roots: set[str],
    used_projects: set[str],
) -> None:
    root = _identity(row.get("source_root"))
    project = _identity(row.get("source_project"))
    if not root or not project:
        raise RuntimeError(f"{family}: missing source identity")
    if root in used_roots or project in used_projects:
        raise RuntimeError(f"{family}: global source uniqueness collision root={root!r} project={project!r}")
    used_roots.add(root)
    used_projects.add(project)


def finalize() -> dict[str, Any]:
    if (SRC / "v6_corpus_freeze.json").exists():
        raise RuntimeError("v6 source selection is immutable after corpus freeze")

    grounding = _load("v6_owasp_writeup_grounding.json")
    grounding_ext = _load("v6_owasp_extension_grounding.json")
    manual = _load("v6_owasp_writeup_candidates.json")
    exact = _load("v6_owasp_exact_overrides.json")
    extension = _load("v6_owasp_extension_candidates.json")
    complement = _load("v6_complement_overrides.json")
    discovered = _load("v6_candidates.json")

    for doc in (grounding, grounding_ext, manual, exact, extension, complement, discovered):
        if doc.get("scoring_executed") is not False:
            raise RuntimeError("all v6 source artifacts must remain unscored")
    for doc in (manual, exact, extension, complement):
        for key in ("detector_output_used", "admission_output_used", "ranking_output_used"):
            if key in doc and doc.get(key) is not False:
                raise RuntimeError(f"{key} must remain false during v6 source selection")
    if grounding.get("grounding_counts_as_target_evidence") is not False or grounding_ext.get("grounding_counts_as_target_evidence") is not False:
        raise RuntimeError("grounding must not count as target evidence")

    exact_expected = BASE_HARD - {"dom_xss", "sensitive_business_flow_abuse"}
    if set(exact.get("candidates_by_family") or {}) != exact_expected:
        raise RuntimeError("exact override family coverage mismatch")
    if set(extension.get("candidates_by_family") or {}) != EXTENSION_HARD:
        raise RuntimeError("extension family coverage mismatch")
    if set(complement.get("candidates_by_family") or {}) != COMPLEMENT_OVERRIDE_FAMILIES:
        raise RuntimeError("complement override family coverage mismatch")
    if int(complement.get("candidate_count") or 0) != len(COMPLEMENT_OVERRIDE_FAMILIES):
        raise RuntimeError("complement override candidate count mismatch")

    grounding_families: dict[str, Any] = {}
    grounding_families.update(grounding.get("families") or {})
    grounding_families.update(grounding_ext.get("families") or {})
    if set(grounding_families) != HARD:
        raise RuntimeError(f"grounding family coverage mismatch: {len(grounding_families)}/14")
    grounding_urls = _grounding_urls(grounding, grounding_ext)
    prior = exposure_index()

    selected: dict[str, dict[str, Any]] = {}
    hard_report: dict[str, Any] = {}
    complement_report: dict[str, Any] = {}
    used_roots: set[str] = set()
    used_projects: set[str] = set()

    for family in sorted(HARD):
        pool = manual if family in {"dom_xss", "sensitive_business_flow_abuse"} else extension if family in EXTENSION_HARD else exact
        rows = (pool.get("candidates_by_family") or {}).get(family) or []
        if len(rows) != 1:
            raise RuntimeError(f"{family}: expected exactly one grounded candidate")
        row = dict(rows[0])
        group_hits = _semantic_audit(family, row)
        required = set((grounding_families.get(family) or {}).get("wstg_ids") or [])
        supplied = set(row.get("wstg_ids") or [])
        if not supplied or not supplied.issubset(required):
            raise RuntimeError(f"{family}: WSTG mismatch supplied={sorted(supplied)} required={sorted(required)}")

        fw = check_candidate(row, index=prior)
        grounding_overlap = sorted(_candidate_urls(row) & grounding_urls)
        if not fw["allowed"] or grounding_overlap:
            raise RuntimeError(f"{family}: source firewall rejected candidate: firewall={fw} grounding_overlap={grounding_overlap}")
        _reserve_identity(family, row, used_roots, used_projects)
        row["freshness_validated"] = True
        row["v6_firewall_allowed"] = True
        row["source_selection_track"] = "owasp_wstg_writeup_grounded_exact"
        row["owasp_grounding_audit"] = {"passed": True, "group_hits": group_hits, "grounding_only": True, "counts_as_target_evidence": False}
        selected[family] = row
        hard_report[family] = {
            "source_root": row.get("source_root"), "source_project": row.get("source_project"),
            "wstg_ids": sorted(supplied), "semantic_group_hits": group_hits,
            "firewall": fw, "grounding_url_overlap": grounding_overlap,
        }

    for family in sorted(COMPLEMENT_OVERRIDE_FAMILIES):
        rows = (complement.get("candidates_by_family") or {}).get(family) or []
        if len(rows) != 1:
            raise RuntimeError(f"{family}: expected exactly one complement override")
        row = dict(rows[0])
        fw = check_candidate(row, index=prior)
        grounding_overlap = sorted(_candidate_urls(row) & grounding_urls)
        passed, hits, score = audit_row(family, row)
        if not passed:
            raise RuntimeError(f"{family}: complement override failed semantic audit hits={hits} score={score}")
        if not fw["allowed"] or grounding_overlap:
            raise RuntimeError(f"{family}: complement override rejected firewall={fw} grounding_overlap={grounding_overlap}")
        _reserve_identity(family, row, used_roots, used_projects)
        row["freshness_validated"] = True
        row["v6_firewall_allowed"] = True
        row["source_family_audit_version"] = AUDIT_VERSION
        row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION
        row["source_family_audit_score"] = int(score)
        row["source_family_audit_group_hits"] = hits
        row["source_selection_track"] = "fresh_exact_complement_override"
        selected[family] = row
        complement_report[family] = {
            "source_root": row.get("source_root"),
            "source_project": row.get("source_project"),
            "semantic_audit_score": int(score),
            "semantic_audit_hits": hits,
            "firewall": fw,
            "grounding_url_overlap": grounding_overlap,
        }

    pool = discovered.get("candidates_by_family") or {}
    eligible: dict[str, list[dict[str, Any]]] = {}
    for family in sorted(LEGACY_DISCOVERY_FAMILIES):
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for raw in pool.get(family) or []:
            root = _identity(raw.get("source_root"))
            project = _identity(raw.get("source_project"))
            if not root or not project or (root, project) in seen:
                continue
            seen.add((root, project))
            fw = check_candidate(raw, index=prior)
            grounding_overlap = sorted(_candidate_urls(raw) & grounding_urls)
            if not fw["allowed"] or grounding_overlap:
                continue
            passed, hits, score = audit_row(family, raw)
            if not passed:
                continue
            row = dict(raw)
            row["freshness_validated"] = True
            row["v6_firewall_allowed"] = True
            row["source_family_audit_version"] = AUDIT_VERSION
            row["source_family_audit_rule_version"] = AUDIT_RULE_VERSION
            row["source_family_audit_score"] = int(score)
            row["source_family_audit_group_hits"] = hits
            row["source_selection_track"] = "legacy_semantic_fresh_pool"
            rows.append(row)
        rows.sort(key=lambda r: (
            int(r.get("source_family_audit_score") or 0),
            1 if r.get("advisory_source_type") == "reviewed" else 0,
            1 if r.get("repository_advisory_url") else 0,
            r.get("published_at") or "",
        ), reverse=True)
        eligible[family] = rows

    missing = sorted(family for family, rows in eligible.items() if not rows)
    if missing:
        raise RuntimeError("remaining legacy-discovery semantic source gaps: " + ", ".join(missing))

    for family in sorted(eligible, key=lambda name: (len(eligible[name]), name)):
        chosen = None
        for row in eligible[family]:
            root = _identity(row.get("source_root"))
            project = _identity(row.get("source_project"))
            if root in used_roots or project in used_projects:
                continue
            chosen = row
            break
        if chosen is None:
            raise RuntimeError("global uniqueness gap: " + family)
        _reserve_identity(family, chosen, used_roots, used_projects)
        selected[family] = chosen

    if set(selected) != set(DETECTOR_SPECS):
        raise RuntimeError(f"family coverage mismatch {len(selected)}/36")
    rows = [selected[family] for family in sorted(selected)]
    rejected = []
    for row in rows:
        check = check_candidate(row, index=prior)
        if not check["allowed"]:
            rejected.append({"family": row.get("family"), "check": check})
    if len(rows) != 36 or len(used_roots) != 36 or len(used_projects) != 36 or rejected:
        raise RuntimeError(f"final shortlist firewall/uniqueness failed count={len(rows)} roots={len(used_roots)} projects={len(used_projects)} rejected={rejected}")

    final_firewall = {
        "passed": True, "errors": [], "candidate_count": 36,
        "unique_root_count": 36, "unique_project_count": 36, "rejected": [],
        "firewall_rule_version": FIREWALL_RULE_VERSION, "scoring_executed": False,
    }
    shortlist = {
        "version": "3.4.0", "rule_version": RULE_VERSION,
        "evaluation_kind": "fresh_blind_v6_unscored_source_selection",
        "selection_executes_scoring": False, "selection_uses_detector_output": False,
        "selection_uses_admission_results": False, "selection_uses_ranking_results": False,
        "grounding_counts_as_target_evidence": False,
        "family_count": 36, "unique_root_count": 36, "unique_project_count": 36,
        "owasp_grounded_family_count": 14,
        "complement_family_count": 22,
        "complement_override_family_count": 11,
        "legacy_semantic_family_count": 11,
        "supplement_pool_used": False,
        "firewall": final_firewall, "selected": rows,
    }
    report = {
        "version": "1.4.0", "rule_version": RULE_VERSION, "status": "selected",
        "scoring_executed": False, "family_count": 36, "unique_root_count": 36,
        "unique_project_count": 36, "owasp_grounded_family_count": 14,
        "complement_family_count": 22, "complement_override_family_count": 11,
        "legacy_semantic_family_count": 11, "supplement_pool_used": False,
        "grounding_provenance_reuse_count": 0,
        "hard_family_validation": hard_report,
        "complement_override_validation": complement_report,
        "firewall_rule_version": FIREWALL_RULE_VERSION,
    }
    (SRC / "v6_shortlist.json").write_text(json.dumps(shortlist, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (SRC / "v6_selection_final_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    print(json.dumps(finalize(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
