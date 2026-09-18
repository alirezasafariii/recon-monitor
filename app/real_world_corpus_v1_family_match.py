from __future__ import annotations

"""Conservative family resolution helpers for Real-World Corpus V1.

Taxonomy is classification context, never target evidence. These helpers may
resolve the family attached to an already source-attested vulnerability
boundary, but they never create a vulnerability label or Analysis score.
"""

import re
from functools import lru_cache
from typing import Any, Mapping

from family_reasoning import FAMILY_ORDER
from owasp_family_catalog import BUG_FAMILY_METADATA
from owasp_phase2_catalog import PHASE2_FAMILY_SPECS
from real_world_corpus_v1_targeted import canonical_family_cwes
from vulnerability_knowledge_core import BUG_PROFILES

FAMILY_MATCH_VERSION = "1.0.0"
FAMILY_MATCH_RULE_VERSION = "2026.09.18.1"

CANONICAL_FAMILIES = frozenset(str(value) for value in FAMILY_ORDER)

_MANUAL_TERMS = {
    "business_logic": (
        "business logic",
        "workflow bypass",
        "workflow logic",
        "logic flaw",
    ),
    "security_misconfiguration": (
        "security misconfiguration",
        "debug mode",
        "directory listing",
        "management interface",
    ),
    "improper_inventory_management": (
        "improper inventory management",
        "deprecated api",
        "stale api",
        "undocumented api",
        "old api version",
    ),
    "http_verb_tampering": (
        "http verb tampering",
        "method tampering",
        "http method authorization",
        "method authorization",
    ),
    "ssi_injection": (
        "ssi injection",
        "server side include",
        "server-side include",
    ),
    "host_header_injection": (
        "host header injection",
        "unvalidated host header",
        "host header poisoning",
        "host header manipulation",
    ),
    "client_side_resource_manipulation": (
        "client-side resource manipulation",
        "client side resource manipulation",
        "external resource selection",
        "resource url manipulation",
    ),
    "xssi": (
        "cross-site script inclusion",
        "cross site script inclusion",
        "xssi",
    ),
    "tls_hsts_weakness": (
        "hsts",
        "tls hostname verification",
        "certificate validation",
        "weak tls",
        "plaintext transport",
    ),
    "subdomain_takeover": (
        "subdomain takeover",
        "dangling dns",
        "unclaimed service",
        "unclaimed subdomain",
    ),
    "backup_unreferenced_file_exposure": (
        "backup file exposure",
        "backup file",
        "unreferenced file",
        "public backup",
    ),
    "path_confusion": (
        "path confusion",
        "path normalization",
        "routing confusion",
        "normalization disagreement",
    ),
    "oauth_oidc_weakness": (
        "oauth",
        "oidc",
        "openid connect",
        "pkce",
        "redirect_uri",
        "oauth state",
    ),
    "web_cache_poisoning": (
        "web cache poisoning",
        "cache poisoning",
        "poisoned cache",
        "cache key poisoning",
    ),
}

_GENERIC_TERMS = frozenset({
    "weakness",
    "vulnerability",
    "security",
    "injection",
    "exposure",
    "misconfiguration",
    "authentication",
    "authorization",
})


def _text(value: Any) -> str:
    return str(value or "").strip()


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", _text(value).lower()).strip()


def _usable_term(value: Any) -> str:
    term = _normalize(value)
    if not term or term in _GENERIC_TERMS:
        return ""
    if len(term) < 4:
        return ""
    return term


@lru_cache(maxsize=1)
def cwe_owners() -> dict[str, tuple[str, ...]]:
    owners: dict[str, list[str]] = {}
    for family, cwes in canonical_family_cwes().items():
        for cwe in cwes:
            owners.setdefault(str(cwe).upper(), []).append(str(family))
    return {
        cwe: tuple(sorted(set(families)))
        for cwe, families in owners.items()
    }


@lru_cache(maxsize=256)
def family_terms(family: str) -> tuple[str, ...]:
    family = _text(family)
    terms: list[str] = []

    profile = BUG_PROFILES.get(family)
    if isinstance(profile, Mapping):
        terms.append(_text(profile.get("label")))
        terms.extend(_text(value) for value in profile.get("aliases", []) or [])

    phase1 = BUG_FAMILY_METADATA.get(family)
    if isinstance(phase1, Mapping):
        terms.append(_text(phase1.get("label")))

    phase2 = PHASE2_FAMILY_SPECS.get(family)
    if isinstance(phase2, Mapping):
        terms.append(_text(phase2.get("label")))

    terms.append(family.replace("_", " "))
    terms.extend(_MANUAL_TERMS.get(family, ()))

    normalized = []
    seen = set()
    for raw in terms:
        term = _usable_term(raw)
        if not term or term in seen:
            continue
        seen.add(term)
        normalized.append(term)
    return tuple(normalized)


def semantic_matches(family: str, *texts: Any) -> list[str]:
    haystack = " ".join(_normalize(value) for value in texts if _text(value))
    if not haystack:
        return []
    return [term for term in family_terms(family) if term in haystack]


def semantic_family_candidates(*texts: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for family in FAMILY_ORDER:
        matches = semantic_matches(str(family), *texts)
        if matches:
            result[str(family)] = matches
    return result


def resolve_source_family(
    feasibility: Mapping[str, Any],
    advisory: Mapping[str, Any],
) -> dict[str, Any]:
    """Resolve one canonical family without turning taxonomy into a label."""

    reasons: list[str] = []
    hints = [
        _text(value)
        for value in feasibility.get("family_hints", []) or []
        if _text(value)
    ]
    hints = [value for value in hints if value in CANONICAL_FAMILIES]

    taxonomy_raw = feasibility.get("source_taxonomy_match")
    taxonomy = taxonomy_raw if isinstance(taxonomy_raw, Mapping) else {}
    target_family = _text(taxonomy.get("family_target"))
    target_cwe = _text(taxonomy.get("target_cwe")).upper()

    advisory_cwes = {
        _text(item.get("cwe_id")).upper()
        for item in advisory.get("cwes", []) or []
        if isinstance(item, Mapping) and _text(item.get("cwe_id"))
    }
    summary = _text(advisory.get("summary"))

    if len(hints) == 1:
        family = hints[0]
        if target_family and target_family != family:
            return {
                "resolved": False,
                "family": "",
                "basis": "",
                "reasons": ["targeted_family_conflicts_with_unique_family_hint"],
                "semantic_matches": [],
            }
        return {
            "resolved": True,
            "family": family,
            "basis": "unique_family_hint",
            "reasons": [],
            "semantic_matches": semantic_matches(family, summary),
        }

    if target_family and target_family in CANONICAL_FAMILIES:
        canonical = canonical_family_cwes()
        family_cwes = {str(value).upper() for value in canonical.get(target_family, ())}

        if target_cwe:
            if target_cwe not in advisory_cwes:
                reasons.append("target_cwe_missing_from_advisory")
            elif target_cwe not in family_cwes:
                reasons.append("target_cwe_not_canonical_for_family")
            else:
                owners = cwe_owners().get(target_cwe, ())
                if owners == (target_family,):
                    return {
                        "resolved": True,
                        "family": target_family,
                        "basis": "unique_canonical_target_cwe",
                        "reasons": [],
                        "semantic_matches": semantic_matches(target_family, summary),
                    }

                target_semantics = semantic_matches(target_family, summary)
                competing = {
                    family: semantic_matches(family, summary)
                    for family in owners
                    if family != target_family
                }
                competing = {
                    family: matches
                    for family, matches in competing.items()
                    if matches
                }
                if target_semantics and not competing:
                    return {
                        "resolved": True,
                        "family": target_family,
                        "basis": "shared_cwe_plus_unique_summary_semantics",
                        "reasons": [],
                        "semantic_matches": target_semantics,
                    }
                reasons.append("shared_cwe_not_semantically_unique")

        elif not family_cwes:
            target_semantics = semantic_matches(target_family, summary)
            competing = semantic_family_candidates(summary)
            competing.pop(target_family, None)
            if target_semantics and not competing:
                return {
                    "resolved": True,
                    "family": target_family,
                    "basis": "no_cwe_unique_summary_semantics",
                    "reasons": [],
                    "semantic_matches": target_semantics,
                }
            reasons.append("no_cwe_semantics_not_unique")

    if len(hints) > 1:
        reasons.append("multiple_family_hints")
    elif not hints:
        reasons.append("no_unique_family_hint")

    return {
        "resolved": False,
        "family": "",
        "basis": "",
        "reasons": list(dict.fromkeys(reasons)),
        "semantic_matches": [],
    }


__all__ = [
    "FAMILY_MATCH_VERSION",
    "FAMILY_MATCH_RULE_VERSION",
    "CANONICAL_FAMILIES",
    "cwe_owners",
    "family_terms",
    "semantic_matches",
    "semantic_family_candidates",
    "resolve_source_family",
]
