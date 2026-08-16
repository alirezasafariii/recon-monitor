from __future__ import annotations

"""Dedicated Credential / Token Exposure analyzer.

The analyzer is deliberately offline and redaction-first.  Names such as
``apiKey`` or ``password`` are only discovery surface.  Direct family evidence
is emitted only when stored target observations already establish structurally
complete credential material (for example a complete private-key block or a
paired cloud credential) or an explicitly authorized stored observation marks
that material as live.  No credential is ever sent to a provider for validity
checking and no raw credential value is returned by this module.
"""

import hashlib
import math
import re
from collections import Counter
from typing import Any, Iterable, Mapping

from core import Database
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


SECRET_EXPOSURE_FAMILY_ANALYZER_VERSION = "1.0.0"
SECRET_EXPOSURE_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

SECRET_EXPOSURE_TAXONOMY = {
    "owasp": ["Secrets Management", "Information Leakage"],
    "wstg": ["WSTG-INFO-05"],
    "cwe": ["CWE-798"],
    "related_cwe": ["CWE-321", "CWE-540", "CWE-200"],
}

SECRET_EXPOSURE_METHOD = (
    {
        "id": "SECRET-01-pattern-surface",
        "basis": ["WSTG-INFO-05", "CWE-798"],
        "principle": "Treat secret-looking variable names and partial token markers as discovery surface only; names alone do not prove credential material.",
    },
    {
        "id": "SECRET-02-material-classification",
        "basis": ["CWE-798", "CWE-321"],
        "principle": "Classify only stored client-delivered material using format structure, paired fields and bounded local context; never validate credentials online.",
    },
    {
        "id": "SECRET-03-placeholder-public-key-filter",
        "basis": ["OWASP Secrets Management"],
        "principle": "Reject examples, placeholders, environment references, test-only values and intentionally public client identifiers before promotion.",
    },
    {
        "id": "SECRET-04-exposure-context",
        "basis": ["WSTG-INFO-05", "CWE-540"],
        "principle": "Separate credential-shaped material from the fact that it is embedded in client-delivered source or another unintended exposure boundary.",
    },
    {
        "id": "SECRET-05-lifecycle-without-validation",
        "basis": ["OWASP Secrets Management"],
        "principle": "Rotation, revocation or live status may be recorded only from already-authorized evidence; the analyzer itself performs no credential-use request.",
    },
)

SECRET_EXPOSURE_FALSE_POSITIVE_CHECKS = (
    "Variable or field names such as apiKey, clientSecret, accessToken or password are surface only.",
    "AWS access-key identifiers without a paired secret-access-key value are not structurally complete credentials.",
    "JWT-shaped strings are token material candidates but are not assumed live or privileged.",
    "Publishable/public client identifiers and SDK configuration values are not treated as secret credentials merely because they contain the word key.",
    "Examples, samples, placeholders, test values, environment references and templated substitutions are contradiction or hidden-surface evidence.",
    "A provider-specific test credential is not treated as production-live material merely because its syntax is valid.",
    "No raw credential, private-key body, password, token or secret value is copied into analyzer output.",
)

SECRET_EXPOSURE_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-info-05-client-secrets",
        "source": "OWASP WSTG",
        "ref": "WSTG-INFO-05 / Review Web Page Content for Information Leakage",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
        "principle": "Frontend JavaScript may expose private API keys, credentials and other sensitive implementation material.",
        "signals": ["secret_pattern", "context", "credential_material_confirmed"],
    },
    {
        "id": "cwe-798-hard-coded-credential",
        "source": "MITRE CWE",
        "ref": "CWE-798 / Use of Hard-coded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
        "principle": "Hard-coded client-side credentials can be extracted by actors who can obtain the shipped code.",
        "signals": ["credential_material_confirmed"],
    },
    {
        "id": "owasp-secrets-management-source-control",
        "source": "OWASP Cheat Sheet Series",
        "ref": "Secrets Management Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "principle": "Secrets should not be hard-coded into source/configuration artifacts and should have explicit lifecycle management.",
        "signals": ["credential_material_confirmed", "live_secret_context"],
    },
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:example|sample|placeholder|changeme|change_me|replace[_-]?me|dummy|fake|test[_-]?only|your[_-]?(?:api[_-]?key|token|client[_-]?secret|secret|password)|xxxx+|aaaa+|123456|password123)"
)
_TEMPLATE_RE = re.compile(r"(?:\$\{[^}]+\}|<%[^%]+%>|process\.env\.|import\.meta\.env\.|config\s*\()", re.I)

_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----"
    r"(?P<body>[\s\S]{64,20000}?)"
    r"-----END (?P=kind)-----",
    re.M,
)
_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secretAccessKey)\s*[:=]\s*[\"'](?P<value>[A-Za-z0-9/+=]{40})[\"']"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b")
_STRIPE_SECRET_RE = re.compile(r"\bsk_(?P<tier>live|test)_[A-Za-z0-9]{16,255}\b")
_GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<name>api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b"
    r"\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]{6,512})[\"']"
)

_MATERIAL_MARKERS = {"aws_access_key_pattern", "private_key_marker", "jwt_like_token"}
_PUBLIC_IDENTIFIER_HINTS = {
    "publishable_key", "public_key", "client_id", "clientid", "application_id", "app_id", "measurement_id",
}


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _safe_reason(*parts: str) -> list[str]:
    return [str(part) for part in parts if str(part)]


def detect_redacted_secret_material(text: str, *, max_bytes: int = 5_000_000) -> list[dict[str, Any]]:
    """Return redacted, non-reversible secret observations from stored source.

    This is an offline classifier.  It never returns a matched value.  Only an
    opaque fingerprint, normalized kind, confidence, assessment and safe reason
    strings are emitted.
    """
    compact = str(text or "")[:max_bytes]
    if not compact:
        return []
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, material: str, confidence: int, assessment: str, reasons: Iterable[str]) -> None:
        fp = _fingerprint(material)
        key = (kind, fp)
        if key in seen:
            return
        seen.add(key)
        observations.append({
            "secret_kind": kind,
            "value_fingerprint": fp,
            "confidence": max(0, min(100, int(confidence))),
            "assessment": assessment,
            "reasons": [str(reason) for reason in reasons if str(reason)],
            "raw_value_stored": False,
        })

    for match in _PRIVATE_KEY_BLOCK_RE.finditer(compact):
        block = match.group(0)
        body = re.sub(r"\s+", "", match.group("body") or "")
        if len(body) < 64 or _PLACEHOLDER_RE.search(body):
            add("private_key_block", block, 30, "likely_placeholder", _safe_reason(
                "A complete private-key block shape was observed but its body matches placeholder/test characteristics.",
                "Raw private-key material was fingerprinted and discarded.",
            ))
        else:
            add("private_key_block", block, 98, "credential_material_confirmed", _safe_reason(
                "A complete private-key block with non-trivial body material is embedded in stored client source.",
                "Credential structure is confirmed offline; validity is not tested.",
                "Raw private-key material was fingerprinted and discarded.",
            ))

    access_matches = list(_AWS_ACCESS_KEY_RE.finditer(compact))
    secret_matches = list(_AWS_SECRET_ASSIGNMENT_RE.finditer(compact))
    for access in access_matches[:50]:
        nearest = None
        nearest_distance = 10**9
        for secret in secret_matches[:50]:
            distance = abs(secret.start() - access.start())
            if distance <= 1200 and distance < nearest_distance:
                nearest = secret
                nearest_distance = distance
        if nearest is None:
            continue
        secret_value = nearest.group("value")
        material = access.group(0) + ":" + secret_value
        if _PLACEHOLDER_RE.search(material):
            assessment = "likely_placeholder"
            confidence = 30
            reason = "A paired AWS credential shape was observed but matches placeholder/test characteristics."
        else:
            assessment = "credential_material_confirmed"
            confidence = 97
            reason = "An AWS access-key identifier and 40-character secret-access-key value occur in the same local credential context."
        add("aws_credential_pair", material, confidence, assessment, _safe_reason(
            reason,
            "Credential structure is confirmed offline; no AWS request is made.",
            "Raw AWS credential material was fingerprinted and discarded.",
        ))

    for match in _GITHUB_TOKEN_RE.finditer(compact):
        token = match.group(0)
        window = compact[max(0, match.start() - 160): min(len(compact), match.end() + 160)]
        placeholder = bool(_PLACEHOLDER_RE.search(window))
        add(
            "github_token_material",
            token,
            30 if placeholder else 94,
            "likely_placeholder" if placeholder else "credential_material_confirmed",
            _safe_reason(
                "A provider-specific GitHub token structure is embedded in stored client source." if not placeholder else "A GitHub-token-shaped value appears in example/test context.",
                "Token validity or repository/account access is not tested.",
                "Raw token material was fingerprinted and discarded.",
            ),
        )

    for match in _STRIPE_SECRET_RE.finditer(compact):
        token = match.group(0)
        tier = str(match.group("tier") or "")
        assessment = "likely_placeholder" if tier == "test" else "credential_material_confirmed"
        confidence = 35 if tier == "test" else 94
        add(
            "stripe_secret_key_material",
            token,
            confidence,
            assessment,
            _safe_reason(
                "A Stripe test secret-key structure was observed and is treated as test material." if tier == "test" else "A Stripe live secret-key structure is embedded in stored client source.",
                "No Stripe API request is made.",
                "Raw token material was fingerprinted and discarded.",
            ),
        )

    for match in _JWT_RE.finditer(compact):
        token = match.group(0)
        window = compact[max(0, match.start() - 180): min(len(compact), match.end() + 180)]
        placeholder = bool(_PLACEHOLDER_RE.search(window))
        add(
            "jwt_token_material",
            token,
            25 if placeholder else 72,
            "likely_placeholder" if placeholder else "candidate",
            _safe_reason(
                "A three-segment JWT-shaped value is embedded in stored client source.",
                "JWT syntax alone does not establish that the token is live, privileged or unintended.",
                "Raw JWT material was fingerprinted and discarded.",
            ),
        )

    for match in _GENERIC_ASSIGNMENT_RE.finditer(compact):
        name = str(match.group("name") or "").lower().replace("-", "_")
        value = str(match.group("value") or "")
        window = compact[max(0, match.start() - 160): min(len(compact), match.end() + 160)]
        placeholder = bool(_PLACEHOLDER_RE.search(value) or _PLACEHOLDER_RE.search(window) or _TEMPLATE_RE.search(value))
        public_hint = any(hint in window.lower().replace("-", "_") for hint in _PUBLIC_IDENTIFIER_HINTS)
        if public_hint and name == "api_key":
            assessment = "intended_public_client_identifier"
            confidence = 35
            reason = "The API-key assignment is adjacent to an explicitly public/publishable client-identifier hint."
        elif placeholder:
            assessment = "likely_placeholder"
            confidence = 25
            reason = "The assigned value matches an example, placeholder, template or test-only pattern."
        else:
            material_like = len(value) >= 16 and _entropy(value) >= 3.0
            assessment = "candidate" if material_like else "surface_only"
            confidence = 62 if material_like else 35
            reason = "A non-placeholder secret-named assignment contains non-trivial literal material." if material_like else "A secret-named assignment was observed but the literal lacks enough structure for credential classification."
        add(
            f"{name}_assignment",
            value,
            confidence,
            assessment,
            _safe_reason(
                reason,
                "Generic literal assignments are not treated as confirmed live credentials.",
                "Raw literal material was fingerprinted and discarded.",
            ),
        )

    return observations


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "observed", "confirmed", "present", "live"}:
        return True
    if text in {"0", "false", "no", "not_observed", "absent", "inactive", "revoked"}:
        return False
    return None


def _safe_marker_class(value: str) -> str:
    label = str(value or "").split(":count=", 1)[0].strip().lower()
    return label if re.fullmatch(r"[a-z0-9_\-]{2,80}", label) else ""


def _normalize_observations(observations: Iterable[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in observations or []:
        row = dict(raw)
        result.append({
            "secret_kind": str(row.get("secret_kind") or row.get("kind") or "").strip(),
            "value_fingerprint": str(row.get("value_fingerprint") or "").strip()[:80],
            "confidence": max(0, min(100, int(row.get("confidence") or 0))),
            "assessment": str(row.get("assessment") or "candidate").strip().lower(),
            "reasons": [str(x) for x in row.get("reasons", []) if str(x)] if isinstance(row.get("reasons"), list) else [],
        })
    return result


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (str(item.get("type") or ""), str(item.get("source_group") or ""), str(item.get("text") or ""))
    if any((str(row.get("type") or ""), str(row.get("source_group") or ""), str(row.get("text") or "")) == key for row in items):
        return
    items.append(item)


def analyze_secret_exposure_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    js_url: str = "",
    observations: Iterable[Mapping[str, Any]] | None = None,
    marker_classes: Iterable[str] | None = None,
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    normalized = _normalize_observations(observations)
    markers = {str(value).strip().lower() for value in (marker_classes or []) if str(value).strip()}
    detail_markers = details.get("marker_classes", [])
    for value in (detail_markers if isinstance(detail_markers, list) else []):
        marker = _safe_marker_class(str(value))
        if marker:
            markers.add(marker)

    kinds = {row["secret_kind"] for row in normalized if row["secret_kind"]}
    if not kinds and not markers and not _truth(details.get("secret_pattern_observed")):
        return None

    assessments = {row["assessment"] for row in normalized}
    strong_kinds = {
        row["secret_kind"] for row in normalized
        if row["assessment"] in {"credential_material_confirmed", "live_secret_context"}
    }
    material_markers = bool(markers & _MATERIAL_MARKERS)
    concrete_material = bool(
        strong_kinds
        or material_markers
        or {kind for kind in kinds if kind not in {"sensitive_marker", "sensitive_assignment"} and not kind.endswith("_assignment")}
    )
    assignment_only = bool(kinds or markers) and not concrete_material and ("sensitive_assignment" in markers or any(kind.endswith("_assignment") for kind in kinds))
    all_placeholder = bool(normalized) and all(row["assessment"] == "likely_placeholder" for row in normalized)
    public_identifier_only = bool(normalized) and all(row["assessment"] == "intended_public_client_identifier" for row in normalized)

    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    _add_unique(support, {
        "type": "secret_pattern",
        "source": "secret_intelligence",
        "source_group": "secret_pattern_detection",
        "weight": 22,
        "text": "Stored JavaScript analysis contains a redacted credential-, token- or secret-shaped indicator; no raw value is included.",
    })

    # A separate exposure-context root is intentionally withheld for field-name
    # assignments and explicitly public client identifiers. This prevents an
    # `apiKey = ...` surface from satisfying both canonical promotion groups.
    if concrete_material and not all_placeholder and not public_identifier_only:
        _add_unique(support, {
            "type": "context",
            "source": "client_delivered_javascript",
            "source_group": "client_delivery_context",
            "weight": 18,
            "text": "Credential-shaped literal material is embedded in stored client-delivered JavaScript context.",
        })

    confirmed_material = any(row["assessment"] == "credential_material_confirmed" for row in normalized) or _truth(details.get("credential_material_confirmed")) is True
    live_context = any(row["assessment"] == "live_secret_context" for row in normalized)
    if _truth(details.get("live_secret_context")) is True and _truth(details.get("authorized_lifecycle_evidence")) is True:
        live_context = True

    if confirmed_material and not all_placeholder and not public_identifier_only:
        _add_unique(support, {
            "type": "credential_material_confirmed",
            "source": "stored_offline_secret_structure",
            "source_group": "credential_material_structure",
            "weight": 52,
            "text": "Stored offline analysis confirms structurally complete credential material; validity is not tested and raw material is not retained in analyzer output.",
        })
    if live_context and not all_placeholder and not public_identifier_only:
        _add_unique(support, {
            "type": "live_secret_context",
            "source": "authorized_stored_secret_lifecycle",
            "source_group": "stored_secret_lifecycle",
            "weight": 56,
            "text": "An already-authorized stored evidence source records the exposed credential material as live; the analyzer itself made no credential-use request.",
        })

    if all_placeholder or "likely_placeholder" in assessments and not confirmed_material:
        _add_unique(contradict, {
            "type": "placeholder",
            "source": "stored_secret_classification",
            "source_group": "secret_placeholder_control",
            "weight": -44,
            "text": "Stored offline classification indicates the observed material is an example, placeholder, template or test-only value.",
        })
    if public_identifier_only:
        _add_unique(contradict, {
            "type": "intended_public_client_identifier",
            "source": "stored_secret_classification",
            "source_group": "public_client_identifier_control",
            "weight": -36,
            "text": "Stored context classifies the observed value as an intentionally public/publishable client identifier rather than a secret credential.",
        })
    if assignment_only:
        _add_unique(contradict, {
            "type": "assignment_name_only",
            "source": "stored_secret_classification",
            "source_group": "secret_surface_only",
            "weight": -16,
            "text": "Only a secret-named assignment surface is established; structurally credential-shaped material is not confirmed.",
        })

    if _truth(details.get("revoked_or_inactive")) is True:
        _add_unique(contradict, {
            "type": "revoked_or_inactive_material",
            "source": "authorized_stored_secret_lifecycle",
            "source_group": "stored_secret_lifecycle",
            "weight": -24,
            "text": "Authorized stored lifecycle evidence records the material as revoked or inactive; this lowers present exploitability but does not erase historical exposure.",
        })

    observed = {str(item.get("type") or "") for item in support}
    blockers = {str(item.get("type") or "") for item in contradict}
    promotion_ready = "secret_pattern" in observed and "context" in observed and "placeholder" not in blockers
    confirmation_ready = bool(observed & {"credential_material_confirmed", "live_secret_context"}) and "placeholder" not in blockers
    confirmation_missing = list(confirmation_gaps("secret_exposure", observed))
    if confirmation_ready:
        confirmation_missing = []

    if "live_secret_context" in observed:
        variant = "stored_live_secret_context"
    elif "credential_material_confirmed" in observed:
        if "private_key_block" in strong_kinds:
            variant = "complete_private_key_material"
        elif "aws_credential_pair" in strong_kinds:
            variant = "paired_cloud_credential_material"
        elif strong_kinds:
            variant = "provider_credential_material"
        else:
            variant = "credential_material_confirmed"
    elif "placeholder" in blockers:
        variant = "placeholder_or_test_material"
    elif public_identifier_only:
        variant = "intended_public_client_identifier"
    elif assignment_only:
        variant = "secret_assignment_surface_only"
    elif concrete_material:
        variant = "credential_material_candidate"
    else:
        variant = "secret_pattern_surface"

    metadata = SecretExposureFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": SECRET_EXPOSURE_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in SECRET_EXPOSURE_TAXONOMY.items()},
        "methodology": [dict(step) for step in SECRET_EXPOSURE_METHOD],
        "false_positive_checks": list(SECRET_EXPOSURE_FALSE_POSITIVE_CHECKS),
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in SECRET_EXPOSURE_WRITEUP_PATTERNS],
        "observed_secret_kinds": sorted(kinds),
        "marker_classes": sorted(markers),
        "observation_count": len(normalized),
        "promotion_ready_from_stored_target_evidence": promotion_ready,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "confirmation_missing": confirmation_missing,
        "knowledge_does_not_change_target_evidence": True,
        "active_request_performed": False,
        "credential_validation_performed": False,
        "provider_request_performed": False,
        "credential_material_copied_to_output": False,
        "raw_value_stored_by_analyzer": False,
    })

    missing = list(FAMILY_REASONING["secret_exposure"]["next_evidence"])
    if confirmation_ready:
        missing = []

    return {
        "family": "secret_exposure",
        "variant": variant,
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-secret-pattern-surface",
            "family-secret-material-classification",
            "family-secret-placeholder-filter",
            "family-secret-exposure-context",
            "family-secret-no-online-validation",
        ],
        "summary": (
            "Stored offline target evidence confirms credential material embedded in client-delivered code; raw material remains redacted and no provider validation was performed."
            if confirmation_ready
            else "A redacted credential/token signal is retained according to material structure and exposure context; secret-named assignments and placeholders remain hidden or contradicted."
        ),
        "direct": confirmation_ready,
        "family_analyzer": metadata,
    }


class SecretExposureFamilyAnalyzer(FamilyAnalyzer):
    family = "secret_exposure"
    analyzer_version = SECRET_EXPOSURE_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_secret_exposure_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            js_url=str(kwargs.get("js_url") or context.endpoint or ""),
            observations=kwargs.get("observations"),
            marker_classes=kwargs.get("marker_classes"),
            details=context.details,
            business_context=context.business_context,
        )
