from __future__ import annotations

"""Offline review boundary for controlled GraphQL field-policy evidence.

This module performs no network I/O. It accepts only redacted, analyst-reviewed
response-shape metadata from explicitly controlled test roles, validates policy
provenance and freshness, classifies a bounded field-authorization outcome, and
persists review evidence. Raw field values and response bodies are never accepted.
"""

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now


GRAPHQL_DATA_DIFFERENTIAL_VERSION = "1.0.0"
GRAPHQL_DATA_DIFFERENTIAL_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,119}$")
_MODES = {"single_role_policy", "role_differential"}
_FORBIDDEN_VALUE_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "set_cookie",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "secret_value",
    "credential",
    "credentials",
    "raw_body",
    "response_body",
    "raw_response",
    "field_values",
    "response_values",
    "pii_values",
    "financial_values",
    "identity_value",
    "username",
    "email_address",
}


def ensure_graphql_data_differential_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS graphql_data_exposure_differential_runs (
          comparison_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          comparison_mode TEXT NOT NULL,
          artifact_hash TEXT NOT NULL,
          evidence_id TEXT NOT NULL DEFAULT '',
          signal_type TEXT NOT NULL DEFAULT '',
          polarity TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('graphql_data_exposure_differential_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(GRAPHQL_DATA_DIFFERENTIAL_SCHEMA_VERSION),),
    )


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("GraphQL field-policy artifact requires observed_at")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError("GraphQL field-policy artifact has an invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _load(path: str | Path) -> dict[str, Any]:
    artifact = Path(path).expanduser().resolve()
    if artifact.is_symlink():
        raise ReconError(f"Refusing symlinked GraphQL field-policy artifact: {artifact}")
    if not artifact.exists() or not artifact.is_file():
        raise ReconError(f"GraphQL field-policy artifact not found: {artifact}")
    if artifact.stat().st_size > 1024 * 1024:
        raise ReconError("GraphQL field-policy artifact exceeds the 1 MiB safety limit")
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError("GraphQL field-policy artifact is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReconError("GraphQL field-policy artifact must contain a JSON object")
    return dict(value)


def _reject_value_keys(value: Any, *, path: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in _FORBIDDEN_VALUE_KEYS:
                raise ReconError(
                    f"GraphQL field-policy artifact must not store raw values or secret material ({path}.{key})"
                )
            _reject_value_keys(nested, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_value_keys(nested, path=f"{path}[{index}]")


def _field_names(value: Any, *, field: str, required: bool = False) -> list[str]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ReconError(f"GraphQL field-policy {field} must be a list of field names")
    if len(value) > 128:
        raise ReconError(f"GraphQL field-policy {field} exceeds the field-count limit")
    result: list[str] = []
    for item in value:
        name = str(item or "").strip()
        if not _FIELD_RE.fullmatch(name):
            raise ReconError(f"GraphQL field-policy {field} contains an invalid field name")
        if name not in result:
            result.append(name)
    if required and not result:
        raise ReconError(f"GraphQL field-policy {field} must not be empty")
    return result


def _role(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconError(f"GraphQL field-policy artifact requires {field} role metadata")
    role_class = str(value.get("role_class") or "").strip().lower()
    if not _ROLE_RE.fullmatch(role_class):
        raise ReconError(f"GraphQL field-policy {field}.role_class must be an abstract role class")
    if not bool(value.get("controlled_test_role")):
        raise ReconError("GraphQL field-policy evidence requires explicitly controlled test roles")
    if bool(value.get("raw_field_values_stored")) or bool(value.get("raw_body_stored")):
        raise ReconError("GraphQL field-policy role observations must remain value-redacted")
    return {
        "role_class": role_class,
        "controlled_test_role": True,
        "observed_fields": _field_names(value.get("observed_fields"), field=f"{field}.observed_fields"),
        "raw_field_values_stored": False,
        "raw_body_stored": False,
    }


def _classify(normalized: Mapping[str, Any]) -> tuple[str, str, str]:
    if bool(normalized["confounded"]):
        return "", "contradict", "comparison_confounded"

    restricted = set(normalized["restricted_fields"])
    tested = set(normalized["tested_role"]["observed_fields"])
    violating = sorted(restricted & tested)

    if bool(normalized["field_authorization_observed"]) and not violating:
        return "field_authorization_observed", "contradict", "field_authorization_enforced"
    if not violating:
        return "sensitive_fields_not_returned", "contradict", "restricted_fields_absent"

    if str(normalized["comparison_mode"]) == "role_differential":
        reference = normalized.get("reference_role") or {}
        reference_fields = set(reference.get("observed_fields") or [])
        reference_visible = sorted(restricted & reference_fields)
        if not bool(normalized["reference_role_authorized_for_restricted_fields"]):
            return "", "contradict", "reference_role_policy_not_explicit"
        if not reference_visible:
            return "", "contradict", "reference_role_does_not_establish_field_baseline"
        if not set(violating).issubset(set(reference_visible)):
            return "", "contradict", "role_comparison_not_like_for_like"
        return "field_authorization_differential", "support", "restricted_role_received_reference_authorized_fields"

    return "sensitive_graphql_response_observed", "support", "restricted_fields_returned_to_controlled_role"


def validate_graphql_data_exposure_artifact(
    artifact: Mapping[str, Any],
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    _reject_value_keys(artifact)
    if str(artifact.get("version") or "") != GRAPHQL_DATA_DIFFERENTIAL_VERSION:
        raise ReconError("Unsupported GraphQL field-policy artifact version")
    if not bool(artifact.get("analyst_verified")):
        raise ReconError("GraphQL field-policy artifact requires explicit analyst verification")
    if not bool(artifact.get("controlled_test_roles_only")):
        raise ReconError("GraphQL field-policy artifact requires controlled test roles only")
    if bool(artifact.get("real_user_data_used")):
        raise ReconError("GraphQL field-policy artifact must not use real-user data")
    if bool(artifact.get("raw_field_values_stored")) or bool(artifact.get("raw_body_stored")):
        raise ReconError("GraphQL field-policy artifact must remain value-redacted")
    if not bool(artifact.get("policy_documented")):
        raise ReconError("GraphQL field-policy artifact requires a documented field policy")

    comparison_id = str(artifact.get("comparison_id") or "").strip()
    if not comparison_id.startswith("GQLD-") or len(comparison_id) > 80:
        raise ReconError("GraphQL field-policy artifact has an invalid comparison_id")
    comparison_mode = str(artifact.get("comparison_mode") or "").strip()
    if comparison_mode not in _MODES:
        raise ReconError("GraphQL field-policy artifact has an unsupported comparison_mode")

    operation_fingerprint = str(artifact.get("operation_fingerprint") or "").strip()
    policy_source_fingerprint = str(artifact.get("policy_source_fingerprint") or "").strip()
    if not _HASH_RE.fullmatch(operation_fingerprint):
        raise ReconError("GraphQL field-policy artifact requires an operation fingerprint")
    if not _HASH_RE.fullmatch(policy_source_fingerprint):
        raise ReconError("GraphQL field-policy artifact requires a policy source fingerprint")

    identity: dict[str, str] = {}
    for key in ("run_id", "analysis_id", "target", "hypothesis_id"):
        rendered = str(artifact.get(key) or "").strip()
        if not rendered:
            raise ReconError(f"GraphQL field-policy artifact is missing {key}")
        identity[key] = rendered

    observed = _parse_time(artifact.get("observed_at"))
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if max_age_seconds <= 0 or age < -300 or age > max_age_seconds:
        raise ReconError("GraphQL field-policy artifact is outside the freshness window")

    operation_name = str(artifact.get("operation_name") or "").strip()
    if len(operation_name) > 160:
        raise ReconError("GraphQL field-policy operation_name is too long")

    tested_role = _role(artifact.get("tested_role"), field="tested_role")
    reference_role = None
    if comparison_mode == "role_differential":
        reference_role = _role(artifact.get("reference_role"), field="reference_role")
        if reference_role["role_class"] == tested_role["role_class"]:
            raise ReconError("GraphQL role differential requires distinct abstract role classes")

    normalized = {
        "version": GRAPHQL_DATA_DIFFERENTIAL_VERSION,
        "comparison_id": comparison_id,
        **identity,
        "comparison_mode": comparison_mode,
        "operation_name": operation_name[:160],
        "operation_fingerprint": operation_fingerprint.lower(),
        "policy_source_fingerprint": policy_source_fingerprint.lower(),
        "policy_documented": True,
        "restricted_fields": _field_names(
            artifact.get("restricted_fields"), field="restricted_fields", required=True
        ),
        "tested_role": tested_role,
        "reference_role": reference_role,
        "reference_role_authorized_for_restricted_fields": bool(
            artifact.get("reference_role_authorized_for_restricted_fields")
        ),
        "field_authorization_observed": bool(artifact.get("field_authorization_observed")),
        "confounded": bool(artifact.get("policy_ambiguous"))
        or bool(artifact.get("role_context_ambiguous"))
        or bool(artifact.get("partial_response_confounded"))
        or bool(artifact.get("graphql_error_confounded"))
        or bool(artifact.get("cache_confounded")),
        "observed_at": str(artifact.get("observed_at")),
        "analyst_verified": True,
        "reviewed_by": str(artifact.get("reviewed_by") or "analyst")[:200],
        "controlled_test_roles_only": True,
        "real_user_data_used": False,
        "raw_field_values_stored": False,
        "raw_body_stored": False,
        "affects_admission": False,
        "affects_candidate_promotion": False,
    }
    signal_type, polarity, reason = _classify(normalized)
    normalized["signal_type"] = signal_type
    normalized["polarity"] = polarity
    normalized["classification_reason"] = reason
    normalized["artifact_hash"] = sha256_text(json_dumps(normalized))
    return normalized


def review_graphql_data_exposure_artifact(
    db: Database,
    *,
    artifact_path: str | Path,
    actor: str = "analyst",
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Validate and persist one redacted GraphQL field-policy comparison without promotion."""

    ensure_graphql_data_differential_schema(db)
    normalized = validate_graphql_data_exposure_artifact(
        _load(artifact_path), max_age_seconds=max_age_seconds
    )
    comparison_id = str(normalized["comparison_id"])
    artifact_hash = str(normalized["artifact_hash"])

    previous = db.one(
        "SELECT * FROM graphql_data_exposure_differential_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously reviewed GraphQL field-policy evidence has changed")
        return {
            "version": GRAPHQL_DATA_DIFFERENTIAL_VERSION,
            "status": "already_applied",
            "comparison_id": comparison_id,
            "evidence_id": str(previous["evidence_id"] or ""),
            "signal_type": str(previous["signal_type"] or ""),
            "polarity": str(previous["polarity"] or ""),
            "network_requests_executed": 0,
            "vulnerability_confirmed": False,
        }

    hypothesis_row = db.one(
        "SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(normalized["hypothesis_id"]),),
    )
    if not hypothesis_row:
        raise ReconError("GraphQL field-policy hypothesis was not found")
    hypothesis = dict(hypothesis_row)
    if str(hypothesis.get("bug_family") or "") != "graphql_data_exposure":
        raise ReconError("GraphQL field-policy review requires a graphql_data_exposure hypothesis")

    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        if str(normalized.get(key) or "") != value:
            raise ReconError(f"GraphQL field-policy artifact {key} mismatch")

    root = sha256_text(
        "|".join(
            [
                "graphql-data-exposure-differential",
                comparison_id,
                expected["target"],
                str(normalized["operation_fingerprint"]),
                str(normalized["policy_source_fingerprint"]),
            ]
        )
    )
    evidence_id = "EVD-" + sha256_text(root + "|" + artifact_hash)[:16].upper()
    signal_type = str(normalized["signal_type"] or "")
    polarity = str(normalized["polarity"] or "contradict")
    if signal_type in {"sensitive_graphql_response_observed", "field_authorization_differential"} and polarity == "support":
        evidence_type = "controlled_graphql_field_policy_violation"
        directness = "direct"
        summary = (
            "Analyst-reviewed controlled GraphQL response-shape metadata records a field-policy violation; "
            "only field names and abstract role context are retained."
        )
    elif signal_type:
        evidence_type = "controlled_graphql_field_policy_control"
        directness = "direct"
        summary = (
            "Analyst-reviewed controlled GraphQL response-shape metadata records an enforcing field-policy control; "
            "this evidence does not support promotion."
        )
    else:
        evidence_type = "controlled_graphql_field_policy_inconclusive"
        directness = "contextual"
        summary = "Controlled GraphQL field-policy evidence is inconclusive or confounded and cannot support promotion."

    with db.transaction():
        db.execute(
            """INSERT OR IGNORE INTO evidence_records(
            evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,
            parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,
            raw_reference,integrity_hash,first_seen,last_seen,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                expected["analysis_id"],
                expected["run_id"],
                expected["target"],
                evidence_type,
                polarity,
                "analyst_verified_controlled_graphql",
                "graphql_data_exposure_differential",
                Path(artifact_path).name[:240],
                "graphql_data_exposure_differential",
                GRAPHQL_DATA_DIFFERENTIAL_VERSION,
                f"controlled_graphql:{comparison_id}",
                root,
                90,
                94,
                directness,
                summary,
                f"graphql_data_exposure:{comparison_id}",
                artifact_hash,
                str(normalized["observed_at"]),
                str(normalized["observed_at"]),
                utc_now(),
            ),
        )
        stored = db.one(
            "SELECT evidence_id,integrity_hash FROM evidence_records WHERE evidence_id=?",
            (evidence_id,),
        )
        if not stored or str(stored["integrity_hash"] or "") != artifact_hash:
            raise ReconError("GraphQL field-policy evidence collision or mutable evidence detected")
        db.execute(
            """INSERT INTO graphql_data_exposure_differential_runs(
            comparison_id,analysis_id,hypothesis_id,source_run_id,target,comparison_mode,artifact_hash,
            evidence_id,signal_type,polarity,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                comparison_id,
                expected["analysis_id"],
                str(normalized["hypothesis_id"]),
                expected["run_id"],
                expected["target"],
                str(normalized["comparison_mode"]),
                artifact_hash,
                evidence_id,
                signal_type,
                polarity,
                "reviewed",
                utc_now(),
            ),
        )
        db.audit(
            "graphql_data_exposure_differential_reviewed",
            actor=actor,
            target=expected["target"],
            entity_type="analysis_hypothesis",
            entity_value=str(normalized["hypothesis_id"]),
            details={
                "comparison_id": comparison_id,
                "comparison_mode": str(normalized["comparison_mode"]),
                "evidence_id": evidence_id,
                "signal_type": signal_type,
                "polarity": polarity,
                "confounded": bool(normalized["confounded"]),
                "affects_admission": False,
                "affects_candidate_promotion": False,
                "network_requests_executed": 0,
                "raw_field_values_stored": False,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": GRAPHQL_DATA_DIFFERENTIAL_VERSION,
        "status": "reviewed",
        "comparison_id": comparison_id,
        "analysis_id": expected["analysis_id"],
        "hypothesis_id": str(normalized["hypothesis_id"]),
        "target": expected["target"],
        "comparison_mode": str(normalized["comparison_mode"]),
        "evidence_id": evidence_id,
        "signal_type": signal_type,
        "polarity": polarity,
        "classification_reason": str(normalized["classification_reason"]),
        "confounded": bool(normalized["confounded"]),
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "network_requests_executed": 0,
        "real_user_data_used": False,
        "raw_field_values_stored": False,
        "vulnerability_confirmed": False,
    }
