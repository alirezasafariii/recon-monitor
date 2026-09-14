from __future__ import annotations

"""Offline review boundary for controlled authentication/session lifecycle evidence.

This module performs no network I/O. It accepts only redacted, analyst-reviewed
metadata from explicitly controlled test sessions, validates provenance and
freshness, classifies a bounded lifecycle transition, and persists review evidence.
It never performs login/logout/refresh requests and never creates a Candidate.
"""

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now


AUTH_SESSION_DIFFERENTIAL_VERSION = "1.0.0"
AUTH_SESSION_DIFFERENTIAL_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")
_TRANSITIONS = {
    "logout_invalidation",
    "token_rotation",
    "expiration",
    "authentication_state",
}
_FORBIDDEN_SECRET_KEYS = {
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
    "session_id",
    "session_cookie",
    "credential",
    "credentials",
    "username",
    "email",
    "identity_value",
}
_DENY_STATUSES = {400, 401, 403, 404, 409, 410, 422}


def ensure_auth_session_differential_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS authentication_session_differential_runs (
          lifecycle_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          transition_type TEXT NOT NULL,
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
        "INSERT INTO schema_meta(key,value) VALUES('authentication_session_differential_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(AUTH_SESSION_DIFFERENTIAL_SCHEMA_VERSION),),
    )


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("Authentication lifecycle artifact requires observed_at")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError("Authentication lifecycle artifact has an invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _load(path: str | Path) -> dict[str, Any]:
    artifact = Path(path).expanduser().resolve()
    if artifact.is_symlink():
        raise ReconError(f"Refusing symlinked authentication lifecycle artifact: {artifact}")
    if not artifact.exists() or not artifact.is_file():
        raise ReconError(f"Authentication lifecycle artifact not found: {artifact}")
    if artifact.stat().st_size > 1024 * 1024:
        raise ReconError("Authentication lifecycle artifact exceeds the 1 MiB safety limit")
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError("Authentication lifecycle artifact is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReconError("Authentication lifecycle artifact must contain a JSON object")
    return dict(value)


def _reject_secret_keys(value: Any, *, path: str = "artifact") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in _FORBIDDEN_SECRET_KEYS:
                raise ReconError(
                    f"Authentication lifecycle artifact must not store raw secret or identity material ({path}.{key})"
                )
            _reject_secret_keys(nested, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secret_keys(nested, path=f"{path}[{index}]")


def _optional_bool(value: Any, *, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ReconError(f"Authentication lifecycle field {field} must be boolean")
    return value


def _observation(value: Any, *, phase: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconError("Authentication lifecycle artifact requires before/after observation objects")
    if not bool(value.get("controlled_test_session")):
        raise ReconError("Authentication lifecycle evidence requires an explicitly controlled test session")
    if bool(value.get("raw_secret_material_stored")):
        raise ReconError("Authentication lifecycle evidence must not store raw session or credential material")

    status = int(value.get("status_code") or 0)
    if status < 100 or status > 599:
        raise ReconError("Authentication lifecycle observation has an invalid status_code")

    fingerprint = str(value.get("session_fingerprint") or "").strip()
    if fingerprint and not _HASH_RE.fullmatch(fingerprint):
        raise ReconError("Authentication lifecycle session_fingerprint must be a one-way fingerprint")

    return {
        "phase": phase,
        "controlled_test_session": True,
        "raw_secret_material_stored": False,
        "status_code": status,
        "authenticated": _optional_bool(value.get("authenticated"), field=f"{phase}.authenticated"),
        "access_granted": _optional_bool(value.get("access_granted"), field=f"{phase}.access_granted"),
        "expired": _optional_bool(value.get("expired"), field=f"{phase}.expired"),
        "session_fingerprint": fingerprint.lower(),
    }


def _classify(normalized: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return (signal_type, polarity, reason). Empty signal means non-promoting review evidence."""

    transition = str(normalized["transition_type"])
    before = normalized["before"]
    after = normalized["after"]
    confounded = bool(normalized["confounded"])
    if confounded:
        return "", "contradict", "comparison_confounded"

    if transition == "logout_invalidation":
        if normalized["expected_after_access_granted"] is not False:
            return "", "contradict", "logout_expectation_not_explicit"
        if before["access_granted"] is not True:
            return "", "contradict", "logout_baseline_access_not_established"
        if after["access_granted"] is True:
            return "session_reuse_after_logout", "support", "session_remained_usable_after_logout"
        if after["access_granted"] is False or after["status_code"] in _DENY_STATUSES:
            return "logout_invalidation_observed", "contradict", "logout_invalidation_enforced"
        return "", "contradict", "logout_result_inconclusive"

    if transition == "token_rotation":
        if normalized["rotation_expected"] is not True:
            return "", "contradict", "rotation_expectation_not_explicit"
        before_fp = str(before["session_fingerprint"] or "")
        after_fp = str(after["session_fingerprint"] or "")
        if not before_fp or not after_fp:
            return "", "contradict", "rotation_fingerprint_missing"
        if before_fp == after_fp:
            return "token_not_rotated", "support", "required_rotation_did_not_occur"
        return "session_rotation_observed", "contradict", "session_rotation_observed"

    if transition == "expiration":
        if normalized["expiration_expected"] is not True or after["expired"] is not True:
            return "", "contradict", "expiration_boundary_not_established"
        if normalized["expected_after_access_granted"] is not False:
            return "", "contradict", "expiration_expectation_not_explicit"
        if after["access_granted"] is True:
            return "authentication_state_violation", "support", "expired_session_still_granted_access"
        if after["access_granted"] is False or after["status_code"] in _DENY_STATUSES:
            return "expired_session_rejected", "contradict", "expired_session_rejected"
        return "", "contradict", "expiration_result_inconclusive"

    if transition == "authentication_state":
        expected_access = normalized["expected_after_access_granted"]
        expected_authenticated = normalized["expected_after_authenticated"]
        if expected_access is None and expected_authenticated is None:
            return "", "contradict", "authentication_expectation_missing"
        violation = False
        if expected_access is not None and after["access_granted"] is not None:
            violation = violation or after["access_granted"] != expected_access
        if expected_authenticated is not None and after["authenticated"] is not None:
            violation = violation or after["authenticated"] != expected_authenticated
        if violation:
            return "authentication_state_violation", "support", "authentication_state_mismatched_expectation"
        return "authentication_state_enforced", "contradict", "authentication_state_matched_expectation"

    return "", "contradict", "unsupported_transition"


def validate_authentication_session_artifact(
    artifact: Mapping[str, Any],
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    _reject_secret_keys(artifact)
    if str(artifact.get("version") or "") != AUTH_SESSION_DIFFERENTIAL_VERSION:
        raise ReconError("Unsupported authentication lifecycle artifact version")
    if not bool(artifact.get("analyst_verified")):
        raise ReconError("Authentication lifecycle artifact requires explicit analyst verification")
    if not bool(artifact.get("controlled_test_session_only")):
        raise ReconError("Authentication lifecycle artifact requires controlled test sessions only")
    if bool(artifact.get("real_user_data_used")):
        raise ReconError("Authentication lifecycle artifact must not use real-user data")
    if bool(artifact.get("raw_secret_material_stored")) or bool(artifact.get("raw_body_stored")):
        raise ReconError("Authentication lifecycle artifact must remain redacted")

    lifecycle_id = str(artifact.get("lifecycle_id") or "").strip()
    if not lifecycle_id.startswith("ASL-") or len(lifecycle_id) > 80:
        raise ReconError("Authentication lifecycle artifact has an invalid lifecycle_id")
    transition_type = str(artifact.get("transition_type") or "").strip()
    if transition_type not in _TRANSITIONS:
        raise ReconError("Authentication lifecycle artifact has an unsupported transition_type")
    operation_fingerprint = str(artifact.get("operation_fingerprint") or "").strip()
    if not _HASH_RE.fullmatch(operation_fingerprint):
        raise ReconError("Authentication lifecycle artifact requires an operation fingerprint")

    identity: dict[str, str] = {}
    for key in ("run_id", "analysis_id", "target", "hypothesis_id"):
        rendered = str(artifact.get(key) or "").strip()
        if not rendered:
            raise ReconError(f"Authentication lifecycle artifact is missing {key}")
        identity[key] = rendered

    observed = _parse_time(artifact.get("observed_at"))
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if max_age_seconds <= 0 or age < -300 or age > max_age_seconds:
        raise ReconError("Authentication lifecycle artifact is outside the freshness window")

    normalized = {
        "version": AUTH_SESSION_DIFFERENTIAL_VERSION,
        "lifecycle_id": lifecycle_id,
        **identity,
        "transition_type": transition_type,
        "operation_fingerprint": operation_fingerprint.lower(),
        "before": _observation(artifact.get("before"), phase="before"),
        "after": _observation(artifact.get("after"), phase="after"),
        "expected_after_access_granted": _optional_bool(
            artifact.get("expected_after_access_granted"), field="expected_after_access_granted"
        ),
        "expected_after_authenticated": _optional_bool(
            artifact.get("expected_after_authenticated"), field="expected_after_authenticated"
        ),
        "rotation_expected": _optional_bool(artifact.get("rotation_expected"), field="rotation_expected"),
        "expiration_expected": _optional_bool(artifact.get("expiration_expected"), field="expiration_expected"),
        "confounded": bool(artifact.get("rate_limit_confounded"))
        or bool(artifact.get("challenge_confounded"))
        or bool(artifact.get("clock_confounded"))
        or bool(artifact.get("policy_ambiguous")),
        "observed_at": str(artifact.get("observed_at")),
        "analyst_verified": True,
        "reviewed_by": str(artifact.get("reviewed_by") or "analyst")[:200],
        "controlled_test_session_only": True,
        "real_user_data_used": False,
        "raw_secret_material_stored": False,
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


def review_authentication_session_artifact(
    db: Database,
    *,
    artifact_path: str | Path,
    actor: str = "analyst",
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Validate and persist one redacted lifecycle comparison without promotion."""

    ensure_auth_session_differential_schema(db)
    normalized = validate_authentication_session_artifact(
        _load(artifact_path), max_age_seconds=max_age_seconds
    )
    lifecycle_id = str(normalized["lifecycle_id"])
    artifact_hash = str(normalized["artifact_hash"])

    previous = db.one(
        "SELECT * FROM authentication_session_differential_runs WHERE lifecycle_id=?",
        (lifecycle_id,),
    )
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously reviewed authentication lifecycle evidence has changed")
        return {
            "version": AUTH_SESSION_DIFFERENTIAL_VERSION,
            "status": "already_applied",
            "lifecycle_id": lifecycle_id,
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
        raise ReconError("Authentication lifecycle hypothesis was not found")
    hypothesis = dict(hypothesis_row)
    if str(hypothesis.get("bug_family") or "") != "authentication_session":
        raise ReconError("Authentication lifecycle review requires an authentication_session hypothesis")

    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        if str(normalized.get(key) or "") != value:
            raise ReconError(f"Authentication lifecycle artifact {key} mismatch")

    root = sha256_text(
        "|".join(
            [
                "authentication-session-differential",
                lifecycle_id,
                expected["target"],
                str(normalized["transition_type"]),
            ]
        )
    )
    evidence_id = "EVD-" + sha256_text(root + "|" + artifact_hash)[:16].upper()
    signal_type = str(normalized["signal_type"] or "")
    polarity = str(normalized["polarity"] or "contradict")
    if signal_type and polarity == "support":
        evidence_type = "controlled_auth_session_lifecycle_failure"
        directness = "direct"
        summary = (
            "Analyst-reviewed metadata from a controlled test session records a lifecycle boundary failure "
            f"({signal_type}); no raw session or credential material is retained."
        )
    elif signal_type:
        evidence_type = "controlled_auth_session_control_observed"
        directness = "direct"
        summary = (
            "Analyst-reviewed metadata from a controlled test session records an enforcing lifecycle control "
            f"({signal_type}); this evidence does not support promotion."
        )
    else:
        evidence_type = "controlled_auth_session_comparison_inconclusive"
        directness = "contextual"
        summary = "Controlled authentication/session lifecycle evidence is inconclusive or confounded and cannot support promotion."

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
                "analyst_verified_controlled_session",
                "authentication_session_differential",
                Path(artifact_path).name[:240],
                "authentication_session_differential",
                AUTH_SESSION_DIFFERENTIAL_VERSION,
                f"controlled_auth_session:{lifecycle_id}",
                root,
                90,
                94,
                directness,
                summary,
                f"authentication_session:{lifecycle_id}",
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
            raise ReconError("Authentication lifecycle evidence collision or mutable evidence detected")
        db.execute(
            """INSERT INTO authentication_session_differential_runs(
            lifecycle_id,analysis_id,hypothesis_id,source_run_id,target,transition_type,artifact_hash,
            evidence_id,signal_type,polarity,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                lifecycle_id,
                expected["analysis_id"],
                str(normalized["hypothesis_id"]),
                expected["run_id"],
                expected["target"],
                str(normalized["transition_type"]),
                artifact_hash,
                evidence_id,
                signal_type,
                polarity,
                "reviewed",
                utc_now(),
            ),
        )
        db.audit(
            "authentication_session_differential_reviewed",
            actor=actor,
            target=expected["target"],
            entity_type="analysis_hypothesis",
            entity_value=str(normalized["hypothesis_id"]),
            details={
                "lifecycle_id": lifecycle_id,
                "transition_type": str(normalized["transition_type"]),
                "evidence_id": evidence_id,
                "signal_type": signal_type,
                "polarity": polarity,
                "confounded": bool(normalized["confounded"]),
                "affects_admission": False,
                "affects_candidate_promotion": False,
                "network_requests_executed": 0,
                "raw_secret_material_stored": False,
                "vulnerability_confirmed": False,
            },
        )

    return {
        "version": AUTH_SESSION_DIFFERENTIAL_VERSION,
        "status": "reviewed",
        "lifecycle_id": lifecycle_id,
        "analysis_id": expected["analysis_id"],
        "hypothesis_id": str(normalized["hypothesis_id"]),
        "target": expected["target"],
        "transition_type": str(normalized["transition_type"]),
        "evidence_id": evidence_id,
        "signal_type": signal_type,
        "polarity": polarity,
        "classification_reason": str(normalized["classification_reason"]),
        "confounded": bool(normalized["confounded"]),
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "network_requests_executed": 0,
        "real_user_data_used": False,
        "raw_secret_material_stored": False,
        "vulnerability_confirmed": False,
    }
