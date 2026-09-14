from __future__ import annotations

"""Offline review boundary for analyst-supplied controlled identity comparisons.

This module performs no network I/O and does not mutate Admission or Candidate
state. It validates a redacted comparison between two explicitly controlled test
identities, records provenance-preserving evidence, and leaves interpretation to
later family-specific reasoning.
"""

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now


CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION = "1.0.0"
CONTROLLED_IDENTITY_DIFFERENTIAL_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")
_CLASS_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_FORBIDDEN_IDENTITY_KEYS = {
    "username", "email", "email_address", "phone", "phone_number", "user_id",
    "account", "account_id", "identity_value", "identifier_value", "login_value",
}


def ensure_controlled_identity_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS controlled_identity_differential_runs (
          comparison_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          artifact_hash TEXT NOT NULL,
          evidence_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('controlled_identity_differential_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(CONTROLLED_IDENTITY_DIFFERENTIAL_SCHEMA_VERSION),),
    )


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("Controlled identity comparison requires observed_at")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError("Controlled identity comparison has an invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _load(path: str | Path) -> dict[str, Any]:
    artifact = Path(path).expanduser().resolve()
    if artifact.is_symlink():
        raise ReconError(f"Refusing symlinked controlled identity artifact: {artifact}")
    if not artifact.exists() or not artifact.is_file():
        raise ReconError(f"Controlled identity artifact not found: {artifact}")
    if artifact.stat().st_size > 1024 * 1024:
        raise ReconError("Controlled identity artifact exceeds the 1 MiB safety limit")
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError("Controlled identity artifact is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReconError("Controlled identity artifact must contain a JSON object")
    return dict(value)


def _observation(value: Any, *, expected_class: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconError("Controlled identity comparison requires two observation objects")
    lowered = {str(key).strip().lower() for key in value.keys()}
    if lowered & _FORBIDDEN_IDENTITY_KEYS:
        raise ReconError("Controlled identity comparison must not store identity values")
    if not bool(value.get("controlled_identity")):
        raise ReconError("Controlled identity comparison requires controlled test identities")
    if bool(value.get("identity_value_stored")):
        raise ReconError("Controlled identity comparison must not store identity values")
    if str(value.get("identity_class") or "").strip() != expected_class:
        raise ReconError("Controlled identity comparison identity class mismatch")

    status = int(value.get("status_code") or 0)
    if status < 100 or status > 599:
        raise ReconError("Controlled identity comparison has an invalid status_code")
    response_class = str(value.get("response_class") or "").strip()
    if response_class and not _CLASS_RE.fullmatch(response_class):
        raise ReconError("Controlled identity comparison has an invalid response_class")
    shape_hash = str(value.get("shape_hash") or "").strip()
    if shape_hash and not _HASH_RE.fullmatch(shape_hash):
        raise ReconError("Controlled identity comparison has an invalid shape_hash")

    return {
        "identity_class": expected_class,
        "controlled_identity": True,
        "identity_value_stored": False,
        "status_code": status,
        "response_class": response_class,
        "shape_hash": shape_hash.lower(),
    }


def validate_controlled_identity_artifact(
    artifact: Mapping[str, Any],
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    if str(artifact.get("version") or "") != CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION:
        raise ReconError("Unsupported controlled identity comparison version")
    if not bool(artifact.get("analyst_verified")):
        raise ReconError("Controlled identity comparison requires explicit analyst verification")
    if not bool(artifact.get("controlled_identities_only")):
        raise ReconError("Controlled identity comparison requires controlled identities only")
    if bool(artifact.get("real_user_data_used")):
        raise ReconError("Controlled identity comparison must not use real-user data")
    if bool(artifact.get("identity_values_stored")) or bool(artifact.get("raw_body_stored")):
        raise ReconError("Controlled identity comparison must remain redacted")

    comparison_id = str(artifact.get("comparison_id") or "").strip()
    if not comparison_id.startswith("CID-") or len(comparison_id) > 80:
        raise ReconError("Controlled identity comparison has an invalid comparison_id")
    operation_fingerprint = str(artifact.get("operation_fingerprint") or "").strip()
    if not _HASH_RE.fullmatch(operation_fingerprint):
        raise ReconError("Controlled identity comparison requires an operation fingerprint")

    identity: dict[str, str] = {}
    for key in ("run_id", "analysis_id", "target", "hypothesis_id"):
        rendered = str(artifact.get(key) or "").strip()
        if not rendered:
            raise ReconError(f"Controlled identity comparison is missing {key}")
        identity[key] = rendered

    observed = _parse_time(artifact.get("observed_at"))
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if max_age_seconds <= 0 or age < -300 or age > max_age_seconds:
        raise ReconError("Controlled identity comparison is outside the freshness window")

    existing = _observation(
        artifact.get("existing_test_identity"),
        expected_class="owned_test_existing",
    )
    absent = _observation(
        artifact.get("absent_test_identity"),
        expected_class="synthetic_test_absent",
    )

    confounded = bool(artifact.get("rate_limit_confounded")) or bool(
        artifact.get("challenge_confounded")
    )
    dimensions: list[str] = []
    if existing["status_code"] != absent["status_code"]:
        dimensions.append("status_code")
    if (
        existing["response_class"]
        and absent["response_class"]
        and existing["response_class"] != absent["response_class"]
    ):
        dimensions.append("response_class")
    if (
        existing["shape_hash"]
        and absent["shape_hash"]
        and existing["shape_hash"] != absent["shape_hash"]
    ):
        dimensions.append("shape_hash")

    normalized = {
        "version": CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION,
        "comparison_id": comparison_id,
        **identity,
        "operation_fingerprint": operation_fingerprint.lower(),
        "existing_test_identity": existing,
        "absent_test_identity": absent,
        "response_difference_dimensions": dimensions,
        "material_response_difference": bool(dimensions),
        "confounded": confounded,
        "observed_at": str(artifact.get("observed_at")),
        "analyst_verified": True,
        "reviewed_by": str(artifact.get("reviewed_by") or "analyst")[:200],
        "controlled_identities_only": True,
        "real_user_data_used": False,
        "identity_values_stored": False,
        "raw_body_stored": False,
        "affects_admission": False,
        "affects_candidate_promotion": False,
    }
    normalized["artifact_hash"] = sha256_text(json_dumps(normalized))
    return normalized


def review_controlled_identity_artifact(
    db: Database,
    *,
    artifact_path: str | Path,
    actor: str = "analyst",
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Validate and persist a comparison as review evidence without promotion."""

    ensure_controlled_identity_schema(db)
    normalized = validate_controlled_identity_artifact(
        _load(artifact_path),
        max_age_seconds=max_age_seconds,
    )
    comparison_id = str(normalized["comparison_id"])
    artifact_hash = str(normalized["artifact_hash"])

    previous = db.one(
        "SELECT * FROM controlled_identity_differential_runs WHERE comparison_id=?",
        (comparison_id,),
    )
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously reviewed controlled identity evidence has changed")
        return {
            "version": CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION,
            "status": "already_applied",
            "comparison_id": comparison_id,
            "evidence_id": str(previous["evidence_id"] or ""),
            "material_response_difference": bool(normalized["material_response_difference"]),
            "confounded": bool(normalized["confounded"]),
            "affects_admission": False,
            "affects_candidate_promotion": False,
            "network_requests_executed": 0,
        }

    hypothesis = db.one(
        "SELECT analysis_id,source_run_id,target FROM analysis_hypotheses WHERE hypothesis_id=?",
        (str(normalized["hypothesis_id"]),),
    )
    if not hypothesis:
        raise ReconError("Controlled identity comparison hypothesis was not found")
    expected = {
        "analysis_id": str(hypothesis["analysis_id"] or ""),
        "run_id": str(hypothesis["source_run_id"] or ""),
        "target": str(hypothesis["target"] or ""),
    }
    for key, value in expected.items():
        if str(normalized.get(key) or "") != value:
            raise ReconError(f"Controlled identity comparison {key} mismatch")

    root = sha256_text(
        "|".join(["controlled-identity-differential", comparison_id, expected["target"]])
    )
    evidence_id = "EVD-" + sha256_text(root + "|" + artifact_hash)[:16].upper()
    summary = (
        "Analyst-reviewed comparison of two controlled test identities records redacted "
        "response-profile metadata only. It does not satisfy Admission or confirm a vulnerability."
    )
    polarity = "support" if normalized["material_response_difference"] and not normalized["confounded"] else "contradict"
    evidence_type = (
        "controlled_identity_response_difference"
        if polarity == "support"
        else "controlled_identity_comparison_inconclusive"
    )

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
                "analyst_verified_controlled_identity",
                "controlled_identity_differential",
                Path(artifact_path).name[:240],
                "controlled_identity_differential",
                CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION,
                f"controlled_identity:{comparison_id}",
                root,
                88,
                92,
                "direct" if polarity == "support" else "contextual",
                summary,
                f"controlled_identity:{comparison_id}",
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
            raise ReconError("Controlled identity evidence collision or mutable evidence detected")
        db.execute(
            """INSERT INTO controlled_identity_differential_runs(
            comparison_id,analysis_id,hypothesis_id,source_run_id,target,artifact_hash,evidence_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                comparison_id,
                expected["analysis_id"],
                str(normalized["hypothesis_id"]),
                expected["run_id"],
                expected["target"],
                artifact_hash,
                evidence_id,
                "reviewed",
                utc_now(),
            ),
        )
        db.audit(
            "controlled_identity_differential_reviewed",
            actor=actor,
            target=expected["target"],
            entity_type="analysis_hypothesis",
            entity_value=str(normalized["hypothesis_id"]),
            details={
                "comparison_id": comparison_id,
                "evidence_id": evidence_id,
                "material_response_difference": bool(normalized["material_response_difference"]),
                "confounded": bool(normalized["confounded"]),
                "affects_admission": False,
                "affects_candidate_promotion": False,
                "network_requests_executed": 0,
            },
        )

    return {
        "version": CONTROLLED_IDENTITY_DIFFERENTIAL_VERSION,
        "status": "reviewed",
        "comparison_id": comparison_id,
        "evidence_id": evidence_id,
        "analysis_id": expected["analysis_id"],
        "hypothesis_id": str(normalized["hypothesis_id"]),
        "target": expected["target"],
        "material_response_difference": bool(normalized["material_response_difference"]),
        "difference_dimensions": list(normalized["response_difference_dimensions"]),
        "confounded": bool(normalized["confounded"]),
        "affects_admission": False,
        "affects_candidate_promotion": False,
        "network_requests_executed": 0,
        "raw_bodies_stored": False,
        "identity_values_stored": False,
        "vulnerability_confirmed": False,
    }
