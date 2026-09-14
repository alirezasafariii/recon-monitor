from __future__ import annotations

"""Offline review boundary for redacted Secret Exposure classification metadata.

No detector, network request, provider validation, raw value, or response body is
handled here. The module accepts only a small allow-listed metadata contract from
an analyst-reviewed offline classifier and persists provenance for later admission.
"""

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now

MATERIAL_CLASSIFICATION_REVIEW_VERSION = "1.0.0"
MATERIAL_CLASSIFICATION_REVIEW_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{16,128}$")
_MATERIAL_CLASSES = {"structured_key_material", "paired_provider_material", "provider_token_material"}
_CLASSIFICATIONS = {"confirmed_structure", "placeholder", "intended_public_identifier", "inconclusive"}
_ALLOWED_KEYS = {
    "version", "review_id", "run_id", "analysis_id", "target", "hypothesis_id",
    "material_class", "classification", "classification_fingerprint", "source_artifact_fingerprint",
    "client_delivered_context", "analyst_verified", "redacted", "observed_at", "reviewed_by",
    "classification_ambiguous", "source_context_ambiguous", "provider_validation_performed",
    "network_request_performed",
}


def ensure_material_classification_review_schema(db: Database) -> None:
    db.execute(
        """CREATE TABLE IF NOT EXISTS material_classification_review_runs (
        review_id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL, hypothesis_id TEXT NOT NULL,
        source_run_id TEXT NOT NULL, target TEXT NOT NULL, material_class TEXT NOT NULL,
        artifact_hash TEXT NOT NULL, evidence_id TEXT NOT NULL DEFAULT '', signal_type TEXT NOT NULL DEFAULT '',
        polarity TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, applied_at TEXT NOT NULL)"""
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('material_classification_review_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(MATERIAL_CLASSIFICATION_REVIEW_SCHEMA_VERSION),),
    )


def _load(path: str | Path) -> dict[str, Any]:
    artifact = Path(path).expanduser().resolve()
    if artifact.is_symlink() or not artifact.exists() or not artifact.is_file():
        raise ReconError("Material classification artifact is unavailable or unsafe")
    if artifact.stat().st_size > 512 * 1024:
        raise ReconError("Material classification artifact exceeds the safety limit")
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError("Material classification artifact is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReconError("Material classification artifact must contain a JSON object")
    unknown = set(map(str, value.keys())) - _ALLOWED_KEYS
    if unknown:
        raise ReconError("Material classification artifact contains non-contract fields")
    return dict(value)


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("Material classification artifact requires observed_at")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError("Material classification artifact has invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def validate_material_classification_artifact(
    artifact: Mapping[str, Any], *, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
) -> dict[str, Any]:
    unknown = set(map(str, artifact.keys())) - _ALLOWED_KEYS
    if unknown:
        raise ReconError("Material classification artifact contains non-contract fields")
    if str(artifact.get("version") or "") != MATERIAL_CLASSIFICATION_REVIEW_VERSION:
        raise ReconError("Unsupported material classification artifact version")
    if not bool(artifact.get("analyst_verified")) or not bool(artifact.get("redacted")):
        raise ReconError("Material classification artifact must be analyst-verified and redacted")
    if bool(artifact.get("provider_validation_performed")) or bool(artifact.get("network_request_performed")):
        raise ReconError("Material classification review is offline-only")

    review_id = str(artifact.get("review_id") or "").strip()
    if not review_id.startswith("MCR-") or len(review_id) > 80:
        raise ReconError("Material classification artifact has invalid review_id")
    material_class = str(artifact.get("material_class") or "").strip().lower()
    classification = str(artifact.get("classification") or "").strip().lower()
    if material_class not in _MATERIAL_CLASSES or classification not in _CLASSIFICATIONS:
        raise ReconError("Material classification artifact has an unsupported classification")

    classification_fingerprint = str(artifact.get("classification_fingerprint") or "").strip()
    source_artifact_fingerprint = str(artifact.get("source_artifact_fingerprint") or "").strip()
    if not _HASH_RE.fullmatch(classification_fingerprint) or not _HASH_RE.fullmatch(source_artifact_fingerprint):
        raise ReconError("Material classification artifact requires one-way fingerprints")

    identity = {}
    for key in ("run_id", "analysis_id", "target", "hypothesis_id"):
        rendered = str(artifact.get(key) or "").strip()
        if not rendered:
            raise ReconError(f"Material classification artifact is missing {key}")
        identity[key] = rendered

    observed = _parse_time(artifact.get("observed_at"))
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if max_age_seconds <= 0 or age < -300 or age > max_age_seconds:
        raise ReconError("Material classification artifact is outside the freshness window")

    confounded = bool(artifact.get("classification_ambiguous")) or bool(artifact.get("source_context_ambiguous"))
    signal_type = ""
    polarity = "contradict"
    reason = "classification_inconclusive"
    if classification == "placeholder":
        signal_type, reason = "placeholder", "placeholder_control"
    elif classification == "intended_public_identifier":
        signal_type, reason = "intended_public_client_identifier", "public_identifier_control"
    elif classification == "confirmed_structure" and not confounded and bool(artifact.get("client_delivered_context")):
        signal_type, polarity, reason = "credential_material_confirmed", "support", "redacted_structure_confirmed"
    elif classification == "confirmed_structure" and not bool(artifact.get("client_delivered_context")):
        reason = "client_delivery_context_not_established"
    elif confounded:
        reason = "classification_confounded"

    normalized = {
        "version": MATERIAL_CLASSIFICATION_REVIEW_VERSION,
        "review_id": review_id,
        **identity,
        "material_class": material_class,
        "classification": classification,
        "classification_fingerprint": classification_fingerprint.lower(),
        "source_artifact_fingerprint": source_artifact_fingerprint.lower(),
        "client_delivered_context": bool(artifact.get("client_delivered_context")),
        "confounded": confounded,
        "observed_at": str(artifact.get("observed_at")),
        "reviewed_by": str(artifact.get("reviewed_by") or "analyst")[:200],
        "analyst_verified": True,
        "redacted": True,
        "provider_validation_performed": False,
        "network_request_performed": False,
        "signal_type": signal_type,
        "polarity": polarity,
        "classification_reason": reason,
        "affects_admission": False,
        "affects_candidate_promotion": False,
    }
    normalized["artifact_hash"] = sha256_text(json_dumps(normalized))
    return normalized


def review_material_classification_artifact(
    db: Database, *, artifact_path: str | Path, actor: str = "analyst",
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    ensure_material_classification_review_schema(db)
    normalized = validate_material_classification_artifact(
        _load(artifact_path), max_age_seconds=max_age_seconds
    )
    review_id = str(normalized["review_id"])
    artifact_hash = str(normalized["artifact_hash"])
    previous = db.one("SELECT * FROM material_classification_review_runs WHERE review_id=?", (review_id,))
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously reviewed material classification has changed")
        return {
            "version": MATERIAL_CLASSIFICATION_REVIEW_VERSION, "status": "already_applied",
            "review_id": review_id, "evidence_id": str(previous["evidence_id"] or ""),
            "signal_type": str(previous["signal_type"] or ""), "polarity": str(previous["polarity"] or ""),
            "network_requests_executed": 0, "provider_validation_performed": False,
            "vulnerability_confirmed": False,
        }

    hypothesis_row = db.one("SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?", (str(normalized["hypothesis_id"]),))
    if not hypothesis_row:
        raise ReconError("Material classification hypothesis was not found")
    hypothesis = dict(hypothesis_row)
    if str(hypothesis.get("bug_family") or "") != "secret_exposure":
        raise ReconError("Material classification review requires a secret_exposure hypothesis")
    expected = {
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "run_id": str(hypothesis.get("source_run_id") or ""),
        "target": str(hypothesis.get("target") or ""),
    }
    for key, value in expected.items():
        if str(normalized.get(key) or "") != value:
            raise ReconError(f"Material classification artifact {key} mismatch")

    root = sha256_text("|".join([
        "material-classification-review", review_id, expected["target"],
        str(normalized["material_class"]), str(normalized["source_artifact_fingerprint"]),
    ]))
    evidence_id = "EVD-" + sha256_text(root + "|" + artifact_hash)[:16].upper()
    signal_type = str(normalized["signal_type"] or "")
    polarity = str(normalized["polarity"] or "contradict")
    if signal_type == "credential_material_confirmed" and polarity == "support":
        evidence_type, directness = "reviewed_redacted_material_structure", "direct"
        summary = "Analyst-reviewed redacted metadata confirms a complete material structure in client-delivered context; no reusable value is retained or validated online."
    elif signal_type in {"placeholder", "intended_public_client_identifier"}:
        evidence_type, directness = "reviewed_material_control", "direct"
        summary = "Analyst-reviewed redacted metadata records a control classification that must not support promotion."
    else:
        evidence_type, directness = "reviewed_material_inconclusive", "contextual"
        summary = "Redacted material classification remains incomplete or confounded and cannot support promotion."

    with db.transaction():
        db.execute(
            """INSERT OR IGNORE INTO evidence_records(
            evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,
            parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,
            raw_reference,integrity_hash,first_seen,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id, expected["analysis_id"], expected["run_id"], expected["target"], evidence_type, polarity,
                "analyst_verified_redacted_classification", "material_classification_review", Path(artifact_path).name[:240],
                "material_classification_review", MATERIAL_CLASSIFICATION_REVIEW_VERSION,
                f"material_classification:{review_id}", root, 91, 95, directness, summary,
                f"material_classification:{review_id}", artifact_hash,
                str(normalized["observed_at"]), str(normalized["observed_at"]), utc_now(),
            ),
        )
        stored = db.one("SELECT integrity_hash FROM evidence_records WHERE evidence_id=?", (evidence_id,))
        if not stored or str(stored["integrity_hash"] or "") != artifact_hash:
            raise ReconError("Material classification evidence collision or mutable evidence detected")
        db.execute(
            """INSERT INTO material_classification_review_runs(
            review_id,analysis_id,hypothesis_id,source_run_id,target,material_class,artifact_hash,
            evidence_id,signal_type,polarity,status,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                review_id, expected["analysis_id"], str(normalized["hypothesis_id"]), expected["run_id"], expected["target"],
                str(normalized["material_class"]), artifact_hash, evidence_id, signal_type, polarity, "reviewed", utc_now(),
            ),
        )
        db.audit(
            "material_classification_reviewed", actor=actor, target=expected["target"],
            entity_type="analysis_hypothesis", entity_value=str(normalized["hypothesis_id"]),
            details={"review_id": review_id, "evidence_id": evidence_id, "signal_type": signal_type,
                     "polarity": polarity, "network_requests_executed": 0,
                     "provider_validation_performed": False, "vulnerability_confirmed": False},
        )

    return {
        "version": MATERIAL_CLASSIFICATION_REVIEW_VERSION, "status": "reviewed", "review_id": review_id,
        "analysis_id": expected["analysis_id"], "hypothesis_id": str(normalized["hypothesis_id"]),
        "target": expected["target"], "material_class": str(normalized["material_class"]),
        "evidence_id": evidence_id, "signal_type": signal_type, "polarity": polarity,
        "classification_reason": str(normalized["classification_reason"]), "confounded": bool(normalized["confounded"]),
        "affects_admission": False, "affects_candidate_promotion": False,
        "network_requests_executed": 0, "provider_validation_performed": False,
        "vulnerability_confirmed": False,
    }
