from __future__ import annotations

"""Offline Differential Evidence v2 verification.

The module intentionally performs no network I/O. It validates analyst-reviewed,
redacted expected-vs-observed artifacts before they can be translated into
family-scoped evidence by the existing Canonical Admission path.
"""

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Mapping

from core import ReconError, json_dumps, sha256_text


DIFFERENTIAL_EVIDENCE_VERSION = "2.0.0"
OPEN_REDIRECT_KIND = "open_redirect_expected_observed"
OPEN_REDIRECT_CONTROLLED_DESTINATION = "https://recon-monitor-validation.invalid/open-redirect"
_PARAMETER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("Differential evidence requires observed_at")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError("Differential evidence has an invalid observed_at") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def load_differential_artifact(path: str | Path, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    artifact = Path(path).expanduser().resolve()
    if artifact.is_symlink():
        raise ReconError(f"Refusing symlinked differential evidence artifact: {artifact}")
    if not artifact.exists() or not artifact.is_file():
        raise ReconError(f"Differential evidence artifact not found: {artifact}")
    if artifact.stat().st_size > max_bytes:
        raise ReconError("Differential evidence artifact exceeds the 1 MiB safety limit")
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReconError("Differential evidence artifact is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise ReconError("Differential evidence artifact must contain a JSON object")
    return dict(value)


def validate_open_redirect_artifact(
    artifact: Mapping[str, Any],
    *,
    max_age_seconds: int = 24 * 60 * 60,
) -> dict[str, Any]:
    if str(artifact.get("version") or "") != DIFFERENTIAL_EVIDENCE_VERSION:
        raise ReconError("Unsupported Differential Evidence version")
    if str(artifact.get("kind") or "") != OPEN_REDIRECT_KIND:
        raise ReconError("Differential Evidence kind is not Open Redirect")
    if str(artifact.get("family") or "") != "open_redirect":
        raise ReconError("Differential Evidence family mismatch")
    if bool(artifact.get("raw_body_stored")):
        raise ReconError("Differential Evidence must not contain a stored raw body")
    if bool(artifact.get("redirect_followed")):
        raise ReconError("Differential Evidence must not follow the external redirect")
    if bool(artifact.get("external_destination_connection")):
        raise ReconError("Differential Evidence must not connect to the external destination")
    if not bool(artifact.get("analyst_verified")):
        raise ReconError("Differential Evidence requires explicit analyst verification")

    differential_id = str(artifact.get("differential_id") or "").strip()
    if not differential_id.startswith("DEV-") or len(differential_id) > 80:
        raise ReconError("Differential Evidence has an invalid differential_id")
    parameter = str(artifact.get("parameter_name") or "").strip()
    if not _PARAMETER_RE.fullmatch(parameter):
        raise ReconError("Differential Evidence has an invalid parameter_name")
    controlled = str(artifact.get("controlled_destination") or "").strip()
    if controlled != OPEN_REDIRECT_CONTROLLED_DESTINATION:
        raise ReconError("Differential Evidence controlled destination mismatch")

    baseline = artifact.get("baseline")
    probe = artifact.get("probe")
    if not isinstance(baseline, Mapping) or not isinstance(probe, Mapping):
        raise ReconError("Differential Evidence requires baseline and probe observations")
    probe_status = int(probe.get("status_code") or 0)
    observed_location = str(probe.get("location") or "").strip()
    if not 300 <= probe_status < 400:
        raise ReconError("Open Redirect differential probe did not observe a redirect status")
    if observed_location != OPEN_REDIRECT_CONTROLLED_DESTINATION:
        raise ReconError("Open Redirect differential probe did not accept the controlled destination")

    observed = _parse_time(artifact.get("observed_at"))
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds()
    if max_age_seconds <= 0 or age < -300 or age > max_age_seconds:
        raise ReconError("Differential Evidence is outside the freshness window")

    required_identity = ("run_id", "analysis_id", "target", "hypothesis_id")
    for key in required_identity:
        if not str(artifact.get(key) or "").strip():
            raise ReconError(f"Differential Evidence is missing {key}")

    normalized = {
        "version": DIFFERENTIAL_EVIDENCE_VERSION,
        "kind": OPEN_REDIRECT_KIND,
        "differential_id": differential_id,
        "run_id": str(artifact.get("run_id")),
        "analysis_id": str(artifact.get("analysis_id")),
        "target": str(artifact.get("target")),
        "hypothesis_id": str(artifact.get("hypothesis_id")),
        "family": "open_redirect",
        "parameter_name": parameter,
        "controlled_destination": controlled,
        "baseline": {
            "status_code": int(baseline.get("status_code") or 0),
            "location": str(baseline.get("location") or "")[:1000],
        },
        "probe": {
            "status_code": probe_status,
            "location": observed_location,
        },
        "observed_at": str(artifact.get("observed_at")),
        "analyst_verified": True,
        "reviewed_by": str(artifact.get("reviewed_by") or "analyst")[:200],
        "raw_body_stored": False,
        "redirect_followed": False,
        "external_destination_connection": False,
    }
    normalized["artifact_hash"] = sha256_text(json_dumps(normalized))
    return normalized
