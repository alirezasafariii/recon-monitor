from __future__ import annotations

"""Offline executor for explicitly authorized controlled evidence comparisons.

This module closes the gap between an Evidence Planner recommendation and a
usable comparison artifact without adding credential storage or live request
execution. It compares two already-captured, test-owned observations under an
explicit contract, can persist the comparison as context-only differential
metadata, and can translate a valid comparison into analyzer input metadata.

It never confirms a vulnerability, never changes admission, never guesses
identity/resource ownership, and never performs a network request.
"""

import json
import uuid
from typing import Any, Mapping

from core import Database, json_dumps, parse_int, utc_now
from family_reasoning import validation_level_for_family


CONTROLLED_EVIDENCE_EXECUTOR_VERSION = "1.0.0"
CONTROLLED_EVIDENCE_RULE_VERSION = "2026.08.14.1"

SUCCESS_STATUSES = set(range(200, 300))
DENY_STATUSES = {401, 403, 404}
ALLOWED_RELATIONS = {
    "probe_must_be_rejected",
    "probe_must_not_expose_equivalent_data",
    "role_separation_required",
    "invalid_transition_must_be_rejected",
}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _bool(mapping: Mapping[str, Any], key: str) -> bool:
    value = mapping.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _status(observation: Mapping[str, Any]) -> int:
    value = observation.get("status_code")
    if value is None and isinstance(observation.get("response"), Mapping):
        value = observation["response"].get("status_code")
    return parse_int(value, 0)


def _shape_hash(observation: Mapping[str, Any]) -> str:
    value = observation.get("shape_hash")
    if value:
        return str(value)
    response = observation.get("response")
    if isinstance(response, Mapping) and response.get("shape_hash"):
        return str(response.get("shape_hash"))
    return ""


def _sensitive_keys(observation: Mapping[str, Any]) -> list[str]:
    candidates = observation.get("sensitive_key_names")
    if candidates is None:
        candidates = observation.get("sensitive_keys")
    if candidates is None and isinstance(observation.get("response"), Mapping):
        response = observation["response"]
        candidates = response.get("sensitive_key_names") or response.get("sensitive_keys")
    if isinstance(candidates, str):
        candidates = _loads(candidates, [])
    if not isinstance(candidates, (list, tuple, set)):
        return []
    return sorted({str(value) for value in candidates if str(value).strip()})[:100]


def _observation_value(observation: Mapping[str, Any], key: str) -> str:
    value = observation.get(key)
    if value is None and isinstance(observation.get("metadata"), Mapping):
        value = observation["metadata"].get(key)
    return str(value or "").strip()


def _normalize_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target": _observation_value(observation, "target"),
        "endpoint": _observation_value(observation, "endpoint") or _observation_value(observation, "url"),
        "identity_id": _observation_value(observation, "identity_id"),
        "identity_role": _observation_value(observation, "identity_role"),
        "resource_id": _observation_value(observation, "resource_id"),
        "resource_owner_identity": _observation_value(observation, "resource_owner_identity"),
        "status_code": _status(observation),
        "shape_hash": _shape_hash(observation),
        "sensitive_keys": _sensitive_keys(observation),
        "controlled_capture": _bool(observation, "controlled_capture"),
        "test_owned": _bool(observation, "test_owned"),
        "reversible": _bool(observation, "reversible"),
        "source_ref": _observation_value(observation, "source_ref"),
    }


def _validate_contract(
    contract: Mapping[str, Any],
    control: Mapping[str, Any],
    probe: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    family = str(contract.get("family") or "").strip()
    target = str(contract.get("target") or "").strip()
    endpoint = str(contract.get("endpoint") or "").strip()
    relation = str(contract.get("expected_relation") or "").strip()
    if not family:
        errors.append("family_required")
    if not target:
        errors.append("target_required")
    if not endpoint:
        errors.append("endpoint_required")
    if relation not in ALLOWED_RELATIONS:
        errors.append("expected_relation_not_allowed")
    if not _bool(contract, "authorization_acknowledged"):
        errors.append("authorization_acknowledgement_required")
    if not _bool(contract, "test_owned"):
        errors.append("contract_test_ownership_required")
    if not _bool(contract, "reversible"):
        errors.append("contract_reversibility_required")

    for label, observation in (("control", control), ("probe", probe)):
        if not observation.get("controlled_capture"):
            errors.append(f"{label}_controlled_capture_required")
        if not observation.get("test_owned"):
            errors.append(f"{label}_test_owned_required")
        if not observation.get("reversible"):
            errors.append(f"{label}_reversible_required")
        if observation.get("target") and observation.get("target") != target:
            errors.append(f"{label}_target_mismatch")
        if observation.get("endpoint") and observation.get("endpoint") != endpoint:
            errors.append(f"{label}_endpoint_mismatch")

    if relation in {
        "probe_must_be_rejected",
        "probe_must_not_expose_equivalent_data",
        "role_separation_required",
    }:
        control_identity = str(contract.get("control_identity") or control.get("identity_id") or "").strip()
        probe_identity = str(contract.get("probe_identity") or probe.get("identity_id") or "").strip()
        if not control_identity or not probe_identity:
            errors.append("explicit_control_and_probe_identity_required")
        elif control_identity == probe_identity:
            errors.append("control_and_probe_identity_must_differ")

    if relation == "role_separation_required":
        control_role = str(contract.get("control_role") or control.get("identity_role") or "").strip()
        probe_role = str(contract.get("probe_role") or probe.get("identity_role") or "").strip()
        if not control_role or not probe_role:
            errors.append("explicit_control_and_probe_role_required")
        elif control_role == probe_role:
            errors.append("control_and_probe_role_must_differ")

    if relation in {
        "probe_must_be_rejected",
        "probe_must_not_expose_equivalent_data",
    }:
        resource_id = str(contract.get("resource_id") or control.get("resource_id") or probe.get("resource_id") or "").strip()
        owner = str(contract.get("resource_owner_identity") or control.get("resource_owner_identity") or "").strip()
        control_identity = str(contract.get("control_identity") or control.get("identity_id") or "").strip()
        if not resource_id:
            errors.append("explicit_test_resource_required")
        if not owner:
            errors.append("explicit_resource_owner_required")
        elif control_identity and owner != control_identity:
            errors.append("resource_owner_must_match_control_identity")

    if relation == "invalid_transition_must_be_rejected":
        expected_invariant = str(contract.get("expected_invariant") or "").strip()
        if not expected_invariant:
            errors.append("expected_invariant_required")

    return sorted(set(errors))


def _classification(
    relation: str,
    control: Mapping[str, Any],
    probe: Mapping[str, Any],
) -> tuple[str, list[str]]:
    control_status = parse_int(control.get("status_code"), 0)
    probe_status = parse_int(probe.get("status_code"), 0)
    control_success = control_status in SUCCESS_STATUSES
    probe_success = probe_status in SUCCESS_STATUSES
    probe_denied = probe_status in DENY_STATUSES
    same_shape = bool(
        control.get("shape_hash")
        and probe.get("shape_hash")
        and control.get("shape_hash") == probe.get("shape_hash")
    )
    sensitive_overlap = sorted(
        set(control.get("sensitive_keys") or []) & set(probe.get("sensitive_keys") or [])
    )
    reasons: list[str] = []

    if relation in {"probe_must_be_rejected", "invalid_transition_must_be_rejected"}:
        if probe_success:
            reasons.append(f"Probe succeeded with HTTP {probe_status} although the documented expectation requires rejection.")
            return "strengthened", reasons
        if probe_denied:
            reasons.append(f"Probe was denied with HTTP {probe_status}, matching the documented expected boundary.")
            return "weakened", reasons
        reasons.append("Probe response did not provide a decisive allow/deny outcome.")
        return "inconclusive", reasons

    if relation == "probe_must_not_expose_equivalent_data":
        if probe_denied:
            reasons.append(f"Probe was denied with HTTP {probe_status}, matching the expected object boundary.")
            return "weakened", reasons
        if control_success and probe_success and (same_shape or sensitive_overlap):
            if same_shape:
                reasons.append("Control and probe both succeeded with the same stored response-shape fingerprint.")
            if sensitive_overlap:
                reasons.append("Control and probe successful responses contain overlapping sensitive-key categories.")
            return "strengthened", reasons
        reasons.append("Probe did not reproduce an equivalent sensitive response strongly enough for a controlled differential.")
        return "inconclusive", reasons

    if relation == "role_separation_required":
        if probe_denied:
            reasons.append(f"Lower/different-role probe was denied with HTTP {probe_status}.")
            return "weakened", reasons
        if control_success and probe_success and (same_shape or sensitive_overlap):
            reasons.append("Different-role control and probe both succeeded with materially comparable stored response metadata.")
            return "strengthened", reasons
        reasons.append("Role comparison remained behaviorally different or insufficiently comparable.")
        return "inconclusive", reasons

    return "inconclusive", ["No supported comparison relation was selected."]


def compare_controlled_captures(
    contract: Mapping[str, Any],
    control_observation: Mapping[str, Any],
    probe_observation: Mapping[str, Any],
) -> dict[str, Any]:
    control = _normalize_observation(control_observation)
    probe = _normalize_observation(probe_observation)
    errors = _validate_contract(contract, control, probe)
    family = str(contract.get("family") or "").strip()
    relation = str(contract.get("expected_relation") or "").strip()
    try:
        family_validation_level = validation_level_for_family(family) if family else "offline"
    except Exception:
        family_validation_level = "offline"

    if errors:
        return {
            "version": CONTROLLED_EVIDENCE_EXECUTOR_VERSION,
            "rule_version": CONTROLLED_EVIDENCE_RULE_VERSION,
            "status": "blocked",
            "classification": "inconclusive",
            "family": family,
            "family_validation_level": family_validation_level,
            "expected_relation": relation,
            "blocking_reasons": errors,
            "control": control,
            "probe": probe,
            "network_requests": False,
            "credentials_stored": False,
            "state_changes_performed": False,
            "changes_admission": False,
            "confirms_vulnerability": False,
        }

    classification, reasons = _classification(relation, control, probe)
    return {
        "version": CONTROLLED_EVIDENCE_EXECUTOR_VERSION,
        "rule_version": CONTROLLED_EVIDENCE_RULE_VERSION,
        "status": "completed",
        "classification": classification,
        "family": family,
        "family_validation_level": family_validation_level,
        "target": str(contract.get("target") or ""),
        "endpoint": str(contract.get("endpoint") or ""),
        "expected_relation": relation,
        "expected_invariant": str(contract.get("expected_invariant") or ""),
        "reasons": reasons,
        "control": control,
        "probe": probe,
        "comparison": {
            "status_equal": control["status_code"] == probe["status_code"],
            "shape_equal": bool(control["shape_hash"] and control["shape_hash"] == probe["shape_hash"]),
            "sensitive_key_overlap": sorted(set(control["sensitive_keys"]) & set(probe["sensitive_keys"])),
        },
        "provenance": {
            "explicit_contract": True,
            "authorization_acknowledged": True,
            "test_owned": True,
            "reversible": True,
            "control_identity": str(contract.get("control_identity") or control.get("identity_id") or ""),
            "probe_identity": str(contract.get("probe_identity") or probe.get("identity_id") or ""),
            "resource_id": str(contract.get("resource_id") or control.get("resource_id") or probe.get("resource_id") or ""),
            "resource_owner_identity": str(contract.get("resource_owner_identity") or control.get("resource_owner_identity") or ""),
        },
        "network_requests": False,
        "credentials_stored": False,
        "state_changes_performed": False,
        "changes_admission": False,
        "confirms_vulnerability": False,
    }


def analyzer_details_from_comparison(result: Mapping[str, Any]) -> dict[str, Any]:
    """Translate a valid completed comparison into stored analyzer input metadata.

    The returned mapping still needs to pass the canonical family analyzer and
    Family Reasoning admission checks. This function does not call an analyzer
    and does not create a Candidate.
    """

    if str(result.get("status") or "") != "completed":
        return {}
    family = str(result.get("family") or "")
    classification = str(result.get("classification") or "inconclusive")
    relation = str(result.get("expected_relation") or "")
    probe = result.get("probe") if isinstance(result.get("probe"), Mapping) else {}
    provenance = result.get("provenance") if isinstance(result.get("provenance"), Mapping) else {}

    base = {
        "controlled_evidence_executor_version": CONTROLLED_EVIDENCE_EXECUTOR_VERSION,
        "controlled_test_context": True,
        "authorized_test_context": True,
        "reversible_test_data": True,
        "test_owned_data": True,
        "comparison_classification": classification,
        "expected_relation": relation,
        "network_request_performed_by_executor": False,
        "executor_changes_admission": False,
    }

    if family == "broken_object_authorization":
        expected_access = relation not in {
            "probe_must_be_rejected",
            "probe_must_not_expose_equivalent_data",
        }
        return {
            **base,
            "context_observations": [
                {
                    "context": "controlled_probe",
                    "status_code": probe.get("status_code"),
                    "shape_hash": probe.get("shape_hash"),
                    "identity_id": provenance.get("probe_identity"),
                    "object_owner_id": provenance.get("resource_owner_identity"),
                    "resource_id": provenance.get("resource_id"),
                    "expected_access": expected_access,
                    "controlled_test_context": True,
                    "authorized_test_context": True,
                    "reversible_test_data": True,
                    "test_owned_data": True,
                }
            ],
        }

    if family == "business_logic" and relation == "invalid_transition_must_be_rejected":
        return {
            **base,
            "expected_invariant": str(result.get("expected_invariant") or ""),
            "workflow_runtime_observations": [
                {
                    "controlled_test_context": True,
                    "authorized_test_context": True,
                    "reversible_test_data": True,
                    "test_owned_data": True,
                    "expected_invariant_documented": bool(str(result.get("expected_invariant") or "")),
                    "invalid_transition_accepted": classification == "strengthened",
                    "invalid_transition_rejected": classification == "weakened",
                }
            ],
        }

    return base


def _load_imported_observation(db: Database, observation_id: str) -> dict[str, Any]:
    row = db.one(
        "SELECT observation_id,target,source_type,source_file,observation_json,imported_by,created_at "
        "FROM imported_http_evidence WHERE observation_id=?",
        (observation_id,),
    )
    if not row:
        return {}
    observation = _loads(row["observation_json"], {})
    if not isinstance(observation, Mapping):
        return {}
    result = dict(observation)
    result.setdefault("target", str(row["target"] or ""))
    result.setdefault("source_ref", f"imported_http_evidence:{observation_id}")
    return result


def execute_stored_capture_comparison(
    db: Database,
    *,
    analysis_id: str,
    contract: Mapping[str, Any],
    control_observation_id: str,
    probe_observation_id: str,
    persist: bool = True,
) -> dict[str, Any]:
    control = _load_imported_observation(db, control_observation_id)
    probe = _load_imported_observation(db, probe_observation_id)
    if not control or not probe:
        missing = []
        if not control:
            missing.append("control_observation_not_found")
        if not probe:
            missing.append("probe_observation_not_found")
        return {
            "version": CONTROLLED_EVIDENCE_EXECUTOR_VERSION,
            "rule_version": CONTROLLED_EVIDENCE_RULE_VERSION,
            "status": "blocked",
            "classification": "inconclusive",
            "blocking_reasons": missing,
            "network_requests": False,
            "changes_admission": False,
            "confirms_vulnerability": False,
        }

    result = compare_controlled_captures(contract, control, probe)
    result["control_observation_id"] = control_observation_id
    result["probe_observation_id"] = probe_observation_id
    result["analyzer_details"] = analyzer_details_from_comparison(result)

    if persist and str(result.get("status") or "") == "completed":
        diff_id = "CED-" + uuid.uuid5(
            uuid.NAMESPACE_URL,
            "|".join(
                [
                    str(analysis_id),
                    str(contract.get("target") or ""),
                    str(contract.get("endpoint") or ""),
                    str(contract.get("family") or ""),
                    str(control_observation_id),
                    str(probe_observation_id),
                ]
            ),
        ).hex[:20].upper()
        details = {
            **result,
            "context_only": True,
            "non_decisive_until_family_reasoning": True,
            "comparison_does_not_equal_confirmation": True,
        }
        db.execute(
            "INSERT OR REPLACE INTO differential_findings(diff_id,analysis_id,target,endpoint,diff_kind,confidence,severity,details_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                diff_id,
                analysis_id,
                str(contract.get("target") or ""),
                str(contract.get("endpoint") or ""),
                "controlled_test_capture_comparison",
                92 if result["classification"] in {"strengthened", "weakened"} else 65,
                "medium" if result["classification"] == "strengthened" else "informational",
                json_dumps(details),
                utc_now(),
            ),
        )
        result["persisted_diff_id"] = diff_id

    return result


__all__ = [
    "CONTROLLED_EVIDENCE_EXECUTOR_VERSION",
    "CONTROLLED_EVIDENCE_RULE_VERSION",
    "ALLOWED_RELATIONS",
    "compare_controlled_captures",
    "analyzer_details_from_comparison",
    "execute_stored_capture_comparison",
]
