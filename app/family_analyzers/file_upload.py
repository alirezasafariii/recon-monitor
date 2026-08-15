from __future__ import annotations

"""Dedicated File Upload / Import analyzer.

The analyzer separates an upload/import surface from stored evidence that an
explicitly controlled inert test file outside the intended file policy was
accepted, and from the stricter question of whether the file-validation or
storage/serving boundary was actually bypassed. CWE/WSTG/write-up material is
reasoning context only and never becomes target evidence. This module performs
no active upload, execution, malware delivery, filesystem write, or browser
navigation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database
from family_reasoning import FAMILY_REASONING, confirmation_gaps
from family_specs.registry import get_detection_spec

from .base import FamilyAnalyzer, FamilyAnalyzerContext


FILE_UPLOAD_FAMILY_ANALYZER_VERSION = "1.0.0"
FILE_UPLOAD_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

FILE_FIELD_NAMES = {
    "file", "files", "filename", "file_name", "attachment", "attachments",
    "avatar", "document", "documents", "upload", "upload_file", "uploadfile",
    "import_file", "importfile", "archive", "media", "image", "photo",
}
UPLOAD_ROUTE_MARKERS = {
    "upload", "uploads", "attachment", "attachments", "avatar", "document",
    "documents", "media", "image", "photo", "files",
}
IMPORT_ROUTE_MARKERS = {"import", "ingest", "restore", "bulk_import", "bulkimport"}

FILE_UPLOAD_SPEC = get_detection_spec("file_upload")

# Compatibility exports; canonical definitions live in family_specs.
FILE_UPLOAD_TAXONOMY = FILE_UPLOAD_SPEC.taxonomy()
FILE_UPLOAD_METHOD = tuple(step.as_dict() for step in FILE_UPLOAD_SPEC.standard.methodology)
FILE_UPLOAD_FALSE_POSITIVE_CHECKS = tuple(FILE_UPLOAD_SPEC.standard.false_positive_checks)
FILE_UPLOAD_WRITEUP_PATTERNS = tuple(
    {
        "id": item.id,
        "source": item.source,
        "ref": item.ref,
        "url": item.url,
        "relation": item.relation,
        "principle": item.lesson,
        "signals": list(item.signal_hints),
        "counts_as_target_evidence": False,
    }
    for item in FILE_UPLOAD_SPEC.standard.writeups
)

def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "accepted", "allowed", "present", "enforced", "stored", "persisted", "served", "executed"}:
        return True
    if text in {"false", "0", "no", "rejected", "blocked", "denied", "missing", "absent", "not_observed"}:
        return False
    return None


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _scalar(item: Mapping[str, Any], keys: Iterable[str]) -> Any:
    normalized = {_normalize(key): value for key, value in item.items()}
    for key in keys:
        value = normalized.get(_normalize(key))
        if value is not None and str(value).strip() != "":
            return value
    return None


def _list_value(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        decoded = _loads(value, [])
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in (
        "file_upload_observations", "upload_observations", "import_observations",
        "file_processing_observations", "file_runtime_observations", "runtime_observations",
    ):
        raw = details.get(key)
        decoded = _loads(raw, raw)
        if isinstance(decoded, list):
            return [dict(item) for item in decoded if isinstance(item, Mapping)]
        if isinstance(decoded, Mapping):
            return [dict(decoded)]
    return []


def _add_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    identity = (
        str(item.get("type") or ""),
        str(item.get("source_group") or item.get("source") or ""),
        str(item.get("text") or ""),
    )
    if any(
        (
            str(existing.get("type") or ""),
            str(existing.get("source_group") or existing.get("source") or ""),
            str(existing.get("text") or ""),
        ) == identity
        for existing in items
    ):
        return
    items.append(item)


def _file_fields(body_fields: Iterable[str], query_fields: Iterable[str], details: Mapping[str, Any]) -> list[str]:
    explicit = _list_value(_scalar(details, ("file_fields", "upload_fields", "attachment_fields")))
    found: list[str] = []
    for value in [*explicit, *[str(item) for item in body_fields], *[str(item) for item in query_fields]]:
        normalized = _normalize(value)
        if normalized in FILE_FIELD_NAMES or normalized.endswith("_file") or normalized.endswith("_filename"):
            if value not in found:
                found.append(value)
    return found


def _operation(endpoint: str, method: str, details: Mapping[str, Any], semantic_text: str) -> tuple[bool, bool, bool]:
    text = _normalize(" ".join([endpoint, semantic_text, str(_scalar(details, ("operation", "operation_type", "file_operation")) or "")]))
    write_method = str(method or "").upper() in {"POST", "PUT", "PATCH"}
    upload = write_method and any(marker in text for marker in UPLOAD_ROUTE_MARKERS)
    import_op = write_method and any(marker in text for marker in IMPORT_ROUTE_MARKERS)
    multipart = "multipart_form_data" in text or _bool(_scalar(details, ("multipart_form_data", "multipart"))) is True
    if multipart and write_method:
        upload = True
    return upload, import_op, multipart


def _structural_evidence(
    file_fields: list[str],
    *,
    upload_operation: bool,
    import_operation: bool,
    multipart: bool,
) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    group = "file_upload_structural_surface"
    if file_fields or (multipart and upload_operation):
        _add_unique(support, {
            "type": "file_input",
            "source": "endpoint_schema",
            "source_group": group,
            "weight": 20,
            "text": f"Structured file input observed: {', '.join(file_fields[:6])}." if file_fields else "Multipart semantics are tied to an upload operation.",
        })
    if upload_operation:
        _add_unique(support, {
            "type": "upload_operation",
            "source": "endpoint_contract",
            "source_group": group,
            "weight": 18,
            "text": "The endpoint contract identifies a write-capable file upload operation.",
        })
    if import_operation:
        _add_unique(support, {
            "type": "import_operation",
            "source": "endpoint_contract",
            "source_group": group,
            "weight": 18,
            "text": "The endpoint contract identifies a file import/ingest operation.",
        })
    if multipart:
        _add_unique(support, {
            "type": "content_type_field",
            "source": "http_contract",
            "source_group": group,
            "weight": 6,
            "text": "multipart/form-data is present as structural upload context only.",
        })
    return support


def _runtime_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool, list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    promotion_direct = False
    confirmation_direct = False
    observation_context: list[dict[str, Any]] = []

    observations = _observations(details)
    if not observations and any(
        key in details
        for key in (
            "unsafe_file_accepted", "content_type_bypass_observed", "executable_upload_observed",
            "file_type_enforcement_observed", "safe_storage_observed", "controlled_test_file",
        )
    ):
        observations = [dict(details)]

    for index, observation in enumerate(observations, start=1):
        controlled = _bool(_scalar(observation, (
            "controlled_test_file", "test_file_controlled", "file_owned_by_tester", "controlled_file",
        )))
        inert = _bool(_scalar(observation, (
            "inert_test_file", "benign_test_file", "non_executable_test_file", "harmless_file",
        )))
        expected_reject = _bool(_scalar(observation, (
            "expected_reject", "outside_allowed_policy", "unexpected_file_type", "policy_disallowed_file",
        )))
        accepted = _bool(_scalar(observation, (
            "unsafe_file_accepted", "upload_accepted", "import_accepted", "file_accepted", "accepted",
        )))
        rejected = _bool(_scalar(observation, ("upload_rejected", "file_rejected", "rejected")))
        persisted = _bool(_scalar(observation, ("file_persisted", "stored", "persisted")))

        extension_enforced = _bool(_scalar(observation, ("extension_allowlist_enforced", "file_extension_enforced")))
        mime_enforced = _bool(_scalar(observation, ("mime_validation_enforced", "content_type_enforced")))
        signature_enforced = _bool(_scalar(observation, ("signature_validation_enforced", "magic_bytes_enforced", "content_signature_enforced")))
        scanner_enforced = _bool(_scalar(observation, ("malware_scan_enforced", "content_scan_enforced")))
        safe_storage = _bool(_scalar(observation, (
            "safe_storage_observed", "storage_outside_webroot", "isolated_storage", "execution_disabled",
        )))
        attachment_disposition = _bool(_scalar(observation, ("content_disposition_attachment", "attachment_disposition_observed")))
        generated_name = _bool(_scalar(observation, ("server_generated_filename", "filename_rewritten")))

        explicit_type_bypass = _bool(_scalar(observation, (
            "content_type_bypass_observed", "file_type_bypass_observed", "signature_bypass_observed", "extension_policy_bypass_observed",
        )))
        explicit_exec = _bool(_scalar(observation, (
            "executable_upload_observed", "uploaded_content_executed", "execution_capable_storage_observed",
        )))

        declared_type = str(_scalar(observation, ("declared_content_type", "request_content_type", "mime_type")) or "").strip()
        detected_type = str(_scalar(observation, ("detected_content_type", "detected_mime", "magic_type")) or "").strip()
        filename = str(_scalar(observation, ("filename", "file_name", "test_filename")) or "").strip()

        observation_context.append({
            "index": index,
            "controlled_test_file": controlled is True,
            "inert_test_file": inert is True,
            "expected_reject": expected_reject is True,
            "accepted": accepted is True,
            "persisted": persisted is True,
            "filename_present": bool(filename),
            "declared_content_type": declared_type,
            "detected_content_type": detected_type,
        })

        if rejected is True or (accepted is False and expected_reject is True):
            _add_unique(contradict, {
                "type": "file_type_enforcement_observed",
                "source": "stored_file_upload_runtime",
                "source_group": f"file_upload_runtime_{index}",
                "weight": -34,
                "text": "Stored behavior shows the policy-disallowed controlled file was rejected.",
            })
        if any(value is True for value in (extension_enforced, mime_enforced, signature_enforced, scanner_enforced)):
            _add_unique(contradict, {
                "type": "file_type_enforcement_observed",
                "source": "stored_file_upload_runtime",
                "source_group": f"file_upload_runtime_{index}",
                "weight": -24,
                "text": "Stored evidence records enforcement of file extension, MIME/signature or content-scanning controls on the relevant operation.",
            })
        if safe_storage is True or attachment_disposition is True or generated_name is True:
            _add_unique(contradict, {
                "type": "safe_storage_observed",
                "source": "stored_file_upload_runtime",
                "source_group": f"file_upload_runtime_{index}",
                "weight": -18,
                "text": "Stored evidence records storage/serving controls such as isolation, disabled execution, generated filenames or attachment disposition.",
            })

        safe_direct_observation = controlled is True and inert is True and expected_reject is True and accepted is True
        if safe_direct_observation:
            _add_unique(support, {
                "type": "unsafe_file_accepted",
                "source": "stored_file_upload_runtime",
                "source_group": f"file_upload_runtime_{index}",
                "weight": 38,
                "text": "An explicitly controlled inert test file that the documented file policy says should be rejected was accepted by the upload/import operation.",
            })
            _add_unique(support, {
                "type": "file_policy_differential",
                "source": "stored_file_upload_runtime",
                "source_group": f"file_upload_runtime_{index}",
                "weight": 22,
                "text": "Stored expected-vs-observed behavior differs for the controlled inert file policy decision.",
            })
            promotion_direct = True

            if persisted is True:
                _add_unique(support, {
                    "type": "unsafe_file_persisted",
                    "source": "stored_file_upload_runtime",
                    "source_group": f"file_upload_runtime_{index}",
                    "weight": 20,
                    "text": "The same policy-disallowed controlled inert test file was stored after acceptance.",
                })

            if explicit_type_bypass is True:
                _add_unique(support, {
                    "type": "content_type_bypass_observed",
                    "source": "stored_file_upload_runtime",
                    "source_group": f"file_upload_runtime_{index}",
                    "weight": 46,
                    "text": "Stored evidence shows the relevant file-type/content validation policy was bypassed for the controlled inert test file.",
                })
                confirmation_direct = True

            if explicit_exec is True:
                _add_unique(support, {
                    "type": "executable_upload_observed",
                    "source": "stored_file_upload_runtime",
                    "source_group": f"file_upload_runtime_{index}",
                    "weight": 50,
                    "text": "Stored evidence records execution-capable or executable handling of the uploaded content; the analyzer itself did not execute or upload any payload.",
                })
                confirmation_direct = True

    return support, contradict, promotion_direct, confirmation_direct, observation_context


def _variant(support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "executable_upload_observed" in types:
        return "execution_capable_upload_boundary"
    if "content_type_bypass_observed" in types:
        return "file_type_validation_bypass"
    if "unsafe_file_persisted" in types:
        return "policy_disallowed_file_persisted"
    if "unsafe_file_accepted" in types:
        return "policy_disallowed_file_accepted"
    if "file_type_enforcement_observed" in controls:
        return "file_policy_enforced"
    if "safe_storage_observed" in controls:
        return "safe_storage_controls_observed"
    return "file_upload_surface"


def analyze_file_upload_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str = "UNKNOWN",
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    fields = _file_fields(body_fields, query_fields, details)
    upload_operation, import_operation, multipart = _operation(endpoint, method, details, semantic_text)
    support = _structural_evidence(
        fields,
        upload_operation=upload_operation,
        import_operation=import_operation,
        multipart=multipart,
    )
    runtime_support, contradict, promotion_direct, confirmation_direct, observations = _runtime_evidence(details)
    for item in runtime_support:
        _add_unique(support, item)

    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    catalog_missing = confirmation_gaps("file_upload", observed)
    confirmation_missing = list(catalog_missing)
    if not confirmation_direct:
        stronger = "Stored file-type/content validation bypass or execution-capable unsafe storage/serving evidence."
        if stronger not in confirmation_missing:
            confirmation_missing.append(stronger)
    blockers = {str(item.get("type") or "") for item in contradict}
    confirmation_ready = confirmation_direct and not blockers.intersection({"file_type_enforcement_observed"})

    metadata = FileUploadFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": FILE_UPLOAD_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in FILE_UPLOAD_TAXONOMY.items()},
        "methodology": [dict(step) for step in FILE_UPLOAD_METHOD],
        "false_positive_checks": list(FILE_UPLOAD_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in FILE_UPLOAD_WRITEUP_PATTERNS],
        "file_fields": list(fields),
        "upload_operation": upload_operation,
        "import_operation": import_operation,
        "multipart": multipart,
        "observation_context": observations,
        "structural_file_input_and_operation_are_one_evidence_root": True,
        "promotion_ready_from_stored_target_evidence": promotion_direct,
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "knowledge_does_not_change_target_evidence": True,
        "active_validation_performed": False,
        "active_upload_performed": False,
        "payload_execution_performed": False,
        "malware_or_weaponized_file_used": False,
        "filesystem_write_performed_by_analyzer": False,
    })

    missing = list(FAMILY_REASONING["file_upload"]["next_evidence"])
    if promotion_direct:
        missing = [
            "Determine whether the accepted controlled inert file was isolated, renamed, forced to download, or exposed to an execution-capable handler.",
            "Capture only the minimum storage/serving metadata needed to decide whether the file-validation boundary was bypassed.",
        ]
    if confirmation_ready:
        missing = []

    return {
        "family": "file_upload",
        "variant": _variant(support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-file-upload-surface",
            "family-file-policy",
            "family-file-controlled-observation",
            "family-file-storage-processing",
            "family-file-confirmation-boundary",
        ],
        "summary": (
            "Stored target evidence establishes a file-validation or execution-capable upload boundary failure using an explicitly controlled inert test file."
            if confirmation_ready
            else "Stored target evidence shows a policy-disallowed controlled inert file was accepted; storage/processing impact remains unconfirmed."
            if promotion_direct
            else "A file upload/import surface is retained as a hidden hypothesis; unsafe acceptance has not been established from stored target behavior."
        ),
        "direct": promotion_direct,
        "family_analyzer": metadata,
    }


class FileUploadFamilyAnalyzer(FamilyAnalyzer):
    family = "file_upload"
    analyzer_version = FILE_UPLOAD_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_file_upload_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            body_fields=kwargs.get("body_fields") or (),
            query_fields=kwargs.get("query_fields") or (),
            details=context.details,
            business_context=context.business_context,
            semantic_text=str(kwargs.get("semantic_text") or ""),
        )
