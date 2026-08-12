from __future__ import annotations

"""Dedicated Path Traversal analyzer.

The analyzer separates a user-influenced path/file surface from stored evidence
that a controlled, non-sensitive test path escaped an expected base directory,
and from the stricter question of whether an out-of-root file operation or a
canonicalization boundary bypass was actually observed. CWE/WSTG material is
reasoning context only and never becomes target evidence. This module performs
no active request, filesystem read/write, archive extraction, or traversal
payload generation.
"""

import json
import re
from typing import Any, Iterable, Mapping

from core import Database
from family_reasoning import FAMILY_REASONING, confirmation_gaps

from .base import FamilyAnalyzer, FamilyAnalyzerContext


PATH_TRAVERSAL_FAMILY_ANALYZER_VERSION = "1.0.0"
PATH_TRAVERSAL_FAMILY_ANALYZER_RULE_VERSION = "2026.08.12.1"

PATH_FIELD_NAMES = {
    "path", "filepath", "file_path", "filename", "file_name", "directory",
    "dir", "folder", "storage_path", "storagepath", "resource_path",
    "archive_entry", "entry_path", "member_path", "template_path",
}
FILENAME_FIELD_NAMES = {"filename", "file_name"}
DOWNLOAD_MARKERS = {"download", "downloads", "file", "files", "attachment", "export"}
ARCHIVE_MARKERS = {"archive", "zip", "tar", "extract", "unpack", "restore"}
IMPORT_MARKERS = {"import", "ingest", "restore"}
UPLOAD_MARKERS = {"upload", "uploads", "attachment", "document", "avatar"}

PATH_TRAVERSAL_TAXONOMY = {
    "owasp": ["Broken Access Control"],
    "wstg": ["WSTG-ATHZ-01"],
    "cwe": ["CWE-22"],
    "related_cwe": ["CWE-23", "CWE-36"],
    "capec": ["CAPEC-139", "CAPEC-597"],
}

PATH_TRAVERSAL_METHOD = (
    {
        "id": "PATH-01-path-surface",
        "basis": ["WSTG-ATHZ-01", "CWE-22"],
        "principle": "Identify a concrete user-influenced path, filename, archive member, or storage-path input and a file-system-relevant operation; names and routes alone remain structural evidence.",
    },
    {
        "id": "PATH-02-expected-root-policy",
        "basis": ["WSTG-ATHZ-01", "CWE-22"],
        "principle": "Model the intended base/root directory, canonicalization step, path allow-list, absolute-path policy, archive extraction root and file-operation boundary before classifying a path as unsafe.",
    },
    {
        "id": "PATH-03-controlled-boundary-observation",
        "basis": ["WSTG-ATHZ-01", "CWE-23", "CWE-36"],
        "principle": "Potential-Finding evidence requires stored behavior for an explicitly controlled non-sensitive test resource showing that a path expected to remain inside or be rejected resolved outside the intended base and reached a file operation.",
    },
    {
        "id": "PATH-04-canonicalization-and-root-controls",
        "basis": ["CWE-22", "CWE-23", "CWE-36"],
        "principle": "Treat canonicalization, root containment, absolute-path rejection, archive-member normalization and equivalent enforcement as evidence against traversal when actually observed.",
    },
    {
        "id": "PATH-05-confirmation-boundary",
        "basis": ["WSTG-ATHZ-01", "CWE-22"],
        "principle": "Confirmation is stricter than path escape: the same controlled observation must establish out-of-root access/write behavior or an actual canonicalization/root-boundary bypass tied to the file operation.",
    },
)

PATH_TRAVERSAL_FALSE_POSITIVE_CHECKS = (
    "A parameter named path, file, filename, directory, folder, or storage_path is only an input surface.",
    "A /download, /archive, /import, /extract, or /upload route does not prove the supplied path reaches a filesystem API.",
    "A normalization change or appearance of parent-directory syntax in stored input is not proof that the resolved target escaped the intended root.",
    "Direct evidence is accepted only from explicitly controlled, non-sensitive test resources; requests for sensitive operating-system or unrelated-user files are outside this analyzer contract.",
    "Canonicalization, real-path resolution, root containment, absolute-path rejection, archive-member sanitization and equivalent enforcement are contradictions when observed on the relevant operation.",
    "File Upload concerns remain a neighboring family unless filename/path control crosses a filesystem boundary; upload acceptance alone is not Path Traversal.",
    "Information disclosure is a possible consequence, not interchangeable with the traversal root cause.",
)

PATH_TRAVERSAL_WRITEUP_PATTERNS = (
    {
        "id": "owasp-wstg-athz-01-directory-traversal",
        "source": "OWASP WSTG",
        "ref": "WSTG-ATHZ-01 / Testing Directory Traversal File Include",
        "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
        "principle": "The relevant boundary is whether user-controlled path input can escape the application's intended root and reach files or directories that should be inaccessible.",
        "signals": ["path_parameter", "file_operation", "path_escape_observed", "out_of_root_file_access_observed"],
    },
    {
        "id": "cwe-22-restricted-directory",
        "source": "MITRE CWE",
        "ref": "CWE-22 / Improper Limitation of a Pathname to a Restricted Directory",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
        "principle": "Path traversal exists when external input constructs a pathname that resolves outside the restricted directory because containment is not properly enforced.",
        "signals": ["path_parameter", "base_directory_enforced", "path_escape_observed", "canonicalization_bypass_observed"],
    },
    {
        "id": "cwe-23-relative-path-traversal",
        "source": "MITRE CWE",
        "ref": "CWE-23 / Relative Path Traversal",
        "url": "https://cwe.mitre.org/data/definitions/23.html",
        "principle": "Relative traversal is a specialization of CWE-22 involving externally controlled path segments that can resolve outside the intended directory.",
        "signals": ["path_escape_observed", "canonicalization_bypass_observed"],
    },
    {
        "id": "cwe-36-absolute-path-traversal",
        "source": "MITRE CWE",
        "ref": "CWE-36 / Absolute Path Traversal",
        "url": "https://cwe.mitre.org/data/definitions/36.html",
        "principle": "Absolute-path traversal is a specialization where an externally supplied absolute pathname escapes the intended base/root.",
        "signals": ["path_escape_observed", "canonicalization_bypass_observed"],
    },
)


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "observed", "accepted", "allowed", "present", "enforced", "reached", "outside"}:
        return True
    if text in {"false", "0", "no", "rejected", "blocked", "denied", "missing", "absent", "inside", "not_observed"}:
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
        "path_traversal_observations", "path_runtime_observations", "filesystem_observations",
        "file_path_observations", "archive_extraction_observations", "download_observations",
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


def _path_fields(
    body_fields: Iterable[str], query_fields: Iterable[str], path_fields: Iterable[str], details: Mapping[str, Any]
) -> tuple[list[str], list[str], list[str]]:
    explicit = _list_value(_scalar(details, ("path_fields", "filename_fields", "file_path_fields")))
    path_values: list[str] = []
    filename_values: list[str] = []
    storage_values: list[str] = []
    for value in [*explicit, *map(str, body_fields), *map(str, query_fields), *map(str, path_fields)]:
        normalized = _normalize(value)
        if normalized not in PATH_FIELD_NAMES and not normalized.endswith("_path") and not normalized.endswith("_filename"):
            continue
        if value not in path_values:
            path_values.append(value)
        if normalized in FILENAME_FIELD_NAMES or normalized.endswith("_filename"):
            if value not in filename_values:
                filename_values.append(value)
        if normalized in {"storage_path", "storagepath"}:
            if value not in storage_values:
                storage_values.append(value)
    return path_values, filename_values, storage_values


def _operation(endpoint: str, method: str, details: Mapping[str, Any], semantic_text: str) -> dict[str, bool]:
    operation_text = str(_scalar(details, ("operation", "operation_type", "file_operation")) or "")
    text = _normalize(" ".join([endpoint, semantic_text, operation_text]))
    upper = str(method or "UNKNOWN").upper()
    write_method = upper in {"POST", "PUT", "PATCH", "DELETE"}
    download = upper in {"GET", "POST"} and any(marker in text for marker in DOWNLOAD_MARKERS)
    archive = any(marker in text for marker in ARCHIVE_MARKERS)
    import_op = write_method and any(marker in text for marker in IMPORT_MARKERS)
    upload = write_method and any(marker in text for marker in UPLOAD_MARKERS)
    explicit = _bool(_scalar(details, ("file_operation", "filesystem_operation", "file_operation_observed"))) is True
    return {
        "download_operation": download,
        "archive_operation": archive,
        "import_operation": import_op,
        "upload_operation": upload,
        "file_operation": bool(download or archive or import_op or upload or explicit),
    }


def _structural_evidence(
    path_values: list[str], filename_values: list[str], storage_values: list[str], operations: Mapping[str, bool]
) -> list[dict[str, Any]]:
    support: list[dict[str, Any]] = []
    group = "path_traversal_structural_surface"
    if filename_values:
        _add_unique(support, {
            "type": "filename_field", "source": "endpoint_schema", "source_group": group, "weight": 20,
            "text": f"Structured filename input observed: {', '.join(filename_values[:6])}.",
        })
    non_filename = [value for value in path_values if value not in filename_values and value not in storage_values]
    if non_filename:
        _add_unique(support, {
            "type": "path_parameter", "source": "endpoint_schema", "source_group": group, "weight": 20,
            "text": f"Structured path input observed: {', '.join(non_filename[:6])}.",
        })
    if storage_values:
        _add_unique(support, {
            "type": "storage_path", "source": "endpoint_schema", "source_group": group, "weight": 18,
            "text": "A client-visible storage-path field is present in the endpoint contract.",
        })
    for evidence_type, text in (
        ("download_operation", "The endpoint contract identifies a download/file retrieval operation."),
        ("archive_operation", "The endpoint contract identifies an archive/extraction-related operation."),
        ("import_operation", "The endpoint contract identifies an import/restore operation that may consume path metadata."),
        ("upload_operation", "The endpoint contract identifies an upload operation that may consume a client-controlled filename."),
        ("file_operation", "Endpoint semantics identify a concrete file-system-relevant operation."),
    ):
        if operations.get(evidence_type):
            _add_unique(support, {
                "type": evidence_type, "source": "endpoint_contract", "source_group": group, "weight": 14,
                "text": text,
            })
    return support


def _runtime_evidence(details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool, list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    promotion_direct = False
    confirmation_direct = False
    contexts: list[dict[str, Any]] = []

    observations = _observations(details)
    if not observations and any(
        key in details for key in (
            "path_escape_observed", "resolved_outside_base", "canonicalization_bypass_observed",
            "base_directory_enforced", "canonicalization_enforced", "controlled_test_path",
        )
    ):
        observations = [dict(details)]

    for index, observation in enumerate(observations, start=1):
        group = f"path_traversal_runtime_{index}"
        controlled = _bool(_scalar(observation, (
            "controlled_test_path", "test_path_controlled", "controlled_resource", "test_owned_resource",
        )))
        non_sensitive = _bool(_scalar(observation, (
            "non_sensitive_test_resource", "benign_test_resource", "harmless_sentinel", "test_owned_sentinel",
        )))
        expected_reject = _bool(_scalar(observation, (
            "expected_reject", "expected_inside_base_only", "outside_path_expected_reject", "policy_disallowed_path",
        )))
        file_operation = _bool(_scalar(observation, (
            "filesystem_operation_observed", "file_operation_observed", "file_access_attempt_observed", "archive_extraction_observed",
        )))
        resolved_outside = _bool(_scalar(observation, (
            "path_escape_observed", "resolved_outside_base", "resolved_path_outside_base", "outside_base_directory",
        )))
        rejected = _bool(_scalar(observation, ("path_rejected", "traversal_rejected", "request_rejected")))
        canonicalization_enforced = _bool(_scalar(observation, (
            "canonicalization_enforced", "realpath_enforced", "normalized_path_enforced", "archive_member_normalized",
        )))
        base_enforced = _bool(_scalar(observation, (
            "base_directory_enforced", "root_containment_enforced", "path_allowlist_enforced", "absolute_path_rejected",
        )))
        canonicalization_bypass = _bool(_scalar(observation, (
            "canonicalization_bypass_observed", "root_containment_bypass_observed", "base_directory_check_bypassed",
        )))
        outside_access = _bool(_scalar(observation, (
            "out_of_root_file_access_observed", "outside_base_file_access_observed", "test_sentinel_accessed_outside_base",
        )))
        outside_write = _bool(_scalar(observation, (
            "out_of_root_file_write_observed", "outside_base_file_write_observed", "test_sentinel_written_outside_base",
        )))

        contexts.append({
            "index": index,
            "controlled_test_path": controlled is True,
            "non_sensitive_test_resource": non_sensitive is True,
            "expected_reject_or_containment": expected_reject is True,
            "filesystem_operation_observed": file_operation is True,
            "resolved_outside_base": resolved_outside is True,
            "canonicalization_enforced": canonicalization_enforced is True,
            "base_directory_enforced": base_enforced is True,
            "confirmation_signal_present": any(value is True for value in (canonicalization_bypass, outside_access, outside_write)),
        })

        if rejected is True or base_enforced is True:
            _add_unique(contradict, {
                "type": "base_directory_enforced", "source": "stored_path_runtime", "source_group": group, "weight": -34,
                "text": "Stored behavior shows the relevant path was rejected or constrained to the intended base/root directory.",
            })
        if canonicalization_enforced is True:
            _add_unique(contradict, {
                "type": "canonicalization_enforced", "source": "stored_path_runtime", "source_group": group, "weight": -28,
                "text": "Stored behavior records canonicalization/real-path enforcement before the file operation.",
            })

        safe_direct = (
            controlled is True and non_sensitive is True and expected_reject is True
            and file_operation is True and resolved_outside is True
        )
        if not safe_direct:
            continue

        _add_unique(support, {
            "type": "path_escape_observed", "source": "stored_path_runtime", "source_group": group, "weight": 42,
            "text": "A controlled non-sensitive test path that should have remained inside or been rejected resolved outside the intended base and reached the relevant file operation.",
        })
        _add_unique(support, {
            "type": "path_boundary_differential", "source": "stored_path_runtime", "source_group": group, "weight": 22,
            "text": "Stored expected-vs-observed behavior differs at the documented filesystem root boundary for the same controlled test resource.",
        })
        promotion_direct = True

        if canonicalization_bypass is True:
            _add_unique(support, {
                "type": "canonicalization_bypass_observed", "source": "stored_path_runtime", "source_group": group, "weight": 48,
                "text": "The same controlled observation records a canonicalization/root-containment control bypass tied to the out-of-root file operation.",
            })
            confirmation_direct = True
        if outside_access is True:
            _add_unique(support, {
                "type": "out_of_root_file_access_observed", "source": "stored_path_runtime", "source_group": group, "weight": 50,
                "text": "The same controlled non-sensitive observation records access to a test-owned resource outside the intended base/root.",
            })
            confirmation_direct = True
        if outside_write is True:
            _add_unique(support, {
                "type": "out_of_root_file_write_observed", "source": "stored_path_runtime", "source_group": group, "weight": 52,
                "text": "Stored evidence records a test-owned non-sensitive resource written outside the intended base/root; the analyzer itself performed no write.",
            })
            confirmation_direct = True

    return support, contradict, promotion_direct, confirmation_direct, contexts


def _variant(support: list[dict[str, Any]], contradict: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in support}
    controls = {str(item.get("type") or "") for item in contradict}
    if "out_of_root_file_write_observed" in types:
        return "out_of_root_write"
    if "out_of_root_file_access_observed" in types:
        return "out_of_root_access"
    if "canonicalization_bypass_observed" in types:
        return "canonicalization_boundary_bypass"
    if "path_escape_observed" in types:
        return "controlled_path_escape"
    if controls.intersection({"canonicalization_enforced", "base_directory_enforced"}):
        return "path_boundary_enforced"
    return "path_construction"


def analyze_path_traversal_signal(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    method: str = "UNKNOWN",
    body_fields: Iterable[str] = (),
    query_fields: Iterable[str] = (),
    path_fields: Iterable[str] = (),
    details: Mapping[str, Any] | None = None,
    business_context: str = "general",
    semantic_text: str = "",
) -> dict[str, Any] | None:
    del db, analysis_id, target, business_context
    details = dict(details or {})
    path_values, filename_values, storage_values = _path_fields(body_fields, query_fields, path_fields, details)
    operations = _operation(endpoint, method, details, semantic_text)
    support = _structural_evidence(path_values, filename_values, storage_values, operations)
    runtime_support, contradict, promotion_direct, confirmation_direct, contexts = _runtime_evidence(details)
    for item in runtime_support:
        _add_unique(support, item)

    if not support and not contradict:
        return None

    observed = {str(item.get("type") or "") for item in support}
    confirmation_missing = list(confirmation_gaps("path_traversal", observed))
    if not confirmation_direct:
        stronger = "Stored out-of-root access/write behavior or a canonicalization/root-containment bypass tied to the same controlled non-sensitive file operation."
        if stronger not in confirmation_missing:
            confirmation_missing.append(stronger)
    blockers = {str(item.get("type") or "") for item in contradict}
    direct_confirmation_types = {
        "canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed",
    }
    confirmation_ready = confirmation_direct and bool(observed & direct_confirmation_types)
    if blockers.intersection({"canonicalization_enforced", "base_directory_enforced"}) and not bool(observed & direct_confirmation_types):
        confirmation_ready = False

    metadata = PathTraversalFamilyAnalyzer().metadata()
    metadata.update({
        "family_rule_version": PATH_TRAVERSAL_FAMILY_ANALYZER_RULE_VERSION,
        "taxonomy": {key: list(value) for key, value in PATH_TRAVERSAL_TAXONOMY.items()},
        "methodology": [dict(step) for step in PATH_TRAVERSAL_METHOD],
        "false_positive_checks": list(PATH_TRAVERSAL_FALSE_POSITIVE_CHECKS),
        "triggered_false_positive_checks": [
            {"signal": str(item.get("type") or ""), "text": str(item.get("text") or "")}
            for item in contradict
        ],
        "writeup_patterns": [dict(item, non_evidentiary=True) for item in PATH_TRAVERSAL_WRITEUP_PATTERNS],
        "path_fields": list(path_values),
        "operations": dict(operations),
        "observation_context": contexts,
        "structural_path_and_operation_are_one_evidence_root": True,
        "promotion_ready_from_stored_target_evidence": promotion_direct,
        "confirmation_missing": confirmation_missing,
        "confirmation_ready_from_stored_target_evidence": confirmation_ready,
        "knowledge_does_not_change_target_evidence": True,
        "active_validation_performed": False,
        "active_request_performed": False,
        "filesystem_read_performed_by_analyzer": False,
        "filesystem_write_performed_by_analyzer": False,
        "archive_extraction_performed_by_analyzer": False,
        "sensitive_path_requested_by_analyzer": False,
        "traversal_payload_generated": False,
    })

    missing = list(FAMILY_REASONING["path_traversal"]["next_evidence"])
    if promotion_direct:
        missing = [
            "Determine whether the same controlled non-sensitive observation reached a test-owned resource outside the intended base/root.",
            "Capture whether canonicalization/root-containment enforcement was bypassed without requesting sensitive filesystem paths.",
        ]
    if confirmation_ready:
        missing = []

    return {
        "family": "path_traversal",
        "variant": _variant(support, contradict),
        "support": support,
        "contradict": contradict,
        "missing": missing,
        "rule_ids": [
            "family-path-surface",
            "family-path-root-policy",
            "family-path-controlled-observation",
            "family-path-canonicalization-controls",
            "family-path-confirmation-boundary",
        ],
        "summary": (
            "Stored target evidence establishes an out-of-root file-operation or canonicalization boundary failure using a controlled non-sensitive test resource."
            if confirmation_ready
            else "Stored target evidence shows a controlled non-sensitive path escaped the intended base and reached a file operation; out-of-root access/write impact remains unconfirmed."
            if promotion_direct
            else "A path/file-operation surface is retained as a hidden hypothesis; stored target behavior has not established a filesystem root escape."
        ),
        "direct": promotion_direct,
        "family_analyzer": metadata,
    }


class PathTraversalFamilyAnalyzer(FamilyAnalyzer):
    family = "path_traversal"
    analyzer_version = PATH_TRAVERSAL_FAMILY_ANALYZER_VERSION

    def analyze(self, context: FamilyAnalyzerContext, **kwargs: Any) -> dict[str, Any] | None:
        return analyze_path_traversal_signal(
            context.db,
            analysis_id=context.analysis_id,
            target=context.target,
            endpoint=context.endpoint,
            method=context.method,
            body_fields=kwargs.get("body_fields") or (),
            query_fields=kwargs.get("query_fields") or (),
            path_fields=kwargs.get("path_fields") or (),
            details=context.details,
            business_context=context.business_context,
            semantic_text=str(kwargs.get("semantic_text") or ""),
        )
