from __future__ import annotations

"""Evidence-contract hardening for families migrated into ``family_specs``.

The original Family Reasoning catalog remains the compatibility source for all
consumers. These reviewed overrides tighten only the migrated families whose
analyzers already require stronger stored target evidence than the historical
catalog expressed.
"""

from typing import Any


FINAL_ANALYZER_REASONING_VERSION = "1.2.1"
FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.15.6"


def _groups(*values: set[str]) -> tuple[frozenset[str], ...]:
    return tuple(frozenset(group) for group in values)


def apply_final_analyzer_reasoning(catalog: dict[str, dict[str, Any]]) -> None:
    """Mutate the live compatibility catalog with reviewed evidence gates."""

    bfla = dict(catalog["broken_function_authorization"])
    bfla.update(
        {
            "promotion_required": _groups(
                {"privileged_function", "privileged_classification"},
                {"state_change", "role_property", "privileged_read_operation", "privileged_operation_semantic"},
                {"unauthorized_function_success", "role_authorization_differential", "permission_scope_mismatch"},
            ),
            "blocking_contradictions": frozenset(
                {"role_enforcement_observed", "lower_privilege_denied", "permission_check_enforced"}
            ),
            "override_signals": frozenset(
                {"unauthorized_function_success", "role_authorization_differential", "permission_scope_mismatch"}
            ),
            "confirmation_required": _groups(
                {"unauthorized_function_success", "role_authorization_differential", "permission_scope_mismatch"}
            ),
        }
    )
    catalog["broken_function_authorization"] = bfla

    ssrf = dict(catalog["ssrf"])
    ssrf.update(
        {
            "promotion_required": _groups(
                {"remote_destination", "url_parameter"},
                {"server_feature", "server_fetch_semantic", "server_request_function"},
                {"server_fetch_observed", "controlled_callback_observed"},
            ),
            "blocking_contradictions": frozenset(
                {"browser_side_fetch_observed", "destination_validation_observed", "server_fetch_not_observed"}
            ),
            "override_signals": frozenset(
                {"destination_policy_bypass_observed", "restricted_destination_accepted"}
            ),
            "confirmation_required": _groups(
                {"destination_policy_bypass_observed", "restricted_destination_accepted"}
            ),
        }
    )
    catalog["ssrf"] = ssrf

    dom_xss = dict(catalog["dom_xss"])
    dom_xss.update(
        {
            "promotion_required": _groups(
                {"dataflow_source", "source_sink"},
                {"dataflow_sink", "source_sink"},
                {"unsanitized_dom_flow"},
            ),
            "blocking_contradictions": frozenset(
                {"sanitization_observed", "runtime_unreachable"}
            ),
            "override_signals": frozenset({"unsanitized_dom_flow"}),
            "confirmation_required": _groups({"unsanitized_dom_flow"}),
        }
    )
    catalog["dom_xss"] = dom_xss

    mass_assignment = dict(catalog["mass_assignment"])
    mass_assignment.update(
        {
            "promotion_required": _groups(
                {"privileged_property", "privileged_fields"},
                {"write_method", "body_schema", "object_update"},
                {"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"},
            ),
            "blocking_contradictions": frozenset(
                {"protected_property_rejected", "server_allowlist_observed", "sensitive_property_ignored"}
            ),
            "override_signals": frozenset(
                {"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"}
            ),
            "confirmation_required": _groups(
                {"protected_property_accepted", "protected_property_mutated", "property_authorization_differential"}
            ),
        }
    )
    catalog["mass_assignment"] = mass_assignment

    file_upload = dict(catalog["file_upload"])
    file_upload.update(
        {
            "promotion_required": _groups(
                {"file_input"},
                {"upload_operation", "import_operation"},
                {
                    "unsafe_file_accepted", "file_policy_differential",
                    "content_type_bypass_observed", "executable_upload_observed",
                },
            ),
            "blocking_contradictions": frozenset({"file_type_enforcement_observed", "safe_storage_observed"}),
            "override_signals": frozenset(
                {"unsafe_file_accepted", "content_type_bypass_observed", "executable_upload_observed"}
            ),
            "confirmation_required": _groups(
                {"content_type_bypass_observed", "executable_upload_observed"}
            ),
        }
    )
    catalog["file_upload"] = file_upload

    path_traversal = dict(catalog["path_traversal"])
    path_traversal.update(
        {
            "promotion_required": _groups(
                {"path_parameter", "filename_field", "storage_path"},
                {"file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation"},
                {
                    "path_escape_observed", "path_boundary_differential",
                    "canonicalization_bypass_observed", "out_of_root_file_access_observed",
                    "out_of_root_file_write_observed",
                },
            ),
            "blocking_contradictions": frozenset({"canonicalization_enforced", "base_directory_enforced"}),
            "override_signals": frozenset(
                {"path_escape_observed", "canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed"}
            ),
            "confirmation_required": _groups(
                {"canonicalization_bypass_observed", "out_of_root_file_access_observed", "out_of_root_file_write_observed"}
            ),
        }
    )
    catalog["path_traversal"] = path_traversal

    cors = dict(catalog["cors_misconfiguration"])
    cors.update(
        {
            "promotion_required": _groups(
                {"cors_header"},
                {"sensitive_context"},
                {"untrusted_origin_allowed", "credentialed_cross_origin_read"},
            ),
            "blocking_contradictions": frozenset(
                {"trusted_origin_only", "credentials_disabled", "cross_origin_read_blocked"}
            ),
            "override_signals": frozenset({"untrusted_origin_allowed", "credentialed_cross_origin_read"}),
            "confirmation_required": _groups({"untrusted_origin_allowed", "credentialed_cross_origin_read"}),
        }
    )
    catalog["cors_misconfiguration"] = cors
