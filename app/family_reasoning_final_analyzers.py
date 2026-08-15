from __future__ import annotations

"""Evidence-contract hardening for families migrated into ``family_specs``.

The original Family Reasoning catalog remains the compatibility source for all
consumers. These reviewed overrides tighten only the migrated families whose
analyzers already require stronger stored target evidence than the historical
catalog expressed.
"""

from typing import Any


FINAL_ANALYZER_REASONING_VERSION = "1.0.0"
FINAL_ANALYZER_REASONING_RULE_VERSION = "2026.08.15.3"


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
            # A server-side fetch proves execution location, not a destination
            # control failure. Only actual boundary-failure evidence may override
            # an observed destination control.
            "override_signals": frozenset(
                {"destination_policy_bypass_observed", "restricted_destination_accepted"}
            ),
            "confirmation_required": _groups(
                {"destination_policy_bypass_observed", "restricted_destination_accepted"}
            ),
        }
    )
    catalog["ssrf"] = ssrf
