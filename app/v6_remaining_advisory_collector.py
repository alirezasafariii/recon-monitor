from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

MANIFEST = ROOT / "benchmarks/raw/sources/v6_remaining_capture_manifest.json"
VARIANTS = ("positive", "near_miss", "secure_negative", "sparse_noisy")

# These are capture-only source semantics. They do not participate in production
# detection, admission, ranking, or scoring. Each profile translates a published
# upstream narrative into neutral observable facts without copying family labels
# or detector signal names into raw benchmark observations.
SOURCE_LOGIC: dict[str, dict[str, Any]] = {
    "authentication_session": {
        "terms": (("auth", "session", "ntlm", "token"), ("bypass", "validation", "impersonat", "privilege")),
        "raw": {"identity_boundary_validation_failed": True, "authenticated_context_changed_without_expected_validation": True},
    },
    "broken_function_authorization": {
        "terms": (("admin", "privilege", "role", "permission", "function"), ("bypass", "unauthor", "low-privilege", "access")),
        "raw": {"lower_privilege_context_reached_restricted_operation": True, "function_scope_check_missing_or_ineffective": True},
    },
    "cors_misconfiguration": {
        "terms": (("cors", "cross-origin", "origin"), ("credential", "token", "sensitive", "auth")),
        "raw": {"untrusted_origin_policy_observed": True, "cross_origin_sensitive_response_boundary_present": True},
    },
    "dom_xss": {
        "terms": (("dom", "svg", "browser", "client"), ("xss", "script", "executable", "sanit")),
        "raw": {"user_controlled_client_content_reached_executable_rendering_context": True, "effective_neutralization_missing_or_bypassed": True},
    },
    "file_upload": {
        "terms": (("upload", "file", "attachment", "import"), ("arbitrary", "dangerous", "execute", "type", "content")),
        "raw": {"attacker_controlled_file_processing_boundary_present": True, "dangerous_file_restriction_missing_or_ineffective": True},
    },
    "graphql_data_exposure": {
        "terms": (("graphql", "field", "query", "resolver"), ("data", "expos", "sensitive", "unauthor")),
        "raw": {"structured_query_response_crossed_intended_field_visibility_boundary": True, "additional_sensitive_fields_returned": True},
    },
    "improper_inventory_management": {
        "terms": (("version", "legacy", "old", "deprecated", "inventory"), ("api", "endpoint", "production", "expos")),
        "raw": {"legacy_or_unintended_service_surface_remained_reachable": True, "inventory_lifecycle_control_gap_observed": True},
    },
    "ldap_injection": {
        "terms": (("ldap", "directory", "filter"), ("inject", "query", "filter", "auth")),
        "raw": {"client_input_influenced_directory_filter_semantics": True, "directory_query_structure_changed": True},
    },
    "mass_assignment": {
        "terms": (("property", "field", "attribute", "mass assignment"), ("privilege", "role", "unauthor", "writable")),
        "raw": {"client_supplied_property_outside_intended_write_policy_was_accepted": True, "privileged_state_change_possible": True},
    },
    "nosql_injection": {
        "terms": (("nosql", "mongo", "document", "operator"), ("inject", "query", "operator", "bypass")),
        "raw": {"client_structure_influenced_document_query_semantics": True, "query_operator_behavior_changed": True},
    },
    "open_redirect": {
        "terms": (("redirect", "return url", "next", "callback", "location"), ("external", "untrusted", "arbitrary", "destination")),
        "raw": {"client_controlled_navigation_target_accepted": True, "unintended_external_destination_reachable": True},
    },
    "postmessage_trust": {
        "terms": (("postmessage", "message", "origin", "window"), ("origin", "source", "trust", "validation", "bypass")),
        "raw": {"cross_window_message_reached_sensitive_behavior": True, "sender_origin_or_source_validation_missing_or_ineffective": True},
    },
    "race_condition": {
        "terms": (("race", "concurrent", "timing", "toctou"), ("duplicate", "atomic", "lock", "state", "concurrent")),
        "raw": {"concurrent_state_transition_produced_non_atomic_outcome": True, "single_use_or_state_invariant_was_violated": True},
    },
    "secret_exposure": {
        "terms": (("secret", "credential", "token", "key", "password"), ("expos", "leak", "public", "client", "log")),
        "raw": {"non_placeholder_credential_material_reached_unintended_context": True, "credential_confidentiality_boundary_failed": True},
    },
    "security_logging_alerting_failure": {
        "terms": (("log", "logging", "audit", "alert"), ("missing", "insufficient", "sensitive", "inject", "monitor")),
        "raw": {"security_relevant_event_logging_or_alert_control_failed": True, "stored_audit_outcome_was_missing_or_unsafe": True},
    },
    "security_misconfiguration": {
        "terms": (("config", "configuration", "header", "debug", "method", "default"), ("insecure", "expos", "misconfig", "unsafe", "enabled")),
        "raw": {"deployed_security_configuration_exposed_unsafe_behavior": True, "expected_hardening_control_absent_or_ineffective": True},
    },
    "server_side_template_injection": {
        "terms": (("template", "render", "expression"), ("inject", "evaluate", "execute", "server")),
        "raw": {"client_controlled_template_expression_reached_server_evaluator": True, "server_side_expression_evaluation_observed": True},
    },
    "sql_injection": {
        "terms": (("sql", "database", "query"), ("inject", "query", "execute", "statement")),
        "raw": {"client_input_influenced_relational_query_semantics": True, "unsafe_query_execution_path_observed": True},
    },
    "unrestricted_resource_consumption": {
        "terms": (("resource", "limit", "rate", "memory", "cpu", "request", "upload"), ("unbounded", "exhaust", "dos", "limit", "consume")),
        "raw": {"attacker_controlled_workload_crossed_expected_resource_limit": True, "effective_size_frequency_cost_or_timeout_limit_missing": True},
    },
    "unsafe_api_consumption": {
        "terms": (("api", "upstream", "third-party", "external", "remote"), ("trust", "validate", "sanitize", "timeout", "certificate", "response")),
        "raw": {"external_service_data_crossed_application_trust_boundary": True, "upstream_validation_or_transport_control_missing_or_ineffective": True},
    },
    "websocket_authorization": {
        "terms": (("websocket", "socket", "channel", "subscription"), ("author", "unauthor", "tenant", "room", "subscribe")),
        "raw": {"realtime_channel_or_subscription_crossed_identity_scope": True, "message_or_subscription_authorization_missing_or_ineffective": True},
    },
}


def _get_json(api_url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "analysis-631-remaining-source-capture",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        value = json.load(response)
    if not isinstance(value, Mapping):
        raise RuntimeError(f"GitHub source did not return an object: {api_url}")
    return dict(value)


def _api_for_reference(reference: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(reference)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) == 2 and parts[0] == "advisories" and parts[1].startswith("GHSA-"):
        return f"https://api.github.com/advisories/{parts[1]}", "github_advisory_database"
    if len(parts) >= 5 and parts[2:4] == ["security", "advisories"] and parts[4].startswith("GHSA-"):
        owner, repo, ghsa = parts[0], parts[1], parts[4]
        return f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa}", "repository_security_advisory"
    return None


def _text(doc: Mapping[str, Any]) -> str:
    return str(doc.get("description") or doc.get("body") or "").strip()


def _term_groups_pass(text: str, groups: tuple[tuple[str, ...], ...]) -> bool:
    lower = text.lower()
    return all(any(term.lower() in lower for term in group) for group in groups)


def _vulnerability_metadata(doc: Mapping[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    rows: list[dict[str, str]] = []
    patched: list[str] = []
    for raw in doc.get("vulnerabilities") or []:
        if not isinstance(raw, Mapping):
            continue
        package = raw.get("package") if isinstance(raw.get("package"), Mapping) else {}
        first = raw.get("first_patched_version") if isinstance(raw.get("first_patched_version"), Mapping) else {}
        identifier = str(first.get("identifier") or "").strip()
        if identifier:
            patched.append(identifier)
        rows.append({
            "ecosystem": str(package.get("ecosystem") or ""),
            "package": str(package.get("name") or ""),
            "vulnerable_version_range": str(raw.get("vulnerable_version_range") or ""),
            "first_patched_version": identifier,
        })
    return rows, sorted(set(patched))


def _cwe_ids(doc: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    for raw in doc.get("cwes") or []:
        if isinstance(raw, Mapping):
            value = str(raw.get("cwe_id") or raw.get("id") or "").strip()
        else:
            value = str(raw or "").strip()
        if value:
            result.append(value)
    return sorted(set(result))


def collect(output: Path, *, manifest_path: Path = MANIFEST) -> dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    families = [dict(row) for row in manifest.get("families") or [] if isinstance(row, Mapping)]
    captured_at = datetime.now(timezone.utc).isoformat()
    output.mkdir(parents=True, exist_ok=True)
    completed: list[str] = []
    skipped: dict[str, str] = {}

    for row in families:
        family = str(row.get("family") or "")
        profile = SOURCE_LOGIC.get(family)
        if not profile:
            skipped[family] = "no_capture_logic_profile"
            continue
        reference = str(row.get("canonical_reference") or "").strip()
        api = _api_for_reference(reference)
        if api is None:
            skipped[family] = "canonical_source_not_supported_by_advisory_collector"
            continue
        api_url, source_kind = api
        try:
            doc = _get_json(api_url)
        except Exception as exc:  # source availability is reported, never synthesized around
            skipped[family] = f"source_fetch_failed:{type(exc).__name__}"
            continue
        narrative = _text(doc)
        if not narrative or not _term_groups_pass(narrative, profile["terms"]):
            skipped[family] = "source_narrative_did_not_satisfy_preregistered_semantic_groups"
            continue
        vulnerabilities, patched_versions = _vulnerability_metadata(doc)
        if not vulnerabilities:
            skipped[family] = "no_structured_vulnerability_scope_metadata"
            continue
        if not patched_versions:
            skipped[family] = "no_structured_first_patched_version_for_secure_control"
            continue
        cwes = _cwe_ids(doc)
        references = [str(v) for v in doc.get("references") or [] if str(v).startswith("https://")]
        if not cwes and not references:
            skipped[family] = "no_independent_sparse_metadata"
            continue
        condition_signals = [str(v) for v in row.get("condition_signals") or [] if str(v)]
        if not condition_signals:
            skipped[family] = "no_preregistered_condition_vocabulary"
            continue

        source_id = str(doc.get("ghsa_id") or doc.get("cve_id") or row.get("source_root") or family)
        out = output / family
        out.mkdir(parents=True, exist_ok=True)
        first_scope = vulnerabilities[0]
        raw_base = {
            "target": str(row.get("source_project") or source_id),
            "endpoint": str(first_scope.get("package") or source_id),
            "method": "UNKNOWN",
            "endpoint_schema": {},
        }

        def emit(kind: str, payload: Mapping[str, Any], details: Mapping[str, Any], basis: str, notes: str, signals: list[str]) -> None:
            capture = {
                "family": family,
                "case_kind": kind,
                "captured_at": captured_at,
                "capture_reference": reference,
                "capture_method": "cli_output",
                "collector": {
                    "tool": "github-actions/github-advisory-api-source-capture",
                    "command": f"GET {api_url}",
                    "source_file": source_kind,
                },
                "source_snapshot": {
                    "reference": reference,
                    "retrieved_at": captured_at,
                    "payload": dict(payload),
                },
                "adjudication": {
                    "basis": basis,
                    "notes": notes,
                    "expected_condition_signals": signals,
                    "detector_output_used": False,
                    "admission_output_used": False,
                    "ranking_output_used": False,
                },
                "raw": {**raw_base, "details": dict(details)},
            }
            (out / f"{kind}.json").write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        emit(
            "positive",
            {"source_id": source_id, "narrative": narrative, "published_at": doc.get("published_at")},
            {**dict(profile["raw"]), "affected_component": first_scope.get("package") or "", "affected_range_recorded": bool(first_scope.get("vulnerable_version_range"))},
            "source_observation",
            "The canonical upstream security narrative records the family-specific trust/control failure represented by the neutral raw facts; the narrative is retained only in the source snapshot, not copied into raw input.",
            [condition_signals[0]],
        )
        emit(
            "secure_negative",
            {"source_id": source_id, "first_patched_versions": patched_versions},
            {"published_fixed_version_control": True, "first_patched_versions": patched_versions, "vulnerable_behavior_observed_in_control": False},
            "patched_control",
            "The canonical upstream record independently identifies one or more first patched versions, providing a source-grounded fixed-version control without reusing the positive narrative as raw input.",
            [],
        )
        emit(
            "near_miss",
            {"source_id": source_id, "vulnerability_scope": vulnerabilities},
            {"component_and_version_scope_only": True, "vulnerable_version_ranges": [v.get("vulnerable_version_range") for v in vulnerabilities], "behavioral_outcome_observed": False},
            "source_scope_metadata",
            "The package/ecosystem/version applicability metadata identifies a relevant attack surface but contains no behavioral proof by itself, so it is retained as a near-miss rather than promoted condition evidence.",
            [],
        )
        emit(
            "sparse_noisy",
            {"source_id": source_id, "cwes": cwes, "references": references[:12]},
            {"taxonomy_or_reference_metadata_only": True, "cwe_count": len(cwes), "reference_count": len(references), "behavioral_outcome_observed": False},
            "source_metadata",
            "Taxonomy/reference metadata is independently source-grounded but does not establish exploit preconditions, trust-boundary crossing, or observable vulnerable behavior and is intentionally sparse/noisy.",
            [],
        )
        completed.append(family)

    result = {
        "captured_family_count": len(completed),
        "captured_evidence_count": len(completed) * len(VARIANTS),
        "captured_families": sorted(completed),
        "skipped": dict(sorted(skipped.items())),
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "scoring_executed": False,
        "first_blind_consumed": False,
    }
    if not completed:
        raise RuntimeError("no remaining advisory family satisfied the strict four-observation source contract")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = collect(args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
