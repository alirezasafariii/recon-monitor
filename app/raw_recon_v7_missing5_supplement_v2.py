from __future__ import annotations

import json
import os

import raw_recon_v7_missing5_supplement as base

VERSION = "1.1.0"
RULE_VERSION = "2026.08.14.6.32.v7.26"

# Broader discovery vocabulary only. Acceptance remains entirely in the existing
# firewall + family semantic + condition audit + real merged-patch gates.
base.QUERIES = {
    "file_upload": (
        '"arbitrary file upload" security',
        '"unrestricted file upload" security',
        '"file upload" "extension validation" security',
        '"file upload" "mime validation" security',
        '"upload" "filename validation" security',
        '"upload" "executable file" security',
        '"uploaded file" security validation',
        '"dangerous file" upload security',
        '"content type" upload security validation',
    ),
    "graphql_authorization": (
        'GraphQL authorization security',
        'GraphQL "access control" security',
        'GraphQL permission security',
        'GraphQL permissions resolver security',
        'GraphQL resolver authorization',
        'GraphQL unauthorized mutation',
        'GraphQL unauthorized query',
        'GraphQL role permission',
        'GraphQL RBAC security',
        'GraphQL authentication authorization resolver',
    ),
    "graphql_data_exposure": (
        'GraphQL "information disclosure"',
        'GraphQL "data exposure" security',
        'GraphQL "sensitive data" exposure',
        'GraphQL "sensitive fields" security',
        'GraphQL introspection exposure security',
        'GraphQL schema exposure security',
        'GraphQL unauthorized data security',
        'GraphQL response sensitive security',
        'GraphQL private fields exposure',
        'GraphQL data leak security',
    ),
    "security_logging_alerting_failure": (
        'password log redaction security',
        'password logging security redact',
        'token log redaction security',
        'credential log redaction security',
        'secret logging security redact',
        '"sensitive data" logging security redact',
        '"sensitive information" logs security',
        '"access token" logs redact security',
        '"api key" logs redact security',
        '"remove password" logs security',
    ),
    "software_supply_chain_failure": (
        '"dependency confusion" security',
        '"dependency confusion" package security',
        '"malicious dependency" security',
        '"malicious package" security',
        '"compromised dependency" security',
        '"compromised package" security',
        '"supply chain" dependency security',
        '"supply-chain" dependency security',
        '"package integrity" dependency security',
        '"dependency integrity" security package',
        '"dependency hijacking" security',
        '"package hijacking" security',
    ),
}


def main() -> int:
    report = base.discover(os.environ.get("GITHUB_TOKEN"))
    report["version"] = VERSION
    report["rule_version"] = RULE_VERSION
    report["evaluation_kind"] = "fresh_blind_v7_missing5_patchable_supplement_v2_unscored"
    base.OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_candidate_counts": report["family_candidate_counts"],
        "families_without_candidates": report["families_without_candidates"],
        "search_api_call_count": report["search_api_call_count"],
        "patch_api_call_count": report["patch_api_call_count"],
        "scoring_executed": report["scoring_executed"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
