from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected exactly one replacement, found {count}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def insert_before_once(relative: str, marker: str, block: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(marker)
    if count != 1:
        raise RuntimeError(f"{relative}: expected exactly one insertion marker, found {count}: {marker!r}")
    path.write_text(text.replace(marker, block + marker, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1) Canonical standards: WSTG + OWASP taxonomy + CWE for every family.
# ---------------------------------------------------------------------------
replace_once(
    "app/analysis_standards.py",
    'STANDARDS_ENGINE_VERSION = "1.2.0"\nWSTG_REFERENCE_VERSION = "latest@2026-08-10"\nCWE_REFERENCE_VERSION = "4.20"\nWSTG_BASE_URL = \'https://owasp.org/www-project-web-security-testing-guide/latest/\'\nCWE_BASE_URL = "https://cwe.mitre.org/data/definitions/"',
    'STANDARDS_ENGINE_VERSION = "1.3.0"\nWSTG_REFERENCE_VERSION = "latest@2026-08-10"\nOWASP_REFERENCE_VERSION = "Top10:2025+API-Security:2023"\nCWE_REFERENCE_VERSION = "4.20"\nWSTG_BASE_URL = \'https://owasp.org/www-project-web-security-testing-guide/latest/\'\nOWASP_TOP10_2025_BASE_URL = "https://owasp.org/Top10/2025/"\nOWASP_API_2023_BASE_URL = "https://owasp.org/API-Security/editions/2023/en/"\nCWE_BASE_URL = "https://cwe.mitre.org/data/definitions/"',
)

insert_before_once(
    "app/analysis_standards.py",
    "FAMILY_STANDARDS: dict[str, dict[str, Any]] = {",
    '''def _owasp(ref_id: str, title: str, url: str, *, source: str, mapping: str = "direct") -> dict[str, Any]:
    return {"id": ref_id, "title": title, "url": url, "source": source, "mapping": mapping}


def _top10(ref_id: str, title: str, slug: str, *, mapping: str = "direct") -> dict[str, Any]:
    return _owasp(ref_id, title, f"{OWASP_TOP10_2025_BASE_URL}{slug}/", source="OWASP Top 10", mapping=mapping)


def _api_top10(ref_id: str, title: str, slug: str, *, mapping: str = "direct") -> dict[str, Any]:
    return _owasp(ref_id, title, f"{OWASP_API_2023_BASE_URL}{slug}/", source="OWASP API Security Top 10", mapping=mapping)


''',
)

replace_once(
    "app/analysis_standards.py",
    "            _cwe('CWE-346', 'Origin Validation Error', mapping='contextual', auto_assign=True, when_any=('missing_origin_check', 'wildcard_origin', 'missing_source_window_check')),",
    "            _cwe('CWE-940', 'Improper Verification of Source of a Communication Channel', mapping='direct', auto_assign=True, when_any=('missing_origin_check', 'missing_source_window_check', 'message_schema_unvalidated')),\n            _cwe('CWE-346', 'Origin Validation Error', mapping='contextual', auto_assign=False, when_any=('missing_origin_check', 'wildcard_origin', 'missing_source_window_check')),",
)

OWASP_MAPPING_BLOCK = '''

# Analysis 6.19 makes OWASP taxonomy grounding a first-class, mandatory part of
# every physical family detector. WSTG remains the testing-method source; OWASP
# Top 10 / API Security Top 10 provides risk taxonomy; CWE provides weakness
# taxonomy. None of these references are target evidence.
FAMILY_OWASP_MAPPINGS: dict[str, list[dict[str, Any]]] = {
    "broken_object_authorization": [
        _api_top10("API1:2023", "Broken Object Level Authorization", "0xa1-broken-object-level-authorization"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "broken_function_authorization": [
        _api_top10("API5:2023", "Broken Function Level Authorization", "0xa5-broken-function-level-authorization"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "mass_assignment": [
        _api_top10("API3:2023", "Broken Object Property Level Authorization", "0xa3-broken-object-property-level-authorization"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control", mapping="contextual"),
    ],
    "authentication_session": [
        _top10("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures"),
        _api_top10("API2:2023", "Broken Authentication", "0xa2-broken-authentication", mapping="contextual"),
    ],
    "account_enumeration": [
        _top10("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures", mapping="contextual"),
        _api_top10("API2:2023", "Broken Authentication", "0xa2-broken-authentication", mapping="contextual"),
    ],
    "dom_xss": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "postmessage_trust": [
        _top10("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures"),
    ],
    "open_redirect": [
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "ssrf": [
        _api_top10("API7:2023", "Server Side Request Forgery", "0xa7-server-side-request-forgery"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "file_upload": [
        _top10("A06:2025", "Insecure Design", "A06_2025-Insecure_Design"),
    ],
    "path_traversal": [
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "information_disclosure": [
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "source_map_exposure": [
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control", mapping="contextual"),
    ],
    "secret_exposure": [
        _top10("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures", mapping="contextual"),
    ],
    "graphql_authorization": [
        _api_top10("API1:2023", "Broken Object Level Authorization", "0xa1-broken-object-level-authorization"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "graphql_data_exposure": [
        _api_top10("API3:2023", "Broken Object Property Level Authorization", "0xa3-broken-object-property-level-authorization"),
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control", mapping="contextual"),
    ],
    "business_logic": [
        _top10("A06:2025", "Insecure Design", "A06_2025-Insecure_Design"),
    ],
    "race_condition": [
        _top10("A06:2025", "Insecure Design", "A06_2025-Insecure_Design"),
    ],
    "websocket_authorization": [
        _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control"),
    ],
    "cors_misconfiguration": [
        _top10("A02:2025", "Security Misconfiguration", "A02_2025-Security_Misconfiguration"),
    ],
    "sensitive_caching": [
        _top10("A06:2025", "Insecure Design", "A06_2025-Insecure_Design", mapping="contextual"),
    ],
    "sql_injection": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "nosql_injection": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "command_injection": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "server_side_template_injection": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "ldap_injection": [
        _top10("A05:2025", "Injection", "A05_2025-Injection"),
    ],
    "unrestricted_resource_consumption": [
        _api_top10("API4:2023", "Unrestricted Resource Consumption", "0xa4-unrestricted-resource-consumption"),
    ],
    "sensitive_business_flow_abuse": [
        _api_top10("API6:2023", "Unrestricted Access to Sensitive Business Flows", "0xa6-unrestricted-access-to-sensitive-business-flows"),
        _top10("A06:2025", "Insecure Design", "A06_2025-Insecure_Design", mapping="contextual"),
    ],
    "security_misconfiguration": [
        _api_top10("API8:2023", "Security Misconfiguration", "0xa8-security-misconfiguration"),
        _top10("A02:2025", "Security Misconfiguration", "A02_2025-Security_Misconfiguration"),
    ],
    "improper_inventory_management": [
        _api_top10("API9:2023", "Improper Inventory Management", "0xa9-improper-inventory-management"),
    ],
    "unsafe_api_consumption": [
        _api_top10("API10:2023", "Unsafe Consumption of APIs", "0xaa-unsafe-consumption-of-apis"),
    ],
}

if set(FAMILY_OWASP_MAPPINGS) != set(FAMILY_STANDARDS):
    missing = sorted(set(FAMILY_STANDARDS) - set(FAMILY_OWASP_MAPPINGS))
    extra = sorted(set(FAMILY_OWASP_MAPPINGS) - set(FAMILY_STANDARDS))
    raise RuntimeError(f"OWASP family mapping coverage drift missing={missing} extra={extra}")
for _family, _refs in FAMILY_OWASP_MAPPINGS.items():
    FAMILY_STANDARDS[_family]["owasp"] = list(_refs)
'''
insert_before_once("app/analysis_standards.py", "\ndef standards_for_family(\n", OWASP_MAPPING_BLOCK)

replace_once(
    "app/analysis_standards.py",
    '    WSTG and CWE describe the security condition and taxonomy. They never satisfy\n    an admission evidence group or independent-source requirement.',
    '    WSTG, OWASP Top 10 / API Security Top 10, and CWE describe the testing method,\n    risk taxonomy, and weakness taxonomy. They never satisfy an admission evidence\n    group or independent-source requirement.',
)
replace_once(
    "app/analysis_standards.py",
    '    data = deepcopy(raw) if raw else {"principle": "", "wstg": [], "cwe": []}',
    '    data = deepcopy(raw) if raw else {"principle": "", "wstg": [], "owasp": [], "cwe": []}',
)
replace_once(
    "app/analysis_standards.py",
    '        "wstg_reference_version": WSTG_REFERENCE_VERSION,\n        "cwe_reference_version": CWE_REFERENCE_VERSION,',
    '        "wstg_reference_version": WSTG_REFERENCE_VERSION,\n        "owasp_reference_version": OWASP_REFERENCE_VERSION,\n        "cwe_reference_version": CWE_REFERENCE_VERSION,',
)
replace_once(
    "app/analysis_standards.py",
    '        if not entry.get("cwe"):\n            errors.append(f"{family}:missing_cwe")\n        for item in entry.get("cwe", []):',
    '        if not entry.get("owasp"):\n            errors.append(f"{family}:missing_owasp")\n        if not entry.get("cwe"):\n            errors.append(f"{family}:missing_cwe")\n        for item in entry.get("owasp", []):\n            ref_id = str(item.get("id") or "")\n            if not (ref_id.startswith("A") or ref_id.startswith("API")):\n                errors.append(f"{family}:invalid_owasp_id")\n            if item.get("mapping") not in {"direct", "contextual"}:\n                errors.append(f"{family}:invalid_owasp_mapping_mode")\n            if not str(item.get("url") or "").startswith("https://owasp.org/"):\n                errors.append(f"{family}:invalid_owasp_url")\n        for item in entry.get("cwe", []):',
)

# ---------------------------------------------------------------------------
# 2) Analysis knowledge output now exposes OWASP lineage too.
# ---------------------------------------------------------------------------
replace_once(
    "app/hypothesis_admission.py",
    '"source": "OWASP Top 10 / WSTG", "ref": "A03:2021 Injection / WSTG-INPV-05 SQL Injection",',
    '"source": "OWASP Top 10 / WSTG", "ref": "A05:2025 Injection / WSTG-INPV-05 SQL Injection",',
)
replace_once(
    "app/hypothesis_admission.py",
    '    for item in standards.get("cwe", []):\n        refs.append({\n            "source": "MITRE CWE",',
    '    for item in standards.get("owasp", []):\n        refs.append({\n            "source": str(item.get("source") or "OWASP"),\n            "ref": f"{item.get(\'id\')} / {item.get(\'title\')}",\n            "url": str(item.get("url") or ""),\n            "principle": str(standards.get("principle") or ""),\n        })\n    for item in standards.get("cwe", []):\n        refs.append({\n            "source": "MITRE CWE",',
)

# ---------------------------------------------------------------------------
# 3) Physical detector spec makes OWASP mandatory and traceable.
# ---------------------------------------------------------------------------
replace_once(
    "app/family_detectors/base.py",
    'DETECTOR_ENGINE_VERSION = "1.0.0"\nDETECTOR_RULE_VERSION = "2026.08.10.6.9"',
    'DETECTOR_ENGINE_VERSION = "1.1.0"\nDETECTOR_RULE_VERSION = "2026.08.12.6.19"',
)
replace_once(
    "app/family_detectors/base.py",
    '    wstg_ids: tuple[str, ...]\n    cwe_ids: tuple[str, ...]',
    '    wstg_ids: tuple[str, ...]\n    owasp_ids: tuple[str, ...]\n    cwe_ids: tuple[str, ...]',
)
replace_once(
    "app/family_detectors/base.py",
    '    actual_wstg = tuple(str(x["id"]) for x in standards.get("wstg", []))\n    actual_cwe = tuple(str(x["id"]) for x in standards.get("cwe", []))',
    '    actual_wstg = tuple(str(x["id"]) for x in standards.get("wstg", []))\n    actual_owasp = tuple(str(x["id"]) for x in standards.get("owasp", []))\n    actual_cwe = tuple(str(x["id"]) for x in standards.get("cwe", []))',
)
replace_once(
    "app/family_detectors/base.py",
    '    if actual_cwe != expected_cwe:\n        raise RuntimeError(f"{family}: detector/CWE drift expected={expected_cwe} actual={actual_cwe}")',
    '    if not actual_owasp:\n        raise RuntimeError(f"{family}: detector/OWASP grounding is required")\n    if actual_cwe != expected_cwe:\n        raise RuntimeError(f"{family}: detector/CWE drift expected={expected_cwe} actual={actual_cwe}")',
)
replace_once(
    "app/family_detectors/base.py",
    '        wstg_ids=actual_wstg,\n        cwe_ids=actual_cwe,',
    '        wstg_ids=actual_wstg,\n        owasp_ids=actual_owasp,\n        cwe_ids=actual_cwe,',
)

replace_once(
    "app/family_detectors/registry.py",
    '        if not spec.cwe_ids:\n            errors.append(f"{family}:missing_cwe")',
    '        if not spec.owasp_ids:\n            errors.append(f"{family}:missing_owasp")\n        if not spec.cwe_ids:\n            errors.append(f"{family}:missing_cwe")',
)
replace_once(
    "app/family_detectors/registry.py",
    '        *[f"wstg:{ref}" for ref in spec.wstg_ids],\n        *[f"cwe:{ref}" for ref in spec.cwe_ids],',
    '        *[f"wstg:{ref}" for ref in spec.wstg_ids],\n        *[f"owasp:{ref}" for ref in spec.owasp_ids],\n        *[f"cwe:{ref}" for ref in spec.cwe_ids],\n        *[f"writeup:{ref.ref}" for ref in spec.writeups],',
)
replace_once(
    "app/family_detectors/registry.py",
    '    WSTG, CWE and write-up material defines detector criteria and confounders only.',
    '    WSTG, OWASP, CWE and write-up material define detector criteria and confounders only.',
)
replace_once(
    "app/family_detectors/registry.py",
    '        "wstg_ids": list(spec.wstg_ids),\n        "cwe_ids": list(spec.cwe_ids),',
    '        "wstg_ids": list(spec.wstg_ids),\n        "owasp_ids": list(spec.owasp_ids),\n        "cwe_ids": list(spec.cwe_ids),',
)
replace_once(
    "app/family_detectors/registry.py",
    '{"ref": ref.ref, "url": ref.url, "relation": ref.relation, "source": ref.source, "counts_as_target_evidence": False}',
    '{"ref": ref.ref, "url": ref.url, "relation": ref.relation, "source": ref.source, "lesson": ref.lesson, "counts_as_target_evidence": False}',
)

# PostMessage gets a more mapping-friendly CWE and an exact postMessage write-up.
(ROOT / "app" / "family_detectors" / "postmessage_trust.py").write_text(
    'from .base import make_spec, writeup\n'
    'SPEC = make_spec(family="postmessage_trust", strategy="cross_window_message_trust", '
    'surface_terms=("postmessage","message event","onmessage","event.origin","event.source"), '
    'surface_fields=("origin","message","data"), '
    'confounders=("dom_xss","cors_misconfiguration","authentication_session"), '
    'expected_wstg=("WSTG-CLNT-11",), expected_cwe=("CWE-940","CWE-346"), '
    'writeups=(\n'
    '    writeup("CVE-2019-10779 / GCHQ Stroom postMessage origin validation",'
    '"https://securitylab.github.com/research/gchq-stroom-xss/","exact",'
    '"A real web-messaging issue requires an attacker-controlled postMessage to reach a sensitive action when sender origin/source validation is insufficient."),\n'
    '    writeup("GHSL-2024-027/028 / codeium-chrome external-message trust",'
    '"https://securitylab.github.com/advisories/GHSL-2024-027_GHSL-2024-028_codeium-chrome/","adjacent_primary_case",'
    '"External-message handlers must bind sensitive behavior to a validated sender instead of trusting arbitrary external callers."),\n'
    '))\n',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# 4) Physical client-side raw collector: metadata only.
# ---------------------------------------------------------------------------
client_collector = '''from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

CLIENT_SIDE_COLLECTOR_VERSION = "1.0.0"
CLIENT_SIDE_COLLECTOR_RULE_VERSION = "2026.08.12.6.19"
CLIENT_SIDE_FAMILIES = (
    "dom_xss",
    "postmessage_trust",
    "open_redirect",
)

CLIENT_SIDE_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "dom_xss": RawFamilyObservation(
        family="dom_xss",
        variant="source_to_dom_sink",
        base=18,
        missing=(
            "Runtime reachability of the source-to-sink flow",
            "Effective sanitization or encoding before the sink",
            "Target-specific evidence that user-controlled data reaches executable/HTML interpretation",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-dom-source-sink",
            "admission-dom-runtime-condition",
        ),
        summary=(
            "Stored client artifacts expose a browser-controlled source and dangerous DOM/JavaScript sink; "
            "promotion requires runtime/reachability or missing-sanitizer evidence under the DOM XSS detector."
        ),
    ),
    "postmessage_trust": RawFamilyObservation(
        family="postmessage_trust",
        variant="message_to_sensitive_sink",
        base=17,
        missing=(
            "Strict sender-origin validation",
            "Source-window/channel binding",
            "Message schema validation before the sensitive action",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-message-handler",
            "admission-message-origin-source-schema",
        ),
        summary=(
            "Stored client artifacts expose a cross-window/external message handler near sensitive behavior; "
            "promotion requires target evidence that origin, source, or message-schema enforcement is missing."
        ),
    ),
    "open_redirect": RawFamilyObservation(
        family="open_redirect",
        variant="unvalidated_destination",
        base=20,
        missing=(
            "Final navigation destination after application handling",
            "Same-origin or destination allow-list enforcement",
            "Whether an unintended external destination is accepted",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-redirect-parameter",
            "candidate-navigation-context",
            "admission-external-destination",
        ),
        summary=(
            "Stored navigation evidence exposes a user-controlled destination and navigation sink; "
            "promotion requires evidence that an unintended external destination is actually accepted."
        ),
    ),
}


def validate_client_side_collectors() -> list[str]:
    errors: list[str] = []
    if set(CLIENT_SIDE_OBSERVATIONS) != set(CLIENT_SIDE_FAMILIES):
        errors.append("client-side collector profile coverage drift")
    for family in CLIENT_SIDE_FAMILIES:
        observation = CLIENT_SIDE_OBSERVATIONS.get(family)
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not spec.wstg_ids:
            errors.append(f"client detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"client detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"client detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"client detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"client detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_client_side_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_client_side_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.19 client-side collector registry: " + "; ".join(errors))
    return [
        CLIENT_SIDE_OBSERVATIONS[family]
        for family in CLIENT_SIDE_FAMILIES
        if CLIENT_SIDE_OBSERVATIONS[family].packet_present(execution_map)
    ]
'''
(ROOT / "app" / "raw_family_collectors" / "client_side.py").write_text(client_collector, encoding="utf-8")

insert_before_once(
    "app/raw_family_collectors/__init__.py",
    "from raw_family_collectors.file_remote_resource import (",
    '''from raw_family_collectors.client_side import (
    CLIENT_SIDE_COLLECTOR_RULE_VERSION,
    CLIENT_SIDE_COLLECTOR_VERSION,
    CLIENT_SIDE_FAMILIES,
    CLIENT_SIDE_OBSERVATIONS,
    collect_client_side_observations,
    validate_client_side_collectors,
)
''',
)
replace_once(
    "app/raw_family_collectors/__init__.py",
    '    "RawFamilyObservation",\n    "AUTHORIZATION_COLLECTOR_VERSION",',
    '    "RawFamilyObservation",\n    "CLIENT_SIDE_COLLECTOR_VERSION",\n    "CLIENT_SIDE_COLLECTOR_RULE_VERSION",\n    "CLIENT_SIDE_FAMILIES",\n    "CLIENT_SIDE_OBSERVATIONS",\n    "collect_client_side_observations",\n    "validate_client_side_collectors",\n    "AUTHORIZATION_COLLECTOR_VERSION",',
)

# ---------------------------------------------------------------------------
# 5) Orchestrator cutover: client collector owns alert emission metadata.
# ---------------------------------------------------------------------------
replace_once(
    "app/bug_candidates.py",
    'from raw_family_collectors import collect_authorization_observations, collect_file_remote_resource_observations, collect_injection_observations',
    'from raw_family_collectors import collect_authorization_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations',
)
insert_before_once(
    "app/bug_candidates.py",
    "    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n",
    '''    # Analysis 6.19 — physical raw collector ownership for client-side families.
    # WSTG/OWASP/CWE/write-ups define detector criteria only; all target evidence
    # still comes from passive execution/reconstruction and passes admission.
    for observation in collect_client_side_observations(execution_map):
        emit(
            observation.family,
            observation.variant,
            observation.base,
            [],
            [],
            list(observation.missing),
            list(observation.rules),
            observation.summary,
            direct=observation.direct,
            impact=observation.impact,
        )

''',
)

bug_path = ROOT / "app" / "bug_candidates.py"
bug_text = bug_path.read_text(encoding="utf-8")
start_marker = "    # Redirect\n"
end_marker = "    # Shared remote-destination surface metadata is retained for API10 correlation.\n"
if bug_text.count(start_marker) != 1 or bug_text.count(end_marker) != 1:
    raise RuntimeError("bug_candidates.py: cannot identify legacy redirect block")
start = bug_text.index(start_marker)
end = bug_text.index(end_marker)
replacement = (
    "    # Analysis 6.19: legacy Open Redirect alert emission was physically removed.\n"
    "    # raw_family_collectors.client_side owns emission metadata; detector execution\n"
    "    # owns redirect input/sink/external-destination target evidence.\n\n"
)
bug_path.write_text(bug_text[:start] + replacement + bug_text[end:], encoding="utf-8")

# ---------------------------------------------------------------------------
# 6) Regression contracts.
# ---------------------------------------------------------------------------
replace_once(
    "tests/test_analysis_standards_v630.py",
    'from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION, standards_for_family, validate_family_standards',
    'from analysis_standards import FAMILY_STANDARDS, OWASP_REFERENCE_VERSION, STANDARDS_ENGINE_VERSION, standards_for_family, validate_family_standards',
)
replace_once(
    "tests/test_analysis_standards_v630.py",
    '    def test_every_admission_family_has_wstg_and_cwe_grounding(self):\n        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.2.0")',
    '    def test_every_admission_family_has_wstg_owasp_and_cwe_grounding(self):\n        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")\n        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")',
)
replace_once(
    "tests/test_analysis_standards_v630.py",
    '            self.assertTrue(profile["wstg"], family)\n            self.assertTrue(profile["cwe"], family)\n            self.assertTrue(all(item["id"].startswith("WSTG-") for item in profile["wstg"]), family)\n            self.assertTrue(all(item["id"].startswith("CWE-") for item in profile["cwe"]), family)',
    '            self.assertTrue(profile["wstg"], family)\n            self.assertTrue(profile["owasp"], family)\n            self.assertTrue(profile["cwe"], family)\n            self.assertTrue(all(item["id"].startswith("WSTG-") for item in profile["wstg"]), family)\n            self.assertTrue(all(item["id"].startswith(("A", "API")) for item in profile["owasp"]), family)\n            self.assertTrue(all(item["id"].startswith("CWE-") for item in profile["cwe"]), family)',
)
replace_once(
    "tests/test_analysis_standards_v630.py",
    '                    {"type": "wstg_reference", "source": "OWASP WSTG", "source_group": "knowledge"},\n                    {"type": "cwe_reference", "source": "MITRE CWE", "source_group": "knowledge"},',
    '                    {"type": "wstg_reference", "source": "OWASP WSTG", "source_group": "knowledge"},\n                    {"type": "owasp_reference", "source": "OWASP Top 10", "source_group": "knowledge"},\n                    {"type": "cwe_reference", "source": "MITRE CWE", "source_group": "knowledge"},',
)
replace_once(
    "tests/test_analysis_standards_v630.py",
    '    def test_knowledge_references_include_wstg_and_cwe_for_every_family(self):',
    '    def test_knowledge_references_include_wstg_owasp_and_cwe_for_every_family(self):',
)
replace_once(
    "tests/test_analysis_standards_v630.py",
    '            self.assertIn("OWASP WSTG", sources, family)\n            self.assertIn("MITRE CWE", sources, family)',
    '            self.assertIn("OWASP WSTG", sources, family)\n            self.assertTrue({"OWASP Top 10", "OWASP API Security Top 10"} & sources, family)\n            self.assertIn("MITRE CWE", sources, family)',
)

replace_once(
    "tests/test_physical_family_detectors_v690.py",
    '    def test_wstg_and_cwe_are_exactly_bound_to_canonical_standards(self):',
    '    def test_wstg_owasp_and_cwe_are_exactly_bound_to_canonical_standards(self):',
)
replace_once(
    "tests/test_physical_family_detectors_v690.py",
    '            self.assertEqual(spec.wstg_ids, tuple(x["id"] for x in standards["wstg"]))\n            self.assertEqual(spec.cwe_ids, tuple(x["id"] for x in standards["cwe"]))\n            self.assertTrue(spec.wstg_ids)\n            self.assertTrue(spec.cwe_ids)',
    '            self.assertEqual(spec.wstg_ids, tuple(x["id"] for x in standards["wstg"]))\n            self.assertEqual(spec.owasp_ids, tuple(x["id"] for x in standards["owasp"]))\n            self.assertEqual(spec.cwe_ids, tuple(x["id"] for x in standards["cwe"]))\n            self.assertTrue(spec.wstg_ids)\n            self.assertTrue(spec.owasp_ids)\n            self.assertTrue(spec.cwe_ids)',
)
replace_once(
    "tests/test_physical_family_detectors_v690.py",
    '        self.assertNotIn("CWE-918", serialized_support)',
    '        self.assertNotIn("CWE-918", serialized_support)\n        self.assertNotIn("A01:2025", serialized_support)',
)
replace_once(
    "tests/test_physical_family_detectors_v690.py",
    '        self.assertIn("wstg:WSTG-APIT-02", rules)\n        self.assertIn("cwe:CWE-639", rules)',
    '        self.assertIn("wstg:WSTG-APIT-02", rules)\n        self.assertIn("owasp:API1:2023", rules)\n        self.assertIn("owasp:A01:2025", rules)\n        self.assertIn("cwe:CWE-639", rules)\n        self.assertTrue(any(rule.startswith("writeup:") for rule in rules))',
)
replace_once(
    "tests/test_physical_family_detectors_v690.py",
    '        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.0.0")\n        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.2.0")',
    '        self.assertEqual(DETECTOR_ENGINE_VERSION, "1.1.0")\n        self.assertEqual(STANDARDS_ENGINE_VERSION, "1.3.0")',
)

client_test = '''from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import AppPaths, Database, utc_now
from family_detectors import evaluate_family_detector, execute_detector_intelligence, get_detector_spec
from hypothesis_admission import assess_admission
from raw_family_collectors import (
    AUTHORIZATION_FAMILIES,
    CLIENT_SIDE_COLLECTOR_RULE_VERSION,
    CLIENT_SIDE_COLLECTOR_VERSION,
    CLIENT_SIDE_FAMILIES,
    CLIENT_SIDE_OBSERVATIONS,
    FILE_REMOTE_FAMILIES,
    INJECTION_FAMILIES,
    collect_client_side_observations,
    validate_client_side_collectors,
)


class PhysicalRawCollectorClientSide6190Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        scoped = evaluate_family_detector(family, packet.get("support") or [], packet.get("contradict") or [], channel="analysis_619_test")
        return execution, assess_admission(family, scoped["support"], scoped["contradict"])

    def test_registry_owns_exactly_client_side_batch(self):
        self.assertEqual(set(CLIENT_SIDE_FAMILIES), {"dom_xss", "postmessage_trust", "open_redirect"})
        self.assertEqual(set(CLIENT_SIDE_OBSERVATIONS), set(CLIENT_SIDE_FAMILIES))
        self.assertEqual(validate_client_side_collectors(), [])
        self.assertEqual(CLIENT_SIDE_COLLECTOR_VERSION, "1.0.0")
        self.assertEqual(CLIENT_SIDE_COLLECTOR_RULE_VERSION, "2026.08.12.6.19")
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(INJECTION_FAMILIES)))
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(AUTHORIZATION_FAMILIES)))
        self.assertTrue(set(CLIENT_SIDE_FAMILIES).isdisjoint(set(FILE_REMOTE_FAMILIES)))

    def test_client_specs_have_exact_standards_and_real_writeup_grounding(self):
        expected = {
            "dom_xss": ({"WSTG-CLNT-01"}, {"A05:2025"}, {"CWE-79"}),
            "postmessage_trust": ({"WSTG-CLNT-11"}, {"A07:2025"}, {"CWE-940", "CWE-346"}),
            "open_redirect": ({"WSTG-CLNT-04"}, {"A01:2025"}, {"CWE-601"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_all_three_families(self):
        fixtures = {
            "dom_xss": dict(
                target="fixture.invalid", endpoint="/app.js", method="GET",
                endpoint_schema={},
                details={"source_code": "const x=location.hash; node.innerHTML=x;", "runtime_reachable_flow": True, "status_code": 200},
                category="javascript", business_context="general",
            ),
            "postmessage_trust": dict(
                target="fixture.invalid", endpoint="/frame.js", method="GET",
                endpoint_schema={},
                details={"source_code": "window.addEventListener('message', e => { location.href = e.data; });", "missing_origin_check": True, "status_code": 200},
                category="javascript", business_context="general",
            ),
            "open_redirect": dict(
                target="fixture.invalid", endpoint="/login?redirect=/home", method="GET",
                endpoint_schema={"query_parameters": ["redirect"]},
                details={"status_code": 302, "response_headers": {"Location": "https://external.invalid/landing"}},
                category="navigation", business_context="general",
            ),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_client_side_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(CLIENT_SIDE_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "dom_xss": dict(target="fixture.invalid", endpoint="/app.js", method="GET", endpoint_schema={}, details={"source_code": "const x=location.hash; node.innerHTML=x;"}, category="javascript", business_context="general"),
            "postmessage_trust": dict(target="fixture.invalid", endpoint="/frame.js", method="GET", endpoint_schema={}, details={"source_code": "window.addEventListener('message', e => { location.href=e.data; });"}, category="javascript", business_context="general"),
            "open_redirect": dict(target="fixture.invalid", endpoint="/login?redirect=/home", method="GET", endpoint_schema={"query_parameters": ["redirect"]}, details={"status_code": 302, "response_headers": {"Location": "/home"}}, category="navigation", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_external_knowledge_cannot_become_target_evidence(self):
        execution = execute_detector_intelligence(
            target="fixture.invalid", endpoint="/app.js", method="GET", endpoint_schema={}, details={}, category="javascript",
            evidence_for=[
                {"type": "runtime_reachable_flow", "source": "OWASP WSTG", "url": "https://owasp.org/"},
                {"type": "runtime_reachable_flow", "source": "stored_behavior", "source_group": "runtime_behavior"},
            ],
        )
        rows = execution.get("dom_xss", {}).get("support", [])
        self.assertTrue(any(row.get("source") == "stored_behavior" for row in rows))
        self.assertFalse(any("owasp" in str(row.get("source") or "").lower() for row in rows))

    def test_collector_is_metadata_only(self):
        for family, observation in CLIENT_SIDE_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_redirect_emission(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_client_side_observations(execution_map)", source)
        self.assertIn("Analysis 6.19: legacy Open Redirect alert emission was physically removed", source)
        self.assertNotIn('emit("open_redirect", "unvalidated_destination"', source)

    def test_run_analysis_routes_all_three_through_client_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-619-client"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.18.0", "success", now, now, target))
                alerts = [
                    ("DOM flow", "/app.js", {"method": "GET", "source_code": "const x=location.hash; node.innerHTML=x;", "runtime_reachable_flow": True, "status_code": 200, "category": "javascript"}),
                    ("Message trust", "/frame.js", {"method": "GET", "source_code": "window.addEventListener('message', e => { location.href=e.data; });", "missing_origin_check": True, "status_code": 200, "category": "javascript"}),
                    ("External redirect", "/login?redirect=/home", {"method": "GET", "query_parameters": ["redirect"], "status_code": 302, "response_headers": {"Location": "https://external.invalid/landing"}, "category": "navigation"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"619:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        routed[family] = row
                self.assertEqual(set(routed), set(CLIENT_SIDE_FAMILIES), hypotheses)
                for family, expected in CLIENT_SIDE_OBSERVATIONS.items():
                    self.assertEqual(str(routed[family]["bug_variant"]), expected.variant)
                    self.assertEqual(str(routed[family]["state"]), "promoted")
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted = {}
                for row in candidates:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        promoted[family] = row
                self.assertEqual(set(promoted), set(CLIENT_SIDE_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_physical_raw_collector_client_side_v6190.py").write_text(client_test, encoding="utf-8")

standards_test = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, FAMILY_OWASP_MAPPINGS, OWASP_REFERENCE_VERSION, validate_family_standards
from family_detectors.registry import DETECTOR_SPECS, detector_rule_ids
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, knowledge_for_family


class Analysis619StandardsGroundingTests(unittest.TestCase):
    def test_all_31_families_have_four_layer_knowledge_grounding(self):
        families = set(FAMILY_ADMISSION_POLICIES)
        self.assertEqual(families, set(FAMILY_STANDARDS))
        self.assertEqual(families, set(FAMILY_OWASP_MAPPINGS))
        self.assertEqual(families, set(DETECTOR_SPECS))
        self.assertEqual(len(families), 31)
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(OWASP_REFERENCE_VERSION, "Top10:2025+API-Security:2023")
        for family in families:
            standards = FAMILY_STANDARDS[family]; spec = DETECTOR_SPECS[family]
            self.assertTrue(standards["wstg"], family)
            self.assertTrue(standards["owasp"], family)
            self.assertTrue(standards["cwe"], family)
            self.assertTrue(spec.writeups, family)
            self.assertEqual(spec.owasp_ids, tuple(item["id"] for item in standards["owasp"]), family)
            rules = detector_rule_ids(family)
            self.assertTrue(any(rule.startswith("wstg:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("owasp:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("cwe:") for rule in rules), family)
            self.assertTrue(any(rule.startswith("writeup:") for rule in rules), family)

    def test_knowledge_output_contains_owasp_without_turning_it_into_evidence(self):
        for family in FAMILY_ADMISSION_POLICIES:
            refs = knowledge_for_family(family)
            self.assertTrue(any(str(item.get("source") or "").startswith("OWASP") for item in refs), family)
            self.assertTrue(any(str(item.get("source") or "") == "MITRE CWE" for item in refs), family)
            spec = DETECTOR_SPECS[family]
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_analysis_619_standards_grounding.py").write_text(standards_test, encoding="utf-8")

doc = '''# Analysis Engine 6.19 — Client-side collectors + four-layer standards grounding

Analysis 6.19 introduces a physical client-side raw collector for DOM XSS, postMessage trust, and Open Redirect, and upgrades the detector knowledge contract for all 31 vulnerability families.

## Mandatory four-layer grounding

Every physical family detector must now have all four layers:

1. **OWASP WSTG** — testing method and condition model.
2. **OWASP Top 10:2025 and/or OWASP API Security Top 10:2023** — risk taxonomy and family context.
3. **MITRE CWE 4.20** — weakness taxonomy and root-cause mapping.
4. **Real security write-up(s)** — concrete primary cases used to sharpen the family pattern, confounders, and decisive evidence boundary.

The detector registry refuses incomplete grounding. Detector rule lineage now carries `wstg:*`, `owasp:*`, `cwe:*`, and `writeup:*` metadata.

## Evidence firewall

External knowledge is never target evidence. OWASP, WSTG, CWE, write-up, advisory, or knowledge-source material cannot satisfy an admission group, cannot count as an independent target source, and cannot override a target contradiction. Only stored target artifacts produced by passive execution/reconstruction may do that.

## Client-side batch

- `dom_xss`: WSTG-CLNT-01 + OWASP A05:2025 + CWE-79 + GHSL-2023-205 go2rtc DOM XSS.
- `postmessage_trust`: WSTG-CLNT-11 + OWASP A07:2025 + CWE-940/CWE-346 + GCHQ Stroom postMessage origin-validation case and GHSL-2024-027/028 external-message case.
- `open_redirect`: WSTG-CLNT-04 + OWASP A01:2025 + CWE-601 + GHSL-2020-085 Sourcegraph Open Redirect.

The collector owns emission metadata only. `family_detectors.execution`, reconstruction, the physical detector, family evidence scoping, hidden-hypothesis ledger, admission, independent-source guard, and candidate insertion retain their existing responsibilities.

## Scientific boundary

This phase is an architecture and regression claim. It does not claim universal vulnerability detection accuracy and does not consume a new fresh holdout. Existing Golden/raw corpora remain regression assets only.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_19_CLIENT_SIDE_STANDARDS_GROUNDING.md").write_text(doc, encoding="utf-8")

# ---------------------------------------------------------------------------
# 7) Manifest refresh.
# ---------------------------------------------------------------------------
manifest = ROOT / "MANIFEST.sha256"
paths: list[str] = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip() or "  " not in raw:
        continue
    _, relative = raw.split("  ", 1)
    relative = relative.strip()
    if relative and (ROOT / relative).is_file():
        paths.append(relative)
for relative in (
    "app/raw_family_collectors/client_side.py",
    "docs/ANALYSIS_ENGINE_6_19_CLIENT_SIDE_STANDARDS_GROUNDING.md",
    "tests/test_analysis_619_standards_grounding.py",
    "tests/test_physical_raw_collector_client_side_v6190.py",
):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")
