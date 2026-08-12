from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1) Physical API/configuration raw collector registry.
# ---------------------------------------------------------------------------
collector = '''from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

API_CONFIGURATION_COLLECTOR_VERSION = "1.0.0"
API_CONFIGURATION_COLLECTOR_RULE_VERSION = "2026.08.12.6.20"
API_CONFIGURATION_FAMILIES = (
    "unrestricted_resource_consumption",
    "sensitive_business_flow_abuse",
    "security_misconfiguration",
    "improper_inventory_management",
    "unsafe_api_consumption",
)

API_CONFIGURATION_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "unrestricted_resource_consumption": RawFamilyObservation(
        family="unrestricted_resource_consumption",
        variant="missing_resource_limit",
        base=16,
        missing=(
            "Maximum page/batch/payload size",
            "Per-client operation rate",
            "Execution timeout and provider spending limit",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-resource-surface",
            "admission-resource-limit-failure",
        ),
        summary=(
            "Stored API artifacts expose a resource-amplifying control or costly operation; "
            "promotion requires observed missing or ineffective size, rate, timeout, or cost limits."
        ),
    ),
    "sensitive_business_flow_abuse": RawFamilyObservation(
        family="sensitive_business_flow_abuse",
        variant="automation_abuse_boundary",
        base=15,
        missing=(
            "Per-user/business frequency limits",
            "Anti-automation controls",
            "Scarce-inventory or reservation abuse controls",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-sensitive-business-flow",
            "admission-business-flow-limit",
        ),
        summary=(
            "Stored API artifacts expose an abuse-sensitive business flow; promotion requires "
            "target evidence that automation, frequency, per-user, or inventory controls are absent or bypassable."
        ),
    ),
    "security_misconfiguration": RawFamilyObservation(
        family="security_misconfiguration",
        variant="deployment_hardening",
        base=17,
        missing=(
            "Expected hardening baseline",
            "Production transport/method policy",
            "Whether debug/default functionality is intentionally exposed",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-misconfiguration-surface",
            "admission-direct-misconfiguration",
        ),
        summary=(
            "Stored deployment/application-stack artifacts expose a configuration-sensitive surface; "
            "promotion requires directly observed insecure configuration behavior."
        ),
    ),
    "improper_inventory_management": RawFamilyObservation(
        family="improper_inventory_management",
        variant="legacy_or_nonproduction_exposure",
        base=14,
        missing=(
            "Current API inventory and retirement plan",
            "Control parity with current production API",
            "Whether non-production hosts use production data",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-api-inventory-surface",
            "admission-inventory-drift",
        ),
        summary=(
            "Stored API artifacts expose versioned, legacy, or non-production inventory; promotion requires "
            "observed active stale/undocumented exposure with security relevance."
        ),
    ),
    "unsafe_api_consumption": RawFamilyObservation(
        family="unsafe_api_consumption",
        variant="upstream_trust_boundary",
        base=17,
        missing=(
            "TLS and authentication to upstream service",
            "Redirect/timeout/response-size controls",
            "Validation and sanitization of third-party response data",
        ),
        rules=(
            "raw-collector-api-configuration-v1",
            "candidate-upstream-integration",
            "admission-unsafe-api-consumption",
        ),
        summary=(
            "Stored API artifacts expose a third-party/upstream trust boundary; promotion requires "
            "observed unsafe transport, redirect, resource, authentication, or downstream-validation behavior."
        ),
    ),
}


def validate_api_configuration_collectors() -> list[str]:
    errors: list[str] = []
    if set(API_CONFIGURATION_OBSERVATIONS) != set(API_CONFIGURATION_FAMILIES):
        errors.append("API/configuration collector profile coverage drift")
    for family in API_CONFIGURATION_FAMILIES:
        observation = API_CONFIGURATION_OBSERVATIONS.get(family)
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
            errors.append(f"API/configuration detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"API/configuration detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"API/configuration detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"API/configuration detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"API/configuration write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_api_configuration_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_api_configuration_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.20 API/configuration collector registry: " + "; ".join(errors))
    return [
        API_CONFIGURATION_OBSERVATIONS[family]
        for family in API_CONFIGURATION_FAMILIES
        if API_CONFIGURATION_OBSERVATIONS[family].packet_present(execution_map)
    ]
'''
(ROOT / "app" / "raw_family_collectors" / "api_configuration.py").write_text(collector, encoding="utf-8")

# ---------------------------------------------------------------------------
# 2) Collector package export.
# ---------------------------------------------------------------------------
init_path = ROOT / "app" / "raw_family_collectors" / "__init__.py"
replace_once(
    init_path,
    "from raw_family_collectors.authorization import (\n",
    '''from raw_family_collectors.api_configuration import (
    API_CONFIGURATION_COLLECTOR_RULE_VERSION,
    API_CONFIGURATION_COLLECTOR_VERSION,
    API_CONFIGURATION_FAMILIES,
    API_CONFIGURATION_OBSERVATIONS,
    collect_api_configuration_observations,
    validate_api_configuration_collectors,
)
from raw_family_collectors.authorization import (
''',
)
replace_once(
    init_path,
    '    "RawFamilyObservation",\n',
    '''    "RawFamilyObservation",
    "API_CONFIGURATION_COLLECTOR_VERSION",
    "API_CONFIGURATION_COLLECTOR_RULE_VERSION",
    "API_CONFIGURATION_FAMILIES",
    "API_CONFIGURATION_OBSERVATIONS",
    "collect_api_configuration_observations",
    "validate_api_configuration_collectors",
''',
)

# ---------------------------------------------------------------------------
# 3) Recall-preserving passive execution surface coverage.
# ---------------------------------------------------------------------------
execution_path = ROOT / "app" / "family_detectors" / "execution.py"
replace_once(
    execution_path,
    'THIRD_PARTY_MARKERS = ("third-party", "third_party", "integration", "upstream", "vendor", "partner api", "external api")\n',
    'THIRD_PARTY_MARKERS = ("third-party", "third_party", "integration", "upstream", "vendor", "partner api", "external api", "webhook")\n',
)
replace_once(
    execution_path,
    'BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "redeem", "claim", "coupon", "promo")\n',
    'BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "invite", "create account", "redeem", "claim", "coupon", "promo", "comment", "post", "message", "review")\n',
)
replace_once(
    execution_path,
    'VERSION_MARKERS = ("legacy", "deprecated", "staging", "stage", "beta", "alpha", "/dev/", "/test/")\n',
    '''VERSION_MARKERS = ("legacy", "deprecated", "staging", "stage", "beta", "alpha", "/dev/", "/test/")
CONFIG_SURFACE_MARKERS = ("debug", "stacktrace", "stack_trace", "traceback", "swagger", "actuator", "phpinfo", "directory listing", "server-status", "options method", "http://")
''',
)
replace_once(
    execution_path,
    '    if all_fields & RESOURCE_FIELDS or any(token in surface_text for token in ("batch", "bulk", "export", "report", "generate", "thumbnail", "upload", "download", "sms", "email", "otp")):\n',
    '    if all_fields & RESOURCE_FIELDS or any(token in surface_text for token in ("batch", "bulk", "export", "report", "generate", "pdf", "thumbnail", "upload", "download", "sms", "email", "otp", "biometric")):\n',
)
config_anchor = '''    if endpoint.lower().startswith("http://"):
        packet = _packet_for(result, "security_misconfiguration"); _add_identity(packet, "security_misconfiguration", "transport_surface", "endpoint", "Cleartext HTTP endpoint is present.", "configuration_surface", 14); _add(packet, "support", _signal("security_misconfiguration", "insecure_http_enabled", "endpoint", "Stored target endpoint uses cleartext HTTP.", source_group="configuration_behavior", weight=28, basis="endpoint_scheme"))
'''
config_new = '''    config_hits = [marker for marker in CONFIG_SURFACE_MARKERS if marker in surface_text]
    explicit_misconfig = any(_flag(flat, signal) for signal in EXECUTION_PROFILES["security_misconfiguration"].condition_signals)
    if config_hits or explicit_misconfig:
        packet = _packet_for(result, "security_misconfiguration")
        _add_identity(packet, "security_misconfiguration", "misconfiguration_surface", "raw_configuration", "Stored artifacts expose configuration-sensitive deployment/application behavior.", "configuration_surface", 10)
        if any(token in config_hits for token in ("debug", "stacktrace", "stack_trace", "traceback", "phpinfo")):
            _add_identity(packet, "security_misconfiguration", "debug_surface", "raw_configuration", "Stored artifacts expose a debug/error configuration surface.", "configuration_surface", 10)
        if "http://" in config_hits:
            _add_identity(packet, "security_misconfiguration", "transport_surface", "raw_configuration", "Stored artifacts contain a cleartext HTTP configuration surface.", "configuration_surface", 10)

    if endpoint.lower().startswith("http://"):
        packet = _packet_for(result, "security_misconfiguration"); _add_identity(packet, "security_misconfiguration", "transport_surface", "endpoint", "Cleartext HTTP endpoint is present.", "configuration_surface", 14); _add(packet, "support", _signal("security_misconfiguration", "insecure_http_enabled", "endpoint", "Stored target endpoint uses cleartext HTTP.", source_group="configuration_behavior", weight=28, basis="endpoint_scheme"))
'''
replace_once(execution_path, config_anchor, config_new)
old_inventory = '''    if any(token in surface_text for token in VERSION_MARKERS):
        packet = _packet_for(result, "improper_inventory_management"); _add_identity(packet, "improper_inventory_management", "api_version_surface", "endpoint", "Versioned, legacy, or non-production API surface is present.", "inventory_surface", 16)
        if status in SUCCESS_STATUSES and any(token in endpoint.lower() for token in ("legacy", "deprecated", "old")): _add(packet, "support", _signal("improper_inventory_management", "deprecated_version_still_reachable", "http_response", "Stored legacy/deprecated API endpoint remains reachable.", source_group="inventory_behavior", weight=28, basis="legacy_route_success"))
        if status in SUCCESS_STATUSES and any(token in endpoint.lower() for token in ("staging", "stage", "dev", "test", "beta", "alpha")): _add(packet, "support", _signal("improper_inventory_management", "undocumented_host_observed", "http_response", "Stored non-production/pre-release API surface is reachable.", source_group="inventory_behavior", weight=22, basis="nonproduction_route_success"))
'''
new_inventory = '''    version_hits = re.findall(r"(?:^|[/_.-])(v\\d+(?:\\.\\d+)?|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", surface_text, re.I)
    if version_hits:
        normalized_versions = {str(token).lower() for token in version_hits}
        packet = _packet_for(result, "improper_inventory_management")
        _add_identity(packet, "improper_inventory_management", "api_version_surface", "endpoint", "Versioned, legacy, or non-production API surface is present.", "inventory_surface", 16)
        if normalized_versions & {"legacy", "old", "deprecated"}:
            _add_identity(packet, "improper_inventory_management", "legacy_endpoint_surface", "endpoint", "Legacy/deprecated API inventory semantics are present.", "inventory_surface", 12)
        if normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add_identity(packet, "improper_inventory_management", "nonproduction_surface", "endpoint", "Non-production/pre-release API inventory semantics are present.", "inventory_surface", 12)
        if status in SUCCESS_STATUSES and normalized_versions & {"legacy", "old", "deprecated"}:
            _add(packet, "support", _signal("improper_inventory_management", "deprecated_version_still_reachable", "http_response", "Stored legacy/deprecated API endpoint remains reachable.", source_group="inventory_behavior", weight=28, basis="legacy_route_success"))
        if status in SUCCESS_STATUSES and normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add(packet, "support", _signal("improper_inventory_management", "undocumented_host_observed", "http_response", "Stored non-production/pre-release API surface is reachable.", source_group="inventory_behavior", weight=22, basis="nonproduction_route_success"))
'''
replace_once(execution_path, old_inventory, new_inventory)

# ---------------------------------------------------------------------------
# 4) Orchestrator cutover: collector metadata replaces five inline API blocks.
# ---------------------------------------------------------------------------
bug_path = ROOT / "app" / "bug_candidates.py"
replace_once(
    bug_path,
    'from raw_family_collectors import collect_authorization_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
    'from raw_family_collectors import collect_api_configuration_observations, collect_authorization_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
)
text = bug_path.read_text(encoding="utf-8")
bola_marker = '    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n'
if text.count(bola_marker) != 1:
    raise RuntimeError("BOLA insertion marker drift")
api_loop = '''    # Analysis 6.20 — physical API/configuration collector ownership.
    # WSTG/OWASP/CWE/write-ups define detector criteria only; target evidence
    # remains owned by passive execution/reconstruction and admission.
    for observation in collect_api_configuration_observations(execution_map):
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

'''
text = text.replace(bola_marker, api_loop + bola_marker, 1)
remote_metadata = '''    # Shared remote-destination surface metadata is retained for API10 correlation.
    # Analysis 6.18 removes SSRF emission; detector execution owns SSRF target evidence.
    ssrf_tokens = _contains_any(haystack, ("webhook", "fetchurl", "fetch_url", "imageurl", "image_url", "importurl", "import_url", "previewurl", "proxyurl", "callbackurl", "destinationurl", "remoteurl"))
    generic_url_fields = [field for field in query_fields + body_fields if field.lower() in {"url", "uri", "endpoint", "destination", "callback", "webhook"}]

'''
if text.count(remote_metadata) != 1:
    raise RuntimeError("shared remote metadata block drift")
text = text.replace(remote_metadata, "", 1)
start = text.find("    # API4:2023 — resource consumption.\n")
end = text.find("    # Information exposure / headers\n")
if start < 0 or end < 0 or end <= start:
    raise RuntimeError("API4/API10 legacy cutover boundaries not found")
replacement = '''    # Analysis 6.20: API4/API6/API8/API9/API10 legacy alert emission was physically removed.
    # raw_family_collectors.api_configuration owns emission metadata; detector execution and
    # raw-condition reconstruction remain the sole source of target evidence and controls.

'''
text = text[:start] + replacement + text[end:]
bug_path.write_text(text, encoding="utf-8")

# ---------------------------------------------------------------------------
# 5) Tighten two write-up URLs that previously pointed at generic advisory pages.
# ---------------------------------------------------------------------------
resource_spec = ROOT / "app" / "family_detectors" / "unrestricted_resource_consumption.py"
replace_once(
    resource_spec,
    '"https://securitylab.github.com/advisories/","exact_pattern"',
    '"https://securitylab.github.com/advisories/GHSL-2023-225_GHSL-2023-226_Mealie/","exact_pattern"',
)
flow_spec = ROOT / "app" / "family_detectors" / "sensitive_business_flow_abuse.py"
replace_once(
    flow_spec,
    '"https://securitylab.github.com/advisories/","adjacent_primary_case"',
    '"https://securitylab.github.com/advisories/GHSL-2025-038_github_branch-deploy_action/","adjacent_primary_case"',
)

# ---------------------------------------------------------------------------
# 6) Regression tests.
# ---------------------------------------------------------------------------
test = '''from __future__ import annotations

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
    API_CONFIGURATION_FAMILIES,
    API_CONFIGURATION_OBSERVATIONS,
    collect_api_configuration_observations,
    validate_api_configuration_collectors,
)


class PhysicalRawCollectorApiConfiguration6200Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(API_CONFIGURATION_FAMILIES), {
            "unrestricted_resource_consumption", "sensitive_business_flow_abuse",
            "security_misconfiguration", "improper_inventory_management", "unsafe_api_consumption",
        })
        self.assertEqual(validate_api_configuration_collectors(), [])
        for family in API_CONFIGURATION_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_positive_execution_contracts_admit_all_five(self):
        fixtures = {
            "unrestricted_resource_consumption": dict(target="fixture.invalid", endpoint="/api/report?limit=5000", method="GET", endpoint_schema={"query_parameters": ["limit"]}, details={"rate_limit_absent_observed": True}, category="api", business_context="general"),
            "sensitive_business_flow_abuse": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={"per_user_limit_absent": True}, category="api", business_context="commerce"),
            "security_misconfiguration": dict(target="fixture.invalid", endpoint="/debug", method="GET", endpoint_schema={}, details={"response_body": "Traceback (most recent call last):\\nRuntimeError: boom", "status_code": 500}, category="debug", business_context="general"),
            "improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/legacy/v1/users", method="GET", endpoint_schema={}, details={"status_code": 200}, category="api", business_context="general"),
            "unsafe_api_consumption": dict(target="fixture.invalid", endpoint="/api/integration/webhook", method="POST", endpoint_schema={"body_fields": ["webhook"]}, details={"upstream_timeout_absent": True}, category="integration", business_context="general"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_api_configuration_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(API_CONFIGURATION_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "unrestricted_resource_consumption": dict(target="fixture.invalid", endpoint="/api/report?limit=100", method="GET", endpoint_schema={"query_parameters": ["limit"]}, details={}, category="api", business_context="general"),
            "sensitive_business_flow_abuse": dict(target="fixture.invalid", endpoint="/api/checkout", method="POST", endpoint_schema={}, details={}, category="api", business_context="commerce"),
            "security_misconfiguration": dict(target="fixture.invalid", endpoint="/swagger", method="GET", endpoint_schema={}, details={}, category="api", business_context="general"),
            "improper_inventory_management": dict(target="fixture.invalid", endpoint="/api/v1/users", method="GET", endpoint_schema={}, details={}, category="api", business_context="general"),
            "unsafe_api_consumption": dict(target="fixture.invalid", endpoint="/api/integration/webhook", method="POST", endpoint_schema={"body_fields": ["webhook"]}, details={}, category="integration", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_flag_only_misconfiguration_retains_identity_without_auto_promotion_shortcut(self):
        execution, assessment = self._assessment("security_misconfiguration", dict(
            target="fixture.invalid", endpoint="/health", method="GET", endpoint_schema={},
            details={"debug_mode_exposed": True}, category="api", business_context="general",
        ))
        packet = execution["security_misconfiguration"]
        types = {str(row.get("type") or "") for row in packet["support"]}
        self.assertIn("misconfiguration_surface", types)
        self.assertIn("debug_mode_exposed", types)
        self.assertTrue(assessment["admitted"], assessment)

    def test_collector_is_metadata_only(self):
        for family, observation in API_CONFIGURATION_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_all_five_legacy_blocks(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_api_configuration_observations(execution_map)", source)
        self.assertIn("Analysis 6.20: API4/API6/API8/API9/API10 legacy alert emission was physically removed", source)
        self.assertNotIn("# API4:2023 — resource consumption.", source)
        self.assertNotIn("# API6:2023 — unrestricted access to sensitive business flows.", source)
        self.assertNotIn("# API8:2023 — security misconfiguration.", source)
        self.assertNotIn("# API9:2023 — improper inventory management.", source)
        self.assertNotIn("# API10:2023 — unsafe consumption of third-party APIs.", source)

    def test_run_analysis_routes_all_five_through_api_configuration_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-620-api-config"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.19.0", "success", now, now, target))
                alerts = [
                    ("Resource limit", "/api/report?limit=5000", {"method": "GET", "query_parameters": ["limit"], "rate_limit_absent_observed": True, "category": "api"}),
                    ("Sensitive checkout", "/api/checkout", {"method": "POST", "per_user_limit_absent": True, "category": "api"}),
                    ("Debug exposure", "/debug", {"method": "GET", "response_body": "Traceback (most recent call last):\\nRuntimeError: boom", "status_code": 500, "category": "debug"}),
                    ("Legacy API", "/api/legacy/v1/users", {"method": "GET", "status_code": 200, "category": "api"}),
                    ("Upstream API", "/api/integration/webhook", {"method": "POST", "body_fields": ["webhook"], "upstream_timeout_absent": True, "category": "integration"}),
                ]
                for title, endpoint, details in alerts:
                    db.upsert_alert(target, f"620:{title}", "new_endpoint", "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(API_CONFIGURATION_FAMILIES) and "raw-collector-api-configuration-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(API_CONFIGURATION_FAMILIES), hypotheses)
                for family, expected in API_CONFIGURATION_OBSERVATIONS.items():
                    family_rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(family_rows, (family, routed[family]))
                    promoted = [row for row in family_rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted, (family, [dict(row) for row in family_rows]))
                    conditions = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(any(
                        {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & conditions
                        for row in promoted
                    ), (family, conditions, [dict(row) for row in promoted]))
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted_families = {
                    str(row["bug_family"]) for row in candidates
                    if "raw-collector-api-configuration-v1" in json.loads(row["rule_ids_json"] or "[]")
                }
                self.assertEqual(promoted_families, set(API_CONFIGURATION_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_physical_raw_collector_api_configuration_v6200.py").write_text(test, encoding="utf-8")

# ---------------------------------------------------------------------------
# 7) Documentation.
# ---------------------------------------------------------------------------
doc = '''# Analysis Engine 6.20 — API / Configuration raw collectors

Analysis 6.20 physically decomposes five remaining API/configuration families from the alert-orchestrator monolith:

- `unrestricted_resource_consumption`
- `sensitive_business_flow_abuse`
- `security_misconfiguration`
- `improper_inventory_management`
- `unsafe_api_consumption`

## Four-layer detector grounding

Every family remains subject to the Analysis 6.19 mandatory detector contract:

1. OWASP WSTG testing method.
2. OWASP Top 10:2025 and/or OWASP API Security Top 10:2023 taxonomy.
3. MITRE CWE weakness taxonomy.
4. A real security write-up that sharpens the family condition, confounders, and decisive-evidence boundary.

For this batch the primary taxonomy anchors are API4:2023, API6:2023, API8:2023, API9:2023, and API10:2023, with family-specific WSTG/CWE mappings already enforced by the physical detector registry.

## Write-up lineage

The batch preserves family-specific write-up lessons and tightens direct advisory URLs for the Mealie resource-consumption case and the Branch Deploy Action control-bypass case. The write-up layer remains detector knowledge only.

## Evidence firewall

WSTG, OWASP, CWE, write-ups, advisories, or other knowledge sources never count as target evidence. They cannot satisfy admission groups, independent-source requirements, or override contradictory target controls. Target evidence is produced only by stored passive execution/reconstruction artifacts.

## Recall-preserving cutover

Before removing the five inline blocks, 6.20 expands passive raw-surface reconstruction for patterns previously owned by the monolith:

- API inventory forms such as `v1`, `v2`, `old`, `legacy`, `dev`, `test`, `staging`, `beta`, and `alpha`.
- Upstream `webhook` trust-boundary surfaces.
- Configuration surfaces such as Swagger, Actuator, phpinfo, server-status, OPTIONS, debug/trace semantics, and cleartext HTTP clues.
- Resource surfaces including PDF/biometric/paid-provider-like and expensive operations.
- Sensitive business-flow semantics including posting, messaging, invitation, and account-creation paths.

These remain surface clues only. Promotion still requires each family's decisive condition evidence and independent-source admission requirements.

## Scientific boundary

This phase is an architecture and regression claim. It does not claim universal vulnerability-detection accuracy and does not consume a new fresh holdout. Existing Golden/raw corpora remain regression assets.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_20_API_CONFIGURATION_RAW_COLLECTORS.md").write_text(doc, encoding="utf-8")

# ---------------------------------------------------------------------------
# 8) Manifest refresh.
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
    "app/raw_family_collectors/api_configuration.py",
    "docs/ANALYSIS_ENGINE_6_20_API_CONFIGURATION_RAW_COLLECTORS.md",
    "tests/test_physical_raw_collector_api_configuration_v6200.py",
):
    if relative not in paths:
        paths.append(relative)
entries = []
for relative in sorted(set(paths)):
    digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    entries.append(f"{digest}  {relative}")
manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")
