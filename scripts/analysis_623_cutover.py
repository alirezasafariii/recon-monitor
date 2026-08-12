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


collector = '''from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

EXPOSURE_HEADERS_COLLECTOR_VERSION = "1.0.0"
EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION = "2026.08.12.6.23"
EXPOSURE_HEADERS_FAMILIES = (
    "information_disclosure",
    "cors_misconfiguration",
    "sensitive_caching",
)

EXPOSURE_HEADERS_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "information_disclosure": RawFamilyObservation(
        family="information_disclosure",
        variant="sensitive_metadata",
        base=18,
        missing=(
            "Exact sensitive/debug material exposed by the stored response",
            "Whether the response context is public, unauthorized, or otherwise unintended",
            "Minimum affected data scope and intended disclosure policy",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-sensitive-marker",
            "admission-sensitive-response-exposure",
        ),
        summary=(
            "Stored artifacts contain sensitive/debug disclosure evidence; promotion requires actual response exposure "
            "in a public, unauthorized, or otherwise unintended context."
        ),
        impact=66,
    ),
    "cors_misconfiguration": RawFamilyObservation(
        family="cors_misconfiguration",
        variant="origin_policy",
        base=18,
        missing=(
            "Exact origin allow-list/reflection policy",
            "Credential behavior or authenticated response context",
            "Whether sensitive response data is actually readable cross-origin",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-cors-header",
            "admission-cors-origin-exposure",
        ),
        summary=(
            "Stored CORS artifacts expose an unsafe-origin-policy hypothesis; promotion requires credentials, "
            "an authenticated context, or observed sensitive cross-origin response exposure."
        ),
        impact=64,
    ),
    "sensitive_caching": RawFamilyObservation(
        family="sensitive_caching",
        variant="cache_policy",
        base=20,
        missing=(
            "Whether the response contains sensitive or authenticated data",
            "Browser/shared cache policy including Cache-Control and Vary",
            "Observed cache isolation weakness such as missing no-store, missing auth Vary, or shared/CDN caching",
        ),
        rules=(
            "raw-collector-exposure-headers-v1",
            "candidate-cache-header",
            "admission-sensitive-cache-isolation",
        ),
        summary=(
            "Stored response/cache artifacts expose a cache-isolation hypothesis; promotion requires sensitive or "
            "authenticated content plus a concrete browser/shared-cache isolation weakness."
        ),
        impact=62,
    ),
}


def validate_exposure_headers_collectors() -> list[str]:
    errors: list[str] = []
    if set(EXPOSURE_HEADERS_OBSERVATIONS) != set(EXPOSURE_HEADERS_FAMILIES):
        errors.append("exposure/headers collector profile coverage drift")
    for family in EXPOSURE_HEADERS_FAMILIES:
        observation = EXPOSURE_HEADERS_OBSERVATIONS.get(family)
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
            errors.append(f"exposure detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"exposure detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"exposure detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"exposure detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"exposure detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_exposure_headers_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_exposure_headers_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.23 exposure/headers collector registry: " + "; ".join(errors))
    return [
        EXPOSURE_HEADERS_OBSERVATIONS[family]
        for family in EXPOSURE_HEADERS_FAMILIES
        if EXPOSURE_HEADERS_OBSERVATIONS[family].packet_present(execution_map)
    ]
'''
(ROOT / "app" / "raw_family_collectors" / "exposure_headers.py").write_text(collector, encoding="utf-8")

init_path = ROOT / "app" / "raw_family_collectors" / "__init__.py"
replace_once(
    init_path,
    "from raw_family_collectors.file_remote_resource import (\n",
    '''from raw_family_collectors.exposure_headers import (
    EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION,
    EXPOSURE_HEADERS_COLLECTOR_VERSION,
    EXPOSURE_HEADERS_FAMILIES,
    EXPOSURE_HEADERS_OBSERVATIONS,
    collect_exposure_headers_observations,
    validate_exposure_headers_collectors,
)
from raw_family_collectors.file_remote_resource import (
''',
)
replace_once(
    init_path,
    '    "FILE_REMOTE_COLLECTOR_VERSION",\n',
    '''    "EXPOSURE_HEADERS_COLLECTOR_VERSION",
    "EXPOSURE_HEADERS_COLLECTOR_RULE_VERSION",
    "EXPOSURE_HEADERS_FAMILIES",
    "EXPOSURE_HEADERS_OBSERVATIONS",
    "collect_exposure_headers_observations",
    "validate_exposure_headers_collectors",
    "FILE_REMOTE_COLLECTOR_VERSION",
''',
)

bug_path = ROOT / "app" / "bug_candidates.py"
replace_once(
    bug_path,
    'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
    'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
)
text = bug_path.read_text(encoding="utf-8")
bola_marker = '    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n'
if text.count(bola_marker) != 1:
    raise RuntimeError("6.23 collector insertion marker drift")
loop = '''    # Analysis 6.23 — physical information-disclosure/CORS/cache collector ownership.
    # WSTG/OWASP/CWE/write-ups define detector criteria only; passive stored target
    # evidence remains owned by execution/reconstruction and family admission.
    for observation in collect_exposure_headers_observations(execution_map):
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
text = text.replace(bola_marker, loop + bola_marker, 1)
start = text.find("    # Information exposure / headers\n")
end = text.find("    # Analysis 6.21: Business Logic and Race Condition legacy alert emission was physically removed.\n")
if start < 0 or end < 0 or end <= start:
    raise RuntimeError("6.23 information/headers legacy cutover boundaries not found")
text = text[:start] + '''    # Analysis 6.23: Information Disclosure, CORS, and Sensitive Caching legacy alert emission was physically removed.
    # raw_family_collectors.exposure_headers owns emission metadata; execution/reconstruction
    # remains the sole source of target evidence, blockers, and condition signals.

''' + text[end:]
bug_path.write_text(text, encoding="utf-8")

# Pin sensitive caching to an exact browser-cache advisory instead of a generic adjacent cache case.
cache_detector = ROOT / "app" / "family_detectors" / "sensitive_caching.py"
cache_detector.write_text('''from .base import make_spec, writeup
SPEC = make_spec(
    family="sensitive_caching",
    strategy="shared_cache_isolation",
    surface_terms=("cache-control","public","s-maxage","cdn","vary","authorization","etag","no-store"),
    surface_fields=("cache-control","vary","age","x-cache"),
    confounders=("information_disclosure","security_misconfiguration"),
    expected_wstg=("WSTG-ATHN-06",),
    expected_cwe=("CWE-524","CWE-525"),
    writeups=(
        writeup(
            "CVE-2024-45314 / Flask-AppBuilder browser cache of sensitive login fields",
            "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p",
            "exact",
            "Sensitive/authenticated content is vulnerable only when caching policy permits retention or cross-context reuse; a cache header or route name alone is not sufficient.",
            source="GitHub Repository Security Advisory",
        ),
    ),
)
''', encoding="utf-8")

# Add an explicit browser-cache condition derived from WSTG-ATHN-06/CWE-525.
admission_path = ROOT / "app" / "hypothesis_admission.py"
replace_once(
    admission_path,
    '{"shared_cache_risk", "missing_vary", "cdn_cache", "cache_key_missing_auth_context"},\n        ],\n        "min_independent_sources": 2,\n        "label": "cacheable response + sensitive/authenticated data + shared-cache isolation weakness",',
    '{"shared_cache_risk", "missing_vary", "cdn_cache", "cache_key_missing_auth_context", "browser_cache_no_store_missing"},\n        ],\n        "min_independent_sources": 2,\n        "label": "cacheable response + sensitive/authenticated data + browser/shared-cache isolation weakness",',
)

standards_path = ROOT / "app" / "analysis_standards.py"
replace_once(
    standards_path,
    "_cwe('CWE-525', 'Use of Web Browser Cache Containing Sensitive Information', mapping='contextual', auto_assign=True, when_any=('public_cache',)),",
    "_cwe('CWE-525', 'Use of Web Browser Cache Containing Sensitive Information', mapping='contextual', auto_assign=True, when_any=('public_cache', 'browser_cache_no_store_missing')),")

execution_path = ROOT / "app" / "family_detectors" / "execution.py"
old_cache = '''    cache_control = response_headers.get("cache-control", "").lower(); vary = response_headers.get("vary", "").lower()
    if cache_control and any(token in cache_control for token in ("public", "s-maxage", "max-age")):
        packet = _packet_for(result, "sensitive_caching")
        _add_identity(packet, "sensitive_caching", "cache_header", "http_headers", "Cacheable response directive is present.", "cache_policy", 16)
        sensitive_context = bool(auth_hints) or business_context in {"identity", "customer_data", "payment", "administration"} or any(word in surface_text for word in SENSITIVE_FIELD_WORDS)
        if sensitive_context:
            _add_identity(packet, "sensitive_caching", "sensitive_context", "endpoint_context", "Cacheable response is associated with sensitive/authenticated context.", "cache_context", 16)
            if "authorization" not in vary and "cookie" not in vary: _add(packet, "support", _signal("sensitive_caching", "missing_vary", "http_headers", "Sensitive cacheable response lacks Vary on Authorization/Cookie.", source_group="shared_cache_behavior", weight=24, basis="cache_header_interaction"))
        if _flag(flat, "cdn_cache") or any(header in response_headers for header in ("age", "x-cache", "cf-cache-status")): _add(packet, "support", _signal("sensitive_caching", "cdn_cache", "http_headers", "Stored response contains shared/CDN cache evidence.", source_group="shared_cache_behavior", weight=22, basis="cache_header_interaction"))
'''
new_cache = '''    cache_control = response_headers.get("cache-control", "").lower(); vary = response_headers.get("vary", "").lower()
    cacheable_directive = bool(cache_control and any(token in cache_control for token in ("public", "s-maxage", "max-age")))
    sensitive_body = bool(text_lower and any(word in text_lower for word in SENSITIVE_FIELD_WORDS))
    explicit_sensitive = _flag(flat, "sensitive_context") or _flag(flat, "sensitive_response") or _flag(flat, "response_data")
    authenticated_response = bool(auth_hints)
    sensitive_response = sensitive_body or explicit_sensitive or authenticated_response
    cache_surface = cacheable_directive or (status in SUCCESS_STATUSES and sensitive_response)
    if cache_surface:
        packet = _packet_for(result, "sensitive_caching")
        if cacheable_directive:
            _add_identity(packet, "sensitive_caching", "cache_header", "http_headers", "Cacheable response directive is present.", "cache_policy", 16)
        else:
            _add_identity(packet, "sensitive_caching", "cacheable_response_context", "http_response", "Stored sensitive/authenticated response has no explicit no-store cache prohibition.", "cache_policy", 12)
        if authenticated_response:
            _add_identity(packet, "sensitive_caching", "authenticated_context", "endpoint_schema", "Stored response is tied to an authenticated/session-bearing request context.", "cache_context", 18)
        if sensitive_body or explicit_sensitive:
            _add_identity(packet, "sensitive_caching", "sensitive_context", "raw_response", "Stored response contains sensitive data/context indicators.", "cache_context", 18)
        if sensitive_response and status in SUCCESS_STATUSES and "no-store" not in cache_control:
            _add(packet, "support", _signal("sensitive_caching", "browser_cache_no_store_missing", "http_headers", "Sensitive/authenticated successful response lacks Cache-Control: no-store.", source_group="browser_cache_behavior", weight=26, basis="wstg_athn_06_cache_policy"))
        if sensitive_response and cacheable_directive and "authorization" not in vary and "cookie" not in vary:
            _add(packet, "support", _signal("sensitive_caching", "missing_vary", "http_headers", "Sensitive cacheable response lacks Vary on Authorization/Cookie.", source_group="shared_cache_behavior", weight=24, basis="cache_header_interaction"))
        if _flag(flat, "cdn_cache") or any(header in response_headers for header in ("age", "x-cache", "cf-cache-status")):
            _add(packet, "support", _signal("sensitive_caching", "cdn_cache", "http_headers", "Stored response contains shared/CDN cache evidence.", source_group="shared_cache_behavior", weight=22, basis="cache_header_interaction"))
        if "no-store" in cache_control:
            _add(packet, "contradict", _signal("sensitive_caching", "no_store", "http_headers", "Cache-Control: no-store is present.", source_group="cache_control", weight=-30, basis="cache_control_header"))
        if "private" in cache_control:
            _add(packet, "contradict", _signal("sensitive_caching", "private_cache", "http_headers", "Cache-Control marks the response private.", source_group="cache_control", weight=-22, basis="cache_control_header"))
        if "authorization" in vary or "cookie" in vary:
            _add(packet, "contradict", _signal("sensitive_caching", "vary_authorization", "http_headers", "Vary includes Authorization or Cookie context.", source_group="cache_control", weight=-22, basis="vary_header"))
'''
replace_once(execution_path, old_cache, new_cache)

# Preserve low-cost disclosure hypotheses after removing legacy keyword collection, without promoting them by themselves.
old_info = '''    if text and any(pattern in text_lower for pattern in STACK_TRACE_PATTERNS):
        packet = _packet_for(result, "information_disclosure"); _add_identity(packet, "information_disclosure", "debug_information", "raw_response", "Stored response contains debug/stack-trace material.", "sensitive_material", 18)
        if status in SUCCESS_STATUSES and not auth_hints: _add(packet, "support", _signal("information_disclosure", "public_observation", "http_response", "Debug material was stored from a successful response without an authentication hint.", source_group="exposure_context", weight=22, basis="anonymous_success_context"))
'''
new_info = '''    disclosure_surface_hits = [marker for marker in ("debug", "internal", "stacktrace", "stack_trace", "exception", "apikey", "api_key", "secret", "token") if marker in surface_text]
    if disclosure_surface_hits:
        packet = _packet_for(result, "information_disclosure")
        _add_identity(packet, "information_disclosure", "sensitive_marker", "stored_semantic", "Stored artifacts contain sensitive/debug disclosure terminology; this is a hypothesis surface only.", "sensitive_material", 6)
    if text and any(pattern in text_lower for pattern in STACK_TRACE_PATTERNS):
        packet = _packet_for(result, "information_disclosure"); _add_identity(packet, "information_disclosure", "debug_information", "raw_response", "Stored response contains debug/stack-trace material.", "sensitive_material", 18)
        if status in SUCCESS_STATUSES and not auth_hints: _add(packet, "support", _signal("information_disclosure", "public_observation", "http_response", "Debug material was stored from a successful response without an authentication hint.", source_group="exposure_context", weight=22, basis="anonymous_success_context"))
'''
replace_once(execution_path, old_info, new_info)

# Tighten CORS condition creation: business-context labels alone do not prove authenticated/sensitive cross-origin exposure.
old_cors = '''        if unsafe_origin_policy and acac == "true":
            _add(packet, "support", _signal("cors_misconfiguration", "credentials_allowed", "http_headers", "Unsafe observed origin policy is combined with Access-Control-Allow-Credentials: true.", source_group="cors_credentials", weight=26, basis="unsafe_origin_with_credentials"))
        if unsafe_origin_policy and (auth_hints or business_context in {"identity", "customer_data", "payment", "administration"}):
            _add(packet, "support", _signal("cors_misconfiguration", "authenticated_context", "endpoint_context", "Unsafe observed CORS origin policy is associated with an authenticated or sensitive application context.", source_group="cors_sensitive_context", weight=18, basis="unsafe_origin_with_sensitive_context"))
'''
new_cors = '''        if unsafe_origin_policy and acac == "true":
            _add(packet, "support", _signal("cors_misconfiguration", "credentials_allowed", "http_headers", "Unsafe observed origin policy is combined with Access-Control-Allow-Credentials: true.", source_group="cors_credentials", weight=26, basis="unsafe_origin_with_credentials"))
        if unsafe_origin_policy and auth_hints:
            _add(packet, "support", _signal("cors_misconfiguration", "authenticated_context", "endpoint_schema", "Unsafe observed CORS origin policy is tied to an authenticated/session-bearing request context.", source_group="cors_sensitive_context", weight=18, basis="unsafe_origin_with_authenticated_context"))
'''
replace_once(execution_path, old_cors, new_cors)


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
from raw_family_collectors import EXPOSURE_HEADERS_FAMILIES, EXPOSURE_HEADERS_OBSERVATIONS, collect_exposure_headers_observations, validate_exposure_headers_collectors


class PhysicalRawCollectorExposureHeaders6230Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        extraction = evaluate_family_detector(family, packet.get("support", []), packet.get("contradict", []), channel="alert")
        return execution, assess_admission(family, extraction["support"], extraction["contradict"])

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(EXPOSURE_HEADERS_FAMILIES), {"information_disclosure", "cors_misconfiguration", "sensitive_caching"})
        self.assertEqual(validate_exposure_headers_collectors(), [])
        expected = {
            "information_disclosure": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A01:2025"}, {"CWE-200"}),
            "cors_misconfiguration": ({"WSTG-CLNT-07"}, {"A02:2025"}, {"CWE-942"}),
            "sensitive_caching": ({"WSTG-ATHN-06"}, {"A06:2025"}, {"CWE-524", "CWE-525"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("information_disclosure").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2026-037_Wekan/")
        self.assertEqual(get_detector_spec("cors_misconfiguration").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2024-161_GHSL-2024-162_rembg/")
        cache_ref = get_detector_spec("sensitive_caching").writeups[0]
        self.assertEqual(cache_ref.url, "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p")
        self.assertEqual(cache_ref.relation, "exact")
        self.assertEqual(cache_ref.source, "GitHub Repository Security Advisory")

    def test_positive_execution_contracts_admit_all_three(self):
        fixtures = {
            "information_disclosure": dict(target="fixture.invalid", endpoint="/status", method="GET", endpoint_schema={}, details={"status_code": 200, "response_text": "Traceback: File '/srv/app.py', line 42, internal exception"}, category="debug", business_context="general"),
            "cors_misconfiguration": dict(target="fixture.invalid", endpoint="/api/profile", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"response_headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}, category="api", business_context="identity"),
            "sensitive_caching": dict(target="fixture.invalid", endpoint="/account", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"status_code": 200, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "email=user@example.invalid"}, category="account", business_context="identity"),
        }
        execution_map = {}
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertTrue(assessment["admitted"], (family, assessment, execution.get(family)))
            execution_map[family] = execution[family]
        observations = collect_exposure_headers_observations(execution_map)
        self.assertEqual({item.family for item in observations}, set(EXPOSURE_HEADERS_FAMILIES))

    def test_surface_only_near_misses_stay_hidden(self):
        fixtures = {
            "information_disclosure": dict(target="fixture.invalid", endpoint="/internal/debug", method="GET", endpoint_schema={}, details={}, category="debug", business_context="general"),
            "cors_misconfiguration": dict(target="fixture.invalid", endpoint="/public", method="GET", endpoint_schema={}, details={"response_headers": {"Access-Control-Allow-Origin": "*"}}, category="api", business_context="general"),
            "sensitive_caching": dict(target="fixture.invalid", endpoint="/catalog", method="GET", endpoint_schema={}, details={"status_code": 200, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "public catalog"}, category="api", business_context="general"),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution, family)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_browser_cache_no_store_condition_is_evidence_gated(self):
        vulnerable = dict(target="fixture.invalid", endpoint="/account", method="GET", endpoint_schema={"authentication_hints": ["session"]}, details={"status_code": 200, "response_headers": {"Cache-Control": "max-age=300"}, "response_text": "email=user@example.invalid"}, category="account", business_context="identity")
        execution, assessment = self._assessment("sensitive_caching", vulnerable)
        signals = {str(row.get("type") or "") for row in execution["sensitive_caching"]["support"]}
        self.assertIn("browser_cache_no_store_missing", signals)
        self.assertTrue(assessment["admitted"], (assessment, execution["sensitive_caching"]))
        protected = dict(vulnerable)
        protected["details"] = {"status_code": 200, "response_headers": {"Cache-Control": "private, no-store"}, "response_text": "email=user@example.invalid"}
        execution2, assessment2 = self._assessment("sensitive_caching", protected)
        support2 = {str(row.get("type") or "") for row in execution2["sensitive_caching"]["support"]}
        contradict2 = {str(row.get("type") or "") for row in execution2["sensitive_caching"]["contradict"]}
        self.assertNotIn("browser_cache_no_store_missing", support2)
        self.assertIn("no_store", contradict2)
        self.assertFalse(assessment2["admitted"], (assessment2, execution2["sensitive_caching"]))

    def test_cors_business_label_without_auth_or_credentials_does_not_promote(self):
        raw = dict(target="fixture.invalid", endpoint="/api/profile", method="GET", endpoint_schema={}, details={"response_headers": {"Access-Control-Allow-Origin": "*"}}, category="api", business_context="customer_data")
        execution, assessment = self._assessment("cors_misconfiguration", raw)
        signals = {str(row.get("type") or "") for row in execution["cors_misconfiguration"]["support"]}
        self.assertNotIn("authenticated_context", signals)
        self.assertFalse(assessment["admitted"], (assessment, execution["cors_misconfiguration"]))

    def test_collector_is_metadata_only(self):
        for family, observation in EXPOSURE_HEADERS_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_exposure_header_block(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_exposure_headers_observations(execution_map)", source)
        self.assertIn("Analysis 6.23: Information Disclosure, CORS, and Sensitive Caching legacy alert emission was physically removed", source)
        self.assertNotIn("# Information exposure / headers", source)
        self.assertNotIn('emit("information_disclosure", "sensitive_metadata"', source)
        self.assertNotIn('emit("cors_misconfiguration", "origin_policy"', source)
        self.assertNotIn('emit("sensitive_caching", "cache_policy"', source)

    def test_run_analysis_routes_all_three_through_exposure_headers_collector(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); run_id = "run-623-exposure"; target = "fixture.invalid"
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES(?,?,?,?,?,?,1)", (run_id, "6.22.0", "success", now, now, target))
                alerts = [
                    ("Public stack trace", "/status", {"method": "GET", "status_code": 200, "response_text": "Traceback: File '/srv/app.py', line 42, internal exception"}, "debug"),
                    ("Credentialed CORS", "/api/profile", {"method": "GET", "request_headers": {"Authorization": "Bearer <redacted>"}, "response_headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}}, "api"),
                    ("Sensitive browser cache", "/account", {"method": "GET", "status_code": 200, "request_headers": {"Authorization": "Bearer <redacted>"}, "response_headers": {"Cache-Control": "max-age=600"}, "response_text": "email=user@example.invalid"}, "account"),
                ]
                for title, endpoint, details, category in alerts:
                    db.upsert_alert(target, f"623:{title}", category, "HIGH", 90, title, endpoint, details, run_id)
                result = run_analysis(paths, db, run_id, target)
                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(EXPOSURE_HEADERS_FAMILIES) and "raw-collector-exposure-headers-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(EXPOSURE_HEADERS_FAMILIES), hypotheses)
                for family, expected in EXPOSURE_HEADERS_OBSERVATIONS.items():
                    rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(rows, (family, routed[family]))
                    promoted = [row for row in rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted, (family, [dict(row) for row in rows]))
                    conditions = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(any(
                        {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & conditions
                        for row in promoted
                    ), (family, conditions, [dict(row) for row in promoted]))
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (result["analysis_id"],))
                promoted = {str(row["bug_family"]) for row in candidates if "raw-collector-exposure-headers-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertEqual(promoted, set(EXPOSURE_HEADERS_FAMILIES), candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_physical_raw_collector_exposure_headers_v6230.py").write_text(test, encoding="utf-8")

doc = '''# Analysis Engine 6.23 — Information Disclosure / CORS / Sensitive Caching raw collectors

Analysis 6.23 physically decomposes the final three inline exposure/header families from the alert-orchestrator monolith: `information_disclosure`, `cors_misconfiguration`, and `sensitive_caching`.

All three retain the mandatory four-layer grounding contract: OWASP WSTG testing semantics, OWASP Top 10 risk taxonomy, MITRE CWE weakness taxonomy, and a real vulnerability write-up. None of these knowledge sources count as target evidence.

- Information disclosure: WSTG-ERRH-01/02, OWASP A01:2025, CWE-200, and GHSL-2026-037 Wekan. Sensitive-looking names are hypothesis surfaces only; actual public/unauthorized/unintended response exposure is required.
- CORS: WSTG-CLNT-07, OWASP A02:2025, CWE-942, and GHSL-2024-162 rembg. An unsafe origin pattern is insufficient without credentialed/authenticated or observed sensitive cross-origin exposure.
- Sensitive caching: WSTG-ATHN-06, OWASP A06:2025, CWE-524/CWE-525, and CVE-2024-45314 Flask-AppBuilder. Analysis 6.23 adds an explicit `browser_cache_no_store_missing` condition so the engine models the WSTG/CWE browser-cache weakness directly. Missing `no-store` is not enough by itself; the stored response must be sensitive or authenticated. `no-store`, `private`, and auth-aware `Vary` are retained as blocking controls.

The collector is metadata-only. Target evidence remains owned by passive execution/reconstruction and family admission. No cross-origin requests, cache poisoning, credential use, or active exploitation are introduced.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_23_EXPOSURE_HEADERS_RAW_COLLECTORS.md").write_text(doc, encoding="utf-8")

manifest_path = ROOT / "MANIFEST.sha256"
entries: set[str] = set()
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.add(rel.strip())
entries.update({
    "app/raw_family_collectors/exposure_headers.py",
    "docs/ANALYSIS_ENGINE_6_23_EXPOSURE_HEADERS_RAW_COLLECTORS.md",
    "tests/test_physical_raw_collector_exposure_headers_v6230.py",
})
lines = []
for rel in sorted(entries):
    path = ROOT / rel
    if not path.is_file():
        raise RuntimeError(f"manifest path missing after 6.23 cutover: {rel}")
    lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}")
manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
