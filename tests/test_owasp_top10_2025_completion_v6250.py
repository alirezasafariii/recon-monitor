from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, validate_family_standards
from family_detectors import get_detector_spec, validate_detector_registry, execute_detector_intelligence
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission
from raw_family_collectors import (
    OWASP_TOP10_2025_COLLECTOR_RULE_VERSION,
    OWASP_TOP10_2025_FAMILIES,
    collect_owasp_top10_2025_observations,
    validate_owasp_top10_2025_collectors,
)


NEW_FAMILIES = {
    "software_supply_chain_failure",
    "cryptographic_failure",
    "software_data_integrity_failure",
    "security_logging_alerting_failure",
    "exceptional_condition_mishandling",
}


class OwaspTop102025Completion6250Tests(unittest.TestCase):
    def test_exact_family_count_and_new_family_ownership(self) -> None:
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 36)
        self.assertEqual(set(OWASP_TOP10_2025_FAMILIES), NEW_FAMILIES)
        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(validate_owasp_top10_2025_collectors(), [])
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])

    def test_owasp_top10_2025_is_exactly_ten_of_ten(self) -> None:
        top10 = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("A") and str(ref.get("id") or "").endswith(":2025")
        }
        self.assertEqual(top10, {f"A{i:02d}:2025" for i in range(1, 11)})
        api = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("API") and str(ref.get("id") or "").endswith(":2023")
        }
        self.assertEqual(api, {f"API{i}:2023" for i in range(1, 11)})

    def test_new_families_keep_four_layer_grounding_and_non_evidence_writeups(self) -> None:
        expected = {
            "software_supply_chain_failure": ({"WSTG-CONF-01", "WSTG-CONF-02"}, {"A03:2025"}, {"CWE-1104", "CWE-1357", "CWE-1395"}),
            "cryptographic_failure": ({"WSTG-CRYP-01"}, {"A04:2025"}, {"CWE-319", "CWE-327", "CWE-338", "CWE-757"}),
            "software_data_integrity_failure": ({"WSTG-CONF-02"}, {"A08:2025"}, {"CWE-345", "CWE-494", "CWE-502", "CWE-829"}),
            "security_logging_alerting_failure": ({"WSTG-CONF-02", "WSTG-ERRH-01"}, {"A09:2025"}, {"CWE-117", "CWE-532", "CWE-778"}),
            "exceptional_condition_mishandling": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A10:2025"}, {"CWE-248", "CWE-636", "CWE-703", "CWE-755"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_collector_is_metadata_only(self) -> None:
        execution = {family: {"support": [{"type": "surface"}], "contradict": []} for family in NEW_FAMILIES}
        observations = collect_owasp_top10_2025_observations(execution)
        self.assertEqual({row.family for row in observations}, NEW_FAMILIES)
        for row in observations:
            self.assertFalse(hasattr(row, "support"))
            self.assertFalse(hasattr(row, "evidence"))

    def test_supply_chain_surface_without_condition_stays_hidden(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/assets/app.js",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"source_code": "package-lock.json dependencies component version registry"},
        )
        packet = packets["software_supply_chain_failure"]
        assessment = assess_admission("software_supply_chain_failure", packet["support"], packet["contradict"])
        self.assertFalse(assessment["admitted"])
        self.assertTrue({"component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "component_fingerprint"} & {x.get("type") for x in packet["support"]})

    def test_crypto_cleartext_sensitive_transport_can_admit_from_real_stored_context(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="http://example.test/login",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["password"], "path_parameters": [], "object_identifiers": [], "authentication_hints": ["session"]},
            details={"status_code": 200},
        )
        packet = packets["cryptographic_failure"]
        types = {x.get("type") for x in packet["support"]}
        self.assertIn("plaintext_sensitive_transport", types)
        self.assertTrue(assess_admission("cryptographic_failure", packet["support"], packet["contradict"])["admitted"])

    def test_unsafe_deserialization_requires_a_real_input_relation(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/import",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["payload"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"source_code": "ObjectInputStream in = new ObjectInputStream(req.getInputStream()); Object x = in.readObject();"},
        )
        packet = packets["software_data_integrity_failure"]
        self.assertIn("unsafe_deserialization_observed", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("software_data_integrity_failure", packet["support"], packet["contradict"])["admitted"])

    def test_logging_failure_is_not_inferred_from_login_without_log_artifacts(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/login",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["username", "password"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 401, "response_body": "invalid credentials"},
        )
        self.assertNotIn("security_logging_alerting_failure", packets)

    def test_sensitive_log_content_is_real_logging_condition(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/admin/audit",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": ["session"]},
            details={"audit_log": "login success authorization: bearer eyJREDACTEDTOKEN"},
        )
        packet = packets["security_logging_alerting_failure"]
        self.assertIn("sensitive_data_logged", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("security_logging_alerting_failure", packet["support"], packet["contradict"])["admitted"])

    def test_unhandled_server_exception_can_admit_but_plain_error_text_cannot(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/process",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["input"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 500, "response_body": "Uncaught exception: NullPointerException"},
        )
        packet = packets["exceptional_condition_mishandling"]
        self.assertIn("unhandled_exception_observed", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("exceptional_condition_mishandling", packet["support"], packet["contradict"])["admitted"])
        near = execute_detector_intelligence(
            target="example.test", endpoint="/api/process", method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["input"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 400, "response_body": "validation error"},
        )
        if "exceptional_condition_mishandling" in near:
            n = near["exceptional_condition_mishandling"]
            self.assertFalse(assess_admission("exceptional_condition_mishandling", n["support"], n["contradict"])["admitted"])

    def test_external_owasp_condition_never_counts_as_target_evidence(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test", endpoint="/", method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={},
            evidence_for=[{"type": "known_vulnerable_component_observed", "source": "OWASP", "source_group": "wstg", "text": "external taxonomy only"}],
        )
        self.assertNotIn("software_supply_chain_failure", packets)


if __name__ == "__main__":
    unittest.main()
