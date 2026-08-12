from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_detectors import evaluate_family_detector, execute_detector_intelligence
from hypothesis_admission import assess_admission
from raw_family_collectors import (
    AUTHORIZATION_COLLECTOR_RULE_VERSION,
    AUTHORIZATION_COLLECTOR_VERSION,
    AUTHORIZATION_FAMILIES,
    AUTHORIZATION_OBSERVATIONS,
    INJECTION_FAMILIES,
    collect_authorization_observations,
    validate_authorization_collectors,
)


class PhysicalRawCollectorAuthorization6170Tests(unittest.TestCase):
    def _assessment(self, family: str, raw: dict):
        execution = execute_detector_intelligence(**raw)
        packet = execution.get(family, {"support": [], "contradict": []})
        scoped = evaluate_family_detector(
            family,
            packet.get("support") or [],
            packet.get("contradict") or [],
            channel="analysis_617_test",
        )
        return execution, assess_admission(family, scoped["support"], scoped["contradict"])

    def test_registry_owns_only_legacy_raw_authorization_blocks(self):
        self.assertEqual(
            set(AUTHORIZATION_FAMILIES),
            {"broken_function_authorization", "mass_assignment"},
        )
        self.assertNotIn("broken_object_authorization", AUTHORIZATION_FAMILIES)
        self.assertNotIn("graphql_authorization", AUTHORIZATION_FAMILIES)
        self.assertEqual(set(AUTHORIZATION_OBSERVATIONS), set(AUTHORIZATION_FAMILIES))
        self.assertEqual(validate_authorization_collectors(), [])
        self.assertEqual(AUTHORIZATION_COLLECTOR_VERSION, "1.0.0")
        self.assertEqual(AUTHORIZATION_COLLECTOR_RULE_VERSION, "2026.08.12.6.17")
        self.assertEqual(
            set(INJECTION_FAMILIES),
            {
                "sql_injection",
                "nosql_injection",
                "command_injection",
                "server_side_template_injection",
                "ldap_injection",
            },
        )

    def test_collectors_emit_only_when_execution_packet_exists(self):
        execution = {
            "broken_function_authorization": {
                "support": [{"type": "privileged_function"}],
                "contradict": [],
            },
            "cors_misconfiguration": {
                "support": [{"type": "wildcard_origin"}],
                "contradict": [],
            },
        }
        observations = collect_authorization_observations(execution)
        self.assertEqual([item.family for item in observations], ["broken_function_authorization"])
        self.assertEqual(observations[0].variant, "role_boundary")
        self.assertIn("raw-collector-authorization-v1", observations[0].rules)

    def test_positive_execution_contracts_admit_both_families(self):
        fixtures = {
            "broken_function_authorization": dict(
                target="fixture.invalid",
                endpoint="/api/admin/users/disable",
                method="POST",
                endpoint_schema={"body_fields": ["user_id"]},
                details={
                    "context_observations": [
                        {
                            "context": "viewer",
                            "role": "viewer",
                            "expected_access": False,
                            "status_code": 200,
                        }
                    ]
                },
                category="admin user management",
                business_context="identity",
            ),
            "mass_assignment": dict(
                target="fixture.invalid",
                endpoint="/api/profile",
                method="PATCH",
                endpoint_schema={"body_fields": ["display_name", "role"]},
                details={"privileged_property_accepted": True, "status_code": 200},
                category="profile update",
                business_context="identity",
            ),
        }
        execution = {}
        for family, raw in fixtures.items():
            packet, assessment = self._assessment(family, raw)
            execution[family] = packet[family]
            self.assertTrue(assessment["admitted"], (family, assessment, packet.get(family)))
        observations = collect_authorization_observations(execution)
        self.assertEqual({item.family for item in observations}, set(AUTHORIZATION_FAMILIES))

    def test_surface_only_near_misses_remain_hypotheses(self):
        fixtures = {
            "broken_function_authorization": dict(
                target="fixture.invalid",
                endpoint="/api/admin/users/disable",
                method="POST",
                endpoint_schema={"body_fields": ["user_id"]},
                details={"status_code": 403},
                category="admin user management",
                business_context="identity",
            ),
            "mass_assignment": dict(
                target="fixture.invalid",
                endpoint="/api/profile",
                method="PATCH",
                endpoint_schema={"body_fields": ["display_name", "role"]},
                details={"status_code": 200},
                category="profile update",
                business_context="identity",
            ),
        }
        for family, raw in fixtures.items():
            execution, assessment = self._assessment(family, raw)
            self.assertIn(family, execution)
            self.assertFalse(assessment["admitted"], (family, assessment, execution.get(family)))

    def test_collector_is_metadata_only(self):
        for family, observation in AUTHORIZATION_OBSERVATIONS.items():
            self.assertEqual(observation.family, family)
            self.assertGreater(observation.base, 0)
            self.assertTrue(observation.missing)
            self.assertTrue(observation.rules)
            self.assertFalse(hasattr(observation, "support"))
            self.assertFalse(hasattr(observation, "contradict"))

    def test_orchestrator_cutover_removes_legacy_authorization_blocks(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_authorization_observations(execution_map)", source)
        self.assertIn("Function Authorization and Mass Assignment legacy collection was physically", source)
        self.assertNotIn("# Function / role authorization", source)
        self.assertNotIn("# Mass assignment / property-level authorization", source)
        self.assertNotIn('emit("broken_function_authorization"', source)
        self.assertNotIn('emit("mass_assignment"', source)


if __name__ == "__main__":
    unittest.main()
