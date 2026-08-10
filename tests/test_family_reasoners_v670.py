from __future__ import annotations

import unittest

from analysis_ranking import RANKING_ENGINE_VERSION, rank_families
from family_reasoners import (
    FAMILY_REASONER_PROFILES,
    FAMILY_REASONER_VERSION,
    reason_family,
)
from hypothesis_admission import FAMILY_ADMISSION_POLICIES
from security_family_ranker import production_family_rankings


def ev(kind: str, group: str) -> dict[str, str]:
    return {"type": kind, "source": group, "source_group": group, "text": kind}


class FamilyReasoners670Tests(unittest.TestCase):
    def test_every_admission_family_has_exactly_one_reasoner(self) -> None:
        self.assertEqual(FAMILY_REASONER_VERSION, "1.1.0")
        self.assertEqual(RANKING_ENGINE_VERSION, "2.1.0")
        self.assertEqual(set(FAMILY_REASONER_PROFILES), set(FAMILY_ADMISSION_POLICIES))
        self.assertEqual(len(FAMILY_REASONER_PROFILES), 31)

    def test_irrelevant_evidence_does_not_inflate_scoped_source_ratio(self) -> None:
        support = [
            ev("object_identifier", "object_surface"),
            ev("object_operation", "object_operation"),
            ev("cross_identity_object_access", "authorization_behavior"),
        ]
        sql = reason_family("sql_injection", support, [])
        self.assertEqual(sql["scoped_independent_sources"], 0)
        self.assertGreaterEqual(sql["unscoped_evidence_count"], 3)
        self.assertEqual(sql["family_fit_score"], 0.0)

    def test_sql_and_nosql_do_not_share_generic_injection_identity(self) -> None:
        support = [
            ev("body_parameter", "request"),
            ev("nosql_query_surface", "query_semantic"),
            ev("nosql_operator_accepted", "behavior"),
        ]
        ranked = rank_families(support, [])
        self.assertEqual(ranked[0]["family"], "nosql_injection")
        sql = next(row for row in ranked if row["family"] == "sql_injection")
        self.assertTrue(sql["confounder_evidence"])
        self.assertLess(sql["family_fit_score"], ranked[0]["family_fit_score"])

    def test_ssrf_is_not_open_redirect(self) -> None:
        support = [
            ev("url_parameter", "destination"),
            ev("backend_fetch", "server_behavior"),
        ]
        ranked = rank_families(support, [])
        self.assertEqual(ranked[0]["family"], "ssrf")
        self.assertGreater(
            reason_family("ssrf", support, [])["family_fit_score"],
            reason_family("open_redirect", support, [])["family_fit_score"],
        )

    def test_file_upload_and_path_traversal_require_different_conditions(self) -> None:
        upload_support = [
            ev("file_input", "upload_input"),
            ev("upload_operation", "upload_operation"),
            ev("dangerous_type_accepted", "upload_behavior"),
        ]
        self.assertEqual(rank_families(upload_support, [])[0]["family"], "file_upload")

        path_support = [
            ev("filename_field", "path_input"),
            ev("upload_operation", "file_operation"),
            ev("base_directory_escape", "filesystem_behavior"),
        ]
        self.assertEqual(rank_families(path_support, [])[0]["family"], "path_traversal")

    def test_secret_exposure_is_not_generic_information_disclosure(self) -> None:
        support = [
            ev("secret_pattern", "secret_surface"),
            ev("production_javascript", "client_runtime"),
            ev("credential_context", "secret_validation"),
        ]
        ranked = rank_families(support, [])
        self.assertEqual(ranked[0]["family"], "secret_exposure")
        generic = reason_family("information_disclosure", support, [])
        secret = reason_family("secret_exposure", support, [])
        self.assertLess(generic["family_fit_score"], secret["family_fit_score"])
        self.assertTrue(generic["confounder_evidence"])

    def test_race_condition_is_not_generic_business_logic(self) -> None:
        support = [
            ev("state_change", "operation"),
            ev("single_use_operation", "semantics"),
            ev("duplicate_effect_observed", "concurrency_behavior"),
        ]
        ranked = rank_families(support, [])
        self.assertEqual(ranked[0]["family"], "race_condition")
        business = reason_family("business_logic", support, [])
        self.assertTrue(business["confounder_evidence"])

    def test_security_control_blocks_condition_without_erasing_family_identity(self) -> None:
        support = [
            ev("privileged_function", "function_surface"),
            ev("state_change", "role_context"),
        ]
        contradict = [ev("lower_privilege_denied", "authorization_control")]
        row = reason_family("broken_function_authorization", support, contradict)
        self.assertGreater(row["family_fit_score"], 0.0)
        self.assertEqual(row["condition_confidence"], 0.04)
        self.assertEqual(row["control_evidence"], ["lower_privilege_denied"])

    def test_production_adapter_uses_same_family_reasoners(self) -> None:
        support = [
            ev("input_parameter", "input"),
            ev("command_execution_surface", "process_surface"),
            ev("command_output_observed", "process_behavior"),
        ]
        rows = production_family_rankings(support, [])
        self.assertEqual(rows[0]["family"], "command_injection")
        self.assertEqual(rows[0]["reason"]["family_reasoner_version"], FAMILY_REASONER_VERSION)
        self.assertIn("primary_question", rows[0]["reason"])
        self.assertIn("scoped_independent_sources", rows[0]["reason"])


if __name__ == "__main__":
    unittest.main()
