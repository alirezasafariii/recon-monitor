from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_specs.knowledge_projection import family_knowledge_projection, taxonomy_projection, validate_knowledge_projection
from family_specs.registry import MIGRATED_FAMILIES, get_detection_spec, validate_family_spec_registry
from hypothesis_admission import assess_admission
from vulnerability_knowledge import BUILTIN_KNOWLEDGE, SPEC_KNOWLEDGE_ERRORS, taxonomy_for_family


class FinalAnalyzersPropertyFilePathCorsSpecTests(unittest.TestCase):
    families = ("mass_assignment", "file_upload", "path_traversal", "cors_misconfiguration")

    def test_registry_and_knowledge_are_drift_free(self):
        self.assertEqual(len(MIGRATED_FAMILIES), 13)
        self.assertEqual(validate_family_spec_registry(), [])
        self.assertFalse(SPEC_KNOWLEDGE_ERRORS)
        for family in self.families:
            spec = get_detection_spec(family)
            self.assertEqual(validate_knowledge_projection(spec), [])
            self.assertEqual(taxonomy_for_family(family), taxonomy_projection(spec))
            self.assertEqual(BUILTIN_KNOWLEDGE[family], family_knowledge_projection(spec))
            self.assertTrue(all(d.get("counts_as_target_evidence") is False for d in BUILTIN_KNOWLEDGE[family]))
            self.assertTrue(all("type" not in d for d in BUILTIN_KNOWLEDGE[family]))

    def test_mass_assignment_requires_target_property_failure(self):
        surface=assess_admission("mass_assignment",[
            {"type":"privileged_property","source_group":"schema"},
            {"type":"write_method","source_group":"operation"}])
        self.assertFalse(surface["admitted"])
        direct=assess_admission("mass_assignment",[
            {"type":"privileged_property","source_group":"schema"},
            {"type":"write_method","source_group":"operation"},
            {"type":"property_authorization_differential","source_group":"controlled"}])
        self.assertTrue(direct["admitted"])

    def test_file_upload_requires_controlled_policy_failure(self):
        surface=assess_admission("file_upload",[
            {"type":"file_input","source_group":"structure"},
            {"type":"upload_operation","source_group":"structure"}])
        self.assertFalse(surface["admitted"])
        direct=assess_admission("file_upload",[
            {"type":"file_input","source_group":"structure"},
            {"type":"upload_operation","source_group":"structure"},
            {"type":"unsafe_file_accepted","source_group":"controlled"}])
        self.assertTrue(direct["admitted"])
        stronger=assess_admission("file_upload",[
            {"type":"file_input","source_group":"structure"},
            {"type":"upload_operation","source_group":"structure"},
            {"type":"content_type_bypass_observed","source_group":"controlled"}])
        self.assertTrue(stronger["admitted"])
        self.assertEqual(direct["confirmation_required"],[["content_type_bypass_observed","executable_upload_observed"]])

    def test_path_traversal_requires_controlled_root_escape(self):
        surface=assess_admission("path_traversal",[
            {"type":"path_parameter","source_group":"structure"},
            {"type":"file_operation","source_group":"structure"}])
        self.assertFalse(surface["admitted"])
        direct=assess_admission("path_traversal",[
            {"type":"path_parameter","source_group":"structure"},
            {"type":"file_operation","source_group":"structure"},
            {"type":"path_escape_observed","source_group":"controlled"}])
        self.assertTrue(direct["admitted"])
        stronger=assess_admission("path_traversal",[
            {"type":"path_parameter","source_group":"structure"},
            {"type":"file_operation","source_group":"structure"},
            {"type":"canonicalization_bypass_observed","source_group":"controlled"}])
        self.assertTrue(stronger["admitted"])

    def test_cors_requires_controlled_unintended_origin(self):
        surface=assess_admission("cors_misconfiguration",[
            {"type":"cors_header","source_group":"policy"},
            {"type":"sensitive_context","source_group":"context"}])
        self.assertFalse(surface["admitted"])
        direct=assess_admission("cors_misconfiguration",[
            {"type":"cors_header","source_group":"policy"},
            {"type":"sensitive_context","source_group":"context"},
            {"type":"untrusted_origin_allowed","source_group":"controlled"}])
        self.assertTrue(direct["admitted"])

    def test_external_knowledge_is_zero_target_evidence(self):
        for family in self.families:
            result=assess_admission(family,[
                {"source":"OWASP","ref":"standard","source_group":"knowledge"},
                {"source":"WSTG","ref":"test","source_group":"knowledge"},
                {"source":"CWE","ref":"weakness","source_group":"knowledge"},
                {"source":"GHSL","ref":"writeup","source_group":"knowledge"}])
            self.assertFalse(result["admitted"])
            self.assertEqual(result["independent_sources"],0)


if __name__ == "__main__":
    unittest.main()
