from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from family_reasoning import FAMILY_ORDER, FAMILY_REASONING
from vulnerability_knowledge import (
    BUG_PROFILES,
    BUILTIN_KNOWLEDGE,
    KNOWLEDGE_RULE_VERSION,
    knowledge_context,
    knowledge_for_family,
    taxonomy_for_family,
)


class KnowledgeCoverage31V892Tests(unittest.TestCase):
    def test_every_canonical_family_has_curated_global_knowledge(self):
        missing = [family for family in FAMILY_ORDER if not BUILTIN_KNOWLEDGE.get(family)]
        self.assertEqual(missing, [])
        self.assertEqual(len(FAMILY_ORDER), 74)

    def test_curated_knowledge_is_bounded_and_non_evidentiary_for_every_family(self):
        for family in FAMILY_ORDER:
            refs = knowledge_for_family(family)
            self.assertGreaterEqual(len(refs), 2, family)
            self.assertLessEqual(len(refs), 12, family)
            self.assertEqual(refs[0]["id"], f"profile:{family}")
            context = knowledge_context(family, [], endpoint="/audit")
            self.assertEqual(context["role"], "classification_and_retrieval_only_not_target_evidence")
            self.assertIn("never satisfies admission", context["safety"])

    def test_original_family_taxonomy_audit_reaches_global_profiles(self):
        expected = {
            "mass_assignment": {"wstg": "WSTG-INPV-20", "cwe": "CWE-915"},
            "account_enumeration": {"wstg": "WSTG-IDNT-04", "cwe": "CWE-208"},
            "postmessage_trust": {"wstg": "WSTG-CLNT-11", "cwe": "CWE-346"},
            "open_redirect": {"wstg": "WSTG-CLNT-04", "cwe": "CWE-601"},
            "source_map_exposure": {"wstg": "WSTG-INFO-05", "cwe": "CWE-200"},
            "secret_exposure": {"wstg": "WSTG-INFO-05", "cwe": "CWE-798"},
            "graphql_authorization": {"wstg": "WSTG-APIT-02", "cwe": "CWE-862"},
            "graphql_data_exposure": {"wstg": "WSTG-APIT-03", "cwe": "CWE-200"},
            "business_logic": {"wstg": "WSTG-BUSL-06", "cwe": "CWE-841"},
            "race_condition": {"wstg": "WSTG-BUSL-05", "cwe": "CWE-362"},
            "websocket_authorization": {"wstg": "WSTG-CLNT-10", "cwe": "CWE-862"},
            "cors_misconfiguration": {"wstg": "WSTG-CLNT-07", "cwe": "CWE-942"},
            "sensitive_caching": {"wstg": "WSTG-ATHN-06", "cwe": "CWE-525"},
        }
        for family, values in expected.items():
            taxonomy = taxonomy_for_family(family)
            self.assertIn(values["wstg"], taxonomy.get("wstg", []), family)
            self.assertIn(values["cwe"], taxonomy.get("cwe", []), family)

    def test_representative_real_world_writeups_are_globally_retrievable(self):
        expected_ids = {
            "open_redirect": "ghsl-2025-122-nocodb-open-redirect",
            "secret_exposure": "ghsl-2026-037-wekan-token-leak",
            "websocket_authorization": "ghsl-2026-040-affine-websocket-authorization",
            "race_condition": "portswigger-smashing-state-machine-race",
        }
        for family, doc_id in expected_ids.items():
            ids = {doc["id"] for doc in knowledge_for_family(family)}
            self.assertIn(doc_id, ids)

    def test_every_reasoning_confirmation_and_blocking_signal_is_ranker_visible(self):
        for family in FAMILY_ORDER:
            contract = FAMILY_REASONING[family]
            profile_signals = BUG_PROFILES[family]["signals"]
            strong = set(profile_signals.get("strong", []))
            contradictions = set(profile_signals.get("contradictions", []))

            decisive = set()
            for group in contract.get("confirmation_required", ()):
                if isinstance(group, (list, tuple, set, frozenset)):
                    decisive.update(str(value) for value in group)
                else:
                    decisive.add(str(group))
            decisive.update(str(value) for value in contract.get("override_signals", ()))
            missing_decisive = sorted(value for value in decisive if value and value not in strong)
            missing_contradictions = sorted(
                str(value)
                for value in contract.get("blocking_contradictions", ())
                if str(value) and str(value) not in contradictions
            )
            self.assertEqual(missing_decisive, [], family)
            self.assertEqual(missing_contradictions, [], family)

    def test_rule_version_records_full_family_knowledge_audit(self):
        self.assertEqual(KNOWLEDGE_RULE_VERSION, "2026.08.13.8")


if __name__ == "__main__":
    unittest.main()
