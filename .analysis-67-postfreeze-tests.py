from __future__ import annotations

from pathlib import Path

path = Path("tests/test_analysis_postfreeze_v660.py")
text = path.read_text(encoding="utf-8")

old = '''import copy\nimport unittest\n\nfrom analysis_postfreeze import (\n'''
new = '''import copy\nimport unittest\n\nfrom analysis_ranking import RANKING_ENGINE_VERSION\nfrom analysis_postfreeze import (\n'''
if old not in text:
    raise SystemExit("import anchor missing")
text = text.replace(old, new, 1)

old = '''    def test_protected_files_match_frozen_git_blobs(self) -> None:\n        result = validate_freeze(load_manifest(DEFAULT_MANIFEST))\n        self.assertTrue(result["passed"], result["errors"])\n        self.assertEqual(len(result["checked_files"]), 6)\n\n    def test_protocol_state_matches_seal_state(self) -> None:\n        manifest = load_manifest(DEFAULT_MANIFEST)\n        status = collection_status(DEFAULT_MANIFEST)\n        self.assertTrue(status["freeze_validation"]["passed"])\n        if manifest["corpus"]["sealed"]:\n            self.assertTrue(status["sealed"])\n            self.assertEqual(status["evaluation_status"], "sealed_postfreeze")\n            digest = str(manifest["corpus"]["sha256"] or "")\n            self.assertEqual(len(digest), 64)\n            int(digest, 16)\n        else:\n            self.assertFalse(status["sealed"])\n            self.assertIn(status["evaluation_status"], {"collection_open", "corpus_materialized"})\n            self.assertIsNone(manifest["corpus"]["sha256"])\n'''
new = '''    def test_historical_v4_freeze_detects_current_engine_drift(self) -> None:\n        manifest = load_manifest(DEFAULT_MANIFEST)\n        result = validate_freeze(manifest)\n        frozen_ranking = str(manifest["frozen_engine"]["ranking_engine_version"])\n        if RANKING_ENGINE_VERSION == frozen_ranking:\n            self.assertTrue(result["passed"], result["errors"])\n        else:\n            self.assertFalse(result["passed"])\n            self.assertTrue(\n                any("POST-FREEZE MODEL MUTATION DETECTED" in error for error in result["errors"]),\n                result["errors"],\n            )\n        self.assertEqual(len(result["checked_files"]), 6)\n\n    def test_protocol_state_preserves_seal_while_new_engine_cannot_replay_fresh_v4(self) -> None:\n        manifest = load_manifest(DEFAULT_MANIFEST)\n        status = collection_status(DEFAULT_MANIFEST)\n        frozen_ranking = str(manifest["frozen_engine"]["ranking_engine_version"])\n        if RANKING_ENGINE_VERSION == frozen_ranking:\n            self.assertTrue(status["freeze_validation"]["passed"])\n        else:\n            self.assertFalse(status["freeze_validation"]["passed"])\n            self.assertTrue(\n                any(\n                    "POST-FREEZE MODEL MUTATION DETECTED" in error\n                    for error in status["freeze_validation"]["errors"]\n                )\n            )\n        if manifest["corpus"]["sealed"]:\n            self.assertTrue(status["sealed"])\n            self.assertEqual(status["evaluation_status"], "sealed_postfreeze")\n            digest = str(manifest["corpus"]["sha256"] or "")\n            self.assertEqual(len(digest), 64)\n            int(digest, 16)\n        else:\n            self.assertFalse(status["sealed"])\n            self.assertIn(status["evaluation_status"], {"collection_open", "corpus_materialized"})\n            self.assertIsNone(manifest["corpus"]["sha256"])\n'''
if old not in text:
    raise SystemExit("post-freeze test anchor missing")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
