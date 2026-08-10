from __future__ import annotations

import copy
import unittest

from analysis_postfreeze import DEFAULT_MANIFEST, load_manifest
from analysis_postfreeze_seal import prepare_sealed_manifest
from analysis_postfreeze_sources import load_source_registry


class AnalysisPostFreezeSeal660Tests(unittest.TestCase):
    def _materialized_manifest(self) -> dict:
        manifest = copy.deepcopy(load_manifest(DEFAULT_MANIFEST))
        manifest["evaluation_status"] = "corpus_materialized"
        manifest["corpus"]["sealed"] = False
        manifest["corpus"]["sha256"] = None
        manifest["corpus"]["source_roots"] = [row["source_root"] for row in load_source_registry()]
        return manifest

    def test_prepare_seal_sets_hash_and_sealed_state_only(self) -> None:
        manifest = self._materialized_manifest()
        roots = list(manifest["corpus"]["source_roots"])
        digest = "a" * 64
        result = prepare_sealed_manifest(manifest, corpus_sha256=digest, source_roots=roots)
        self.assertEqual(result["evaluation_status"], "sealed_postfreeze")
        self.assertTrue(result["corpus"]["sealed"])
        self.assertEqual(result["corpus"]["sha256"], digest)
        self.assertEqual(result["corpus"]["source_roots"], roots)
        self.assertEqual(result["frozen_head_sha"], manifest["frozen_head_sha"])
        self.assertEqual(result["acceptance_gates"], manifest["acceptance_gates"])

    def test_prepare_seal_rejects_wrong_state(self) -> None:
        manifest = self._materialized_manifest()
        manifest["evaluation_status"] = "collection_open"
        with self.assertRaisesRegex(RuntimeError, "materialized"):
            prepare_sealed_manifest(
                manifest,
                corpus_sha256="b" * 64,
                source_roots=list(manifest["corpus"]["source_roots"]),
            )

    def test_prepare_seal_rejects_root_order_change(self) -> None:
        manifest = self._materialized_manifest()
        roots = list(reversed(manifest["corpus"]["source_roots"]))
        with self.assertRaisesRegex(RuntimeError, "source-root order"):
            prepare_sealed_manifest(manifest, corpus_sha256="c" * 64, source_roots=roots)

    def test_prepare_seal_rejects_already_sealed_manifest(self) -> None:
        manifest = self._materialized_manifest()
        manifest["corpus"]["sealed"] = True
        with self.assertRaisesRegex(RuntimeError, "already sealed"):
            prepare_sealed_manifest(
                manifest,
                corpus_sha256="d" * 64,
                source_roots=list(manifest["corpus"]["source_roots"]),
            )


if __name__ == "__main__":
    unittest.main()
