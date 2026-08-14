from __future__ import annotations

import base64, sys, unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]; APP=ROOT/'app'
if str(APP) not in sys.path: sys.path.insert(0,str(APP))
import real_world_corpus_v1_upstream_controls as controls

class UpstreamControlTests(unittest.TestCase):
    def test_identifier_classification(self):
        self.assertEqual(controls.classify('test_valid_url'), 'near_miss_candidate')
        self.assertEqual(controls.classify('test_rejects_unsafe_input'), 'secure_control_candidate')
        self.assertEqual(controls.classify('test_ssrf_bypass'), 'positive_regression_candidate')
        self.assertEqual(controls.classify('test_feature'), 'unclassified')

    def test_extract_common_test_identifiers(self):
        src='def test_valid_url(): pass\ntest("reject unsafe", () => {})\nfunc TestNormalCase(t *testing.T) {}\n'
        ids=controls.identifiers(src)
        self.assertIn('test_valid_url', ids); self.assertIn('reject unsafe', ids); self.assertIn('TestNormalCase', ids)

    @patch.object(controls,'api_json')
    def test_blob_content_is_transient(self,mock_api):
        raw=b'def test_valid_url(): pass\n'
        mock_api.return_value={'encoding':'base64','content':base64.b64encode(raw).decode()}
        text,sha=controls.blob_text('owner/project','blob', '')
        self.assertIn('test_valid_url',text); self.assertEqual(len(sha),64)

    @patch.object(controls,'blob_text')
    def test_pair_mining_persists_only_identifiers_and_hashes(self,mock_blob):
        mock_blob.return_value=('def test_valid_url(): pass\ndef test_reject_bad(): pass\n','a'*64)
        pair={'source_root':'GHSA-0000-aaaa-bbbb','source_project':'owner/project','family_target':'ssrf','revision_pair_sha256':'r','file_pairs':[{'filename':'tests/test_ssrf.py','fix_blob_sha':'blob1'}]}
        result=controls.mine_pair(pair,'')
        self.assertEqual(result['test_file_count'],1); self.assertEqual(result['near_miss_candidate_count'],1); self.assertEqual(result['secure_control_candidate_count'],1)
        self.assertFalse(result['source_contents_persisted']); self.assertFalse(result['third_party_code_executed']); self.assertFalse(result['human_verified'])
        self.assertNotIn('source', result['test_files'][0])

if __name__=='__main__': unittest.main()
