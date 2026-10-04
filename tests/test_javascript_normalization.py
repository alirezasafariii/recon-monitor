from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from core import explain_risk, semantic_js_normalize, sha256_bytes, sha256_text
from analysis_engine import _evidence
from intelligence import build_js_diff
from javascript_normalization import normalize_javascript, normalize_javascript_bytes


class JavaScriptNormalizationTests(unittest.TestCase):
    def assert_change(self, before, after):
        self.assertNotEqual(sha256_text(semantic_js_normalize(before)), sha256_text(semantic_js_normalize(after)))

    def test_protocol_relative_destinations_inside_strings_do_not_disappear(self):
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                self.assert_change(f'const redirect={quote}//first.example/path{quote};',
                                   f'const redirect={quote}//second.example/path{quote};')

    def test_block_comment_markers_inside_strings_are_literal_content(self):
        self.assert_change('const value="before /* first */ after";', 'const value="before /* second */ after";')

    def test_string_spaces_and_punctuation_are_preserved(self):
        for before, after in [('a  b', 'a b'), ('x = y', 'x=y'), ('a : b', 'a:b'), ('a\t b', 'a b')]:
            with self.subTest(before=before):
                self.assert_change(f'const value="{before}";', f'const value="{after}";')

    def test_string_source_map_directive_is_not_removed(self):
        self.assert_change('const value=`//# sourceMappingURL=first.map`;',
                           'const value=`//# sourceMappingURL=second.map`;')

    def test_template_raw_text_and_nested_interpolations_are_preserved(self):
        self.assert_change('const url=`//first.example/${`nested ${value}`}`;',
                           'const url=`//second.example/${`nested ${value}`}`;')

    def test_regex_character_classes_do_not_become_comments(self):
        self.assert_change('const pattern=/[/* first */]+/g;', 'const pattern=/[/* second */]+/g;')

    def test_regex_spaces_are_significant(self):
        self.assert_change('const pattern=/a  b/g;', 'const pattern=/a b/g;')

    def test_escaped_quotes_do_not_end_the_string(self):
        self.assert_change(r'const value="escaped \" //first.example";',
                           r'const value="escaped \" //second.example";')

    def test_automatic_semicolon_insertion_line_break_is_preserved(self):
        self.assert_change('function get(){return\nvalue;}', 'function get(){return value;}')

    def test_line_break_inside_block_comment_is_preserved(self):
        self.assert_change('function get(){return/*\n*/value;}', 'function get(){return/* inline */value;}')

    def test_distinct_operator_tokens_are_not_merged(self):
        self.assert_change('a + +b;', 'a++ + b;')
        self.assert_change('const value=flag ? .1 : .2;', 'const value=flag?.item;')

    def test_build_time_values_are_not_silently_erased(self):
        self.assert_change('const buildTime=1234567890123;', 'const buildTime=1234567890124;')
        self.assert_change('const value="compiledAt: 1234567890123";', 'const value="compiledAt: 1234567890124";')

    def test_comments_and_horizontal_formatting_still_normalize(self):
        before = '// build\nconst value = "https://example.test/a"; //# sourceMappingURL=first.map'
        after = 'const   value="https://example.test/a";\n//# sourceMappingURL=second.map'
        self.assertEqual(semantic_js_normalize(before), semantic_js_normalize(after))

    def test_comments_never_merge_identifier_or_number_tokens(self):
        self.assert_change('const a=typeof/* note */value;', 'const a=typeofvalue;')
        self.assert_change('const a=1/* note */2;', 'const a=12;')

    def test_normalized_diff_keeps_changed_destination_visible(self):
        diff, summary = build_js_diff('const redirect="//first.example/path";', 'const redirect="//second.example/path";')
        self.assertIn('//first.example/path', diff)
        self.assertIn('//second.example/path', diff)
        self.assertTrue(summary['meaningful'])

    def test_diff_preserves_significant_multiline_literal_spaces(self):
        before = 'const value=`first\n  second`;'
        after = 'const value=`first\n second`;'
        diff, summary = build_js_diff(before, after)
        self.assertIn('-  second', diff)
        self.assertIn('+ second', diff)
        self.assertTrue(summary['meaningful'])

    def test_simple_literals_and_operators_use_token_mode(self):
        source = 'const obj={value:0xFF, count:1_000n}; obj.value??=2; const x=obj?.value;'
        result = normalize_javascript(source)
        self.assertEqual(result.mode, 'tokens')
        self.assertEqual(result.fingerprint, sha256_text(semantic_js_normalize(source)))

    def test_parser_dependent_syntax_retains_the_entire_input(self):
        for source, reason in [
            ('// build\nconst pattern=/[/* text */ ]/g; // trailer', 'slash_requires_parser'),
            ('const ratio=a / b; // trailer', 'slash_requires_parser'),
            ('const value=`text ${`nested ${"//value"}`}`; // trailer', 'template_requires_parser'),
            ('const view=<div>/* literal text */</div>;', 'syntax_requires_parser'),
            ('const caf\u00e9="//literal";', 'unsupported_token'),
            ('const value="unterminated //literal', 'unterminated_string'),
            ('const value=1; /* unterminated', 'unterminated_comment'),
        ]:
            with self.subTest(source=source):
                result = normalize_javascript(source)
                self.assertEqual((result.mode, result.reason), ('raw_fallback', reason))
                self.assertEqual(result.text, source)
                self.assertEqual(result.fingerprint, sha256_text(source))

    def test_all_javascript_line_terminators_keep_return_boundary(self):
        for ending in ('\n', '\r', '\r\n', '\u2028', '\u2029'):
            with self.subTest(ending=repr(ending)):
                self.assert_change('function get(){return' + ending + 'value;}', 'function get(){return value;}')
                self.assertEqual(normalize_javascript('function get(){return' + ending + 'value;}').mode, 'tokens')

    def test_escaped_line_continuations_preserve_original_bytes(self):
        for ending in ('\n', '\r\n'):
            with self.subTest(ending=repr(ending)):
                source = 'const value="first\\' + ending + ' //literal";'
                result = normalize_javascript(source)
                self.assertEqual(result.mode, 'tokens')
                self.assertIn('"first\\' + ending + ' //literal"', result.text)

    def test_invalid_utf8_fingerprints_raw_bytes_without_replacement_collision(self):
        before, after = b'const value="\xff";', b'const value="\xfe";'
        first, second = normalize_javascript_bytes(before), normalize_javascript_bytes(after)
        self.assertEqual((first.mode, first.reason), ('raw_fallback', 'invalid_utf8'))
        self.assertEqual(first.text, second.text)
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.fingerprint, sha256_bytes(before))

    def test_unknown_comparison_receives_neither_noise_penalty_nor_semantic_bonus(self):
        details = {'semantic_comparison': 'unknown', 'semantic_changed': None}
        known_score = explain_risk('changed_js', 'https://example.test/app.js', {'semantic_changed': True})[0]
        score, _severity, reasons, _change_class = explain_risk('changed_js', 'https://example.test/app.js', details)
        self.assertEqual(score, known_score)
        self.assertTrue(any('unknown' in reason for reason in reasons))
        evidence_for, evidence_against, adjustment, rules = _evidence({'category': 'changed_js'}, details)
        self.assertEqual(adjustment, 0)
        self.assertNotIn('evidence-semantic-js', rules)
        self.assertNotIn('evidence-raw-only-js', rules)
        self.assertFalse(evidence_against)
        self.assertTrue(any('unknown' in item['text'] and item['weight'] == 0 for item in evidence_for))


if __name__ == "__main__":
    unittest.main()
