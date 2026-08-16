from pathlib import Path

path = Path('.github/scripts/final_taxonomy_attribution_migration.py')
text = path.read_text(encoding='utf-8')

old_anchor = "'    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,\\n}\\n\\n\\ndef _build_detection_specs()',"
new_anchor = "'    SECRET_EXPOSURE_STANDARD_SPEC.family: SECRET_EXPOSURE_STANDARD_SPEC,\\n}\\n\\n\\ndef _build_detection_specs()',"
if old_anchor not in text:
    raise RuntimeError('taxonomy migration registry closing anchor not found')
text = text.replace(old_anchor, new_anchor, 1)

old_replacement = "'''    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,\\n}\\n\\nFAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {"
new_replacement = "'''    SECRET_EXPOSURE_STANDARD_SPEC.family: SECRET_EXPOSURE_STANDARD_SPEC,\\n}\\n\\nFAMILY_STANDARD_SPECS: dict[str, FamilyStandardSpec] = {"
if old_replacement not in text:
    raise RuntimeError('taxonomy migration registry replacement block not found')
text = text.replace(old_replacement, new_replacement, 1)

version_patch = '''# Update the public admission version contract because the assessment output\n# now includes structured post-admission taxonomy attribution metadata.\nreplace_once(\n    'tests/test_bola_intelligence_v850.py',\n    '        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.0.0")\\n',\n    '        self.assertEqual(ADMISSION_ENGINE_VERSION, "2.1.0")\\n',\n)\n\n\n'''
manifest_marker = '# Refresh strict manifest, preserving existing listed files and adding only\n'
if manifest_marker not in text:
    raise RuntimeError('taxonomy migration manifest marker not found')
text = text.replace(manifest_marker, version_patch + manifest_marker, 1)

path.write_text(text, encoding='utf-8')
