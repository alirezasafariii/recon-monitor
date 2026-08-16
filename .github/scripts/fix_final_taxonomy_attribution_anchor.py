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

path.write_text(text, encoding='utf-8')
