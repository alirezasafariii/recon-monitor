from pathlib import Path

path = Path('.github/scripts/final_taxonomy_attribution_migration.py')
text = path.read_text(encoding='utf-8')
old = "    SSRF_STANDARD_SPEC.family: SSRF_STANDARD_SPEC,\\n}\\n\\n\\ndef _build_detection_specs()"
new = "    SECRET_EXPOSURE_STANDARD_SPEC.family: SECRET_EXPOSURE_STANDARD_SPEC,\\n}\\n\\n\\ndef _build_detection_specs()"
if old not in text:
    raise RuntimeError('taxonomy migration registry closing anchor not found')
path.write_text(text.replace(old, new, 1), encoding='utf-8')
