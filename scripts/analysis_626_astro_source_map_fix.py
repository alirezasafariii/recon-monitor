from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
module = ROOT / "app" / "raw_recon_v4_exact_source_supplement.py"
test = ROOT / "tests" / "test_raw_recon_v4_exact_source_supplement_v6260.py"

text = module.read_text(encoding="utf-8")
old = '''    "source_map_exposure": {\n        "source_root": "GHSA-r28c-9q8g-f849",\n        "source_project": "postcss/postcss",\n        "fetch_url": "https://api.github.com/advisories/GHSA-r28c-9q8g-f849",\n        "canonical_advisory_url": "https://github.com/postcss/postcss/security/advisories/GHSA-r28c-9q8g-f849",\n        "expected_cwes": {"CWE-22"},\n        "required_groups": (\n            ("source map", "sourcemap", "sourcemappingurl"),\n            ("arbitrary .map file disclosure", "disclosure of the contents of arbitrary `.map` files", "reads that `.map` file"),\n            ("sourcescontent", "result.map", "returned to the caller", "attacker retrieves the emitted map"),\n        ),\n    },\n'''
new = '''    "source_map_exposure": {\n        "source_root": "GHSA-49w6-73cw-chjr",\n        "source_project": "withastro/astro",\n        "fetch_url": "https://api.github.com/advisories/GHSA-49w6-73cw-chjr",\n        "canonical_advisory_url": "https://github.com/withastro/astro/security/advisories/GHSA-49w6-73cw-chjr",\n        "expected_cwes": {"CWE-219"},\n        "required_groups": (\n            ("sourcemap", "source map"),\n            ("server source code", "server code"),\n            ("publicly-accessible folder", "public internet", "unauthorized http get", "outside party can read"),\n            ("reconstruct the source code", "read parts of the server source code", ".mjs.map"),\n        ),\n    },\n'''
if old not in text:
    raise SystemExit("PostCSS source-map spec marker missing")
module.write_text(text.replace(old, new, 1), encoding="utf-8")

text = test.read_text(encoding="utf-8")
text = text.replace(
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_root"], "GHSA-r28c-9q8g-f849")',
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_root"], "GHSA-49w6-73cw-chjr")',
    1,
)
text = text.replace(
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_project"], "postcss/postcss")',
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_project"], "withastro/astro")',
    1,
)
test.write_text(text, encoding="utf-8")
