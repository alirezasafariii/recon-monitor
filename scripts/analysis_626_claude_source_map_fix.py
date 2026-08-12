from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
module = ROOT / "app" / "raw_recon_v4_exact_source_supplement.py"
test = ROOT / "tests" / "test_raw_recon_v4_exact_source_supplement_v6260.py"

text = module.read_text(encoding="utf-8")
old = '''    "source_map_exposure": {\n        "source_root": "GHSA-r28c-9q8g-f849",\n        "source_project": "postcss/postcss",\n        "fetch_url": "https://api.github.com/advisories/GHSA-r28c-9q8g-f849",\n        "canonical_advisory_url": "https://github.com/postcss/postcss/security/advisories/GHSA-r28c-9q8g-f849",\n        "expected_cwes": {"CWE-22"},\n        "required_groups": (\n            ("source map", "sourcemap", "sourcemappingurl"),\n            ("arbitrary .map file disclosure", "disclosure of the contents of arbitrary `.map` files", "reads that `.map` file"),\n            ("sourcescontent", "result.map", "returned to the caller", "attacker retrieves the emitted map"),\n        ),\n    },\n'''
new = '''    "source_map_exposure": {\n        "source_root": "CLAUDE-CODE-2.1.88-SOURCEMAP",\n        "source_project": "anthropics/claude-code",\n        "fetch_url": "https://api.github.com/repos/anthropics/claude-code/issues/41666",\n        "canonical_advisory_url": "https://github.com/anthropics/claude-code/issues/41666",\n        "expected_cwes": set(),\n        "required_groups": (\n            ("source code leak",),\n            ("59.8mb source map", "59.8mb source map included in the package"),\n            ("v2.1.88", "2.1.88"),\n            ("yanked", "yanked release", "later yanked by anthropic"),\n        ),\n    },\n'''
if old not in text:
    raise SystemExit("PostCSS source-map spec marker missing")
text = text.replace(old, new, 1)

old_fetch = '''        payload = json.loads(body.decode("utf-8"))\n        if not isinstance(payload, Mapping):\n            raise RuntimeError(f"unexpected JSON primary-source payload from {url}")\n        return dict(payload)\n'''
new_fetch = '''        payload = json.loads(body.decode("utf-8"))\n        if not isinstance(payload, Mapping):\n            raise RuntimeError(f"unexpected JSON primary-source payload from {url}")\n        normalized = dict(payload)\n        # Official repository issues use title/body rather than summary/description.\n        # Normalize those fields without changing the fetched primary-source text.\n        if not normalized.get("summary") and normalized.get("title"):\n            normalized["summary"] = str(normalized.get("title") or "")\n        if not normalized.get("description") and normalized.get("body"):\n            normalized["description"] = str(normalized.get("body") or "")\n        return normalized\n'''
if old_fetch not in text:
    raise SystemExit("exact source JSON fetch marker missing")
text = text.replace(old_fetch, new_fetch, 1)
module.write_text(text, encoding="utf-8")

text = test.read_text(encoding="utf-8")
text = text.replace(
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_root"], "GHSA-r28c-9q8g-f849")',
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_root"], "CLAUDE-CODE-2.1.88-SOURCEMAP")',
    1,
)
text = text.replace(
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_project"], "postcss/postcss")',
    'self.assertEqual(EXACT_SOURCE_SPECS["source_map_exposure"]["source_project"], "anthropics/claude-code")',
    1,
)
test.write_text(text, encoding="utf-8")
