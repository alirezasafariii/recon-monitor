from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
module = ROOT / "app" / "raw_recon_v4_exact_source_supplement.py"
test = ROOT / "tests" / "test_raw_recon_v4_exact_source_supplement_v6260.py"

text = module.read_text(encoding="utf-8")
old = '''    "source_map_exposure": {
        "source_root": "GHSA-r28c-9q8g-f849",
        "source_project": "postcss/postcss",
        "fetch_url": "https://api.github.com/advisories/GHSA-r28c-9q8g-f849",
        "canonical_advisory_url": "https://github.com/postcss/postcss/security/advisories/GHSA-r28c-9q8g-f849",
        "expected_cwes": {"CWE-22"},
        "required_groups": (
            ("source map", "sourcemap", "sourcemappingurl"),
            ("arbitrary .map file disclosure", "disclosure of the contents of arbitrary `.map` files", "reads that `.map` file"),
            ("sourcescontent", "result.map", "returned to the caller", "attacker retrieves the emitted map"),
        ),
    },
'''
new = '''    "source_map_exposure": {
        "source_root": "GHSA-rg65-45m7-hq57",
        "source_project": "esm-dev/esm.sh",
        "fetch_url": "https://api.github.com/advisories/GHSA-rg65-45m7-hq57",
        "canonical_advisory_url": "https://github.com/esm-dev/esm.sh/security/advisories/GHSA-rg65-45m7-hq57",
        "expected_cwes": {"CWE-22"},
        "required_groups": (
            ("source map", "sourcemap", ".mjs.map"),
            ("sourcescontent",),
            ("server file contents in source map response", "read sensitive files from the server"),
            ("curl", ".mjs.map"),
        ),
    },
'''
if old not in text:
    raise SystemExit("source-map exact-source marker missing")
module.write_text(text.replace(old, new, 1), encoding="utf-8")

text = test.read_text(encoding="utf-8")
text = text.replace('"GHSA-r28c-9q8g-f849"', '"GHSA-rg65-45m7-hq57"', 1)
text = text.replace('"postcss/postcss"', '"esm-dev/esm.sh"', 1)
test.write_text(text, encoding="utf-8")
