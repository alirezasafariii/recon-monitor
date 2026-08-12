from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
module = ROOT / "app" / "raw_recon_v4_exact_source_supplement.py"
test = ROOT / "tests" / "test_raw_recon_v4_exact_source_supplement_v6260.py"

text = module.read_text(encoding="utf-8")
start = text.find('    "improper_inventory_management": {\n')
end = text.find('    "unsafe_api_consumption": {\n', start)
if start < 0 or end < 0:
    raise SystemExit("improper inventory exact-source block marker missing")
text = text[:start] + text[end:]
module.write_text(text, encoding="utf-8")

text = test.read_text(encoding="utf-8")
text = text.replace(
    '            "source_map_exposure",\n            "improper_inventory_management",\n            "unsafe_api_consumption",\n',
    '            "source_map_exposure",\n            "unsafe_api_consumption",\n',
    1,
)
line = '        self.assertEqual(EXACT_SOURCE_SPECS["improper_inventory_management"]["source_root"], "GHSA-x223-p2gf-v735")\n'
if line not in text:
    raise SystemExit("improper inventory exact-source test marker missing")
text = text.replace(line, "", 1)
test.write_text(text, encoding="utf-8")
