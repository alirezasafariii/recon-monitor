from pathlib import Path

path = Path('app/raw_recon_v5_prepare.py')
text = path.read_text(encoding='utf-8')
old = '''    if BUSINESS_SUPPLEMENT.exists():\n        protected_files["benchmarks/raw/sources/v5_business_logic_supplement.json"] = _sha(\n            BUSINESS_SUPPLEMENT\n        )\n'''
new = '''    if EXACT_SUPPLEMENT.exists():\n        protected_files["benchmarks/raw/sources/v5_exact_source_supplement.json"] = _sha(\n            EXACT_SUPPLEMENT\n        )\n'''
if text.count(old) != 1:
    raise SystemExit(f'expected one obsolete business supplement freeze block, found {text.count(old)}')
path.write_text(text.replace(old, new), encoding='utf-8')
print('obsolete business supplement freeze block replaced by exact supplement protection')
