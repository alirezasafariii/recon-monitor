from pathlib import Path

path = Path('app/raw_recon_v5_freeze.py')
text = path.read_text(encoding='utf-8')
old = '''    "app/raw_recon_v5_exact_source_supplement.py",\n    "app/raw_recon_v5_nvd_discovery.py",'''
new = '''    "app/raw_recon_v5_exact_source_supplement.py",\n    "app/raw_recon_v5_nvd_discovery.py",\n    "app/raw_recon_v5_nvd_api_discovery.py",'''
count = text.count(old)
if count != 1:
    raise SystemExit(f'expected one v5 NVD freeze block, found {count}')
path.write_text(text.replace(old, new), encoding='utf-8')
print('bounded NVD API discovery added to immutable v5 protected files')
