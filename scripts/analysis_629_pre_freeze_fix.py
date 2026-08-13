from pathlib import Path

path = Path('app/raw_recon_v5_prepare.py')
text = path.read_text(encoding='utf-8')
old = '"trace_id": f"v5-{family[:8]}-{kind}",'
new = '"trace_id": f"v5-{family[:8]}",'
count = text.count(old)
if count != 1:
    raise SystemExit(f'expected exactly one variant-dependent v5 trace id, found {count}')
path.write_text(text.replace(old, new), encoding='utf-8')
print('v5 fixture noise is now variant-invariant')
