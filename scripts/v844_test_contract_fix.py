from pathlib import Path

files = [
    Path('tests/test_platform_v60.py'),
    Path('tests/test_product_platform_v50.py'),
    Path('tests/test_safe_validation_v51.py'),
    Path('tests/test_stability_v451.py'),
    Path('tests/test_workspace_v70.py'),
]
changed = []
for path in files:
    text = path.read_text(encoding='utf-8')
    updated = text.replace('8.4.3', '8.4.4').replace('6.0.4', '6.0.5')
    if updated != text:
        path.write_text(updated, encoding='utf-8')
        changed.append(str(path))
if not changed:
    raise SystemExit('no v8.4.4 test contracts were updated')
print('v8.4.4 test contracts:', ', '.join(changed))
