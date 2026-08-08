from pathlib import Path

changed = []
for path in sorted(Path('tests').glob('test_*.py')):
    lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
    out = []
    touched = False
    for line in lines:
        if 'schema_version' in line or 'SCHEMA_VERSION' in line:
            updated = line.replace('"17"', '"18"').replace("'17'", "'18'")
            if updated != line:
                touched = True
            line = updated
        out.append(line)
    if touched:
        path.write_text(''.join(out), encoding='utf-8')
        changed.append(str(path))
print('schema-18 contracts:', ', '.join(changed))
