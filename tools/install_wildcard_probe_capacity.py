"""Install reviewed wildcard CNAME classification change with checked backups."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BEFORE = 'dec39034b88b6eb5a117e2e561e5390bb08a985f9ace8896ea98de50f26e0f4b'
p = argparse.ArgumentParser()
p.add_argument('--root', required=True)
a = p.parse_args()
root = Path(a.root).resolve()
source = Path(__file__).resolve().parents[1] / 'app/dns_wildcard.py'
target = root / 'app/dns_wildcard.py'
manifest = root / 'MANIFEST.sha256'
new = source.read_bytes()
new_hash = hashlib.sha256(new).hexdigest()
old = target.read_bytes()
old_hash = hashlib.sha256(old).hexdigest()
if old_hash == new_hash:
    print(json.dumps({'installed': str(target), 'status': 'already_installed'}))
    raise SystemExit(0)
if old_hash != BEFORE:
    raise SystemExit('Stopped: installed dns_wildcard.py differs from the reviewed baseline; no files changed.')
lines = manifest.read_text().splitlines()
indices = [i for i,line in enumerate(lines) if line.endswith('  app/dns_wildcard.py')]
if len(indices) != 1 or lines[indices[0]].split()[0] != old_hash:
    raise SystemExit('Stopped: dns_wildcard.py manifest does not match baseline; no files changed.')
lines[indices[0]] = new_hash + '  app/dns_wildcard.py'
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
backup = root / 'state' / 'backups' / ('dns-response-codes-' + stamp)
backup.mkdir(parents=True, mode=0o700)
shutil.copy2(target, backup / 'dns_wildcard.py')
shutil.copy2(manifest, backup / 'MANIFEST.sha256')

def replace(path, data):
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, name = tempfile.mkstemp(prefix='.dns-response-codes-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
try:
    replace(target, new)
    replace(manifest, ('\n'.join(lines)+'\n').encode())
except Exception:
    replace(target, old)
    replace(manifest, (backup/'MANIFEST.sha256').read_bytes())
    raise
print(json.dumps({'installed': str(target), 'sha256': new_hash, 'backup': str(backup)}))
