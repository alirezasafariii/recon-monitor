from __future__ import annotations

import base64
import gzip
import hashlib
import shutil
import subprocess
from pathlib import Path

ROOT = Path('.').resolve()
PATCH_B64 = "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"

patch_path = Path('/tmp/cc820-dashboard.patch')
patch_path.write_bytes(gzip.decompress(base64.b64decode(PATCH_B64)))
subprocess.run(['git', 'apply', str(patch_path)], check=True)


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    p = ROOT / path
    s = p.read_text(encoding='utf-8')
    if old not in s:
        raise RuntimeError(f'missing expected text in {path}: {old!r}')
    p.write_text(s.replace(old, new, count), encoding='utf-8')

p = ROOT / 'tests/test_dashboard_polish_v801.py'
s = p.read_text(encoding='utf-8')
s = s.replace('from dashboard import _candidate_confidence_story, _layout', 'from dashboard import _candidate_confidence_story, _command_decision_item, _layout', 1)
method = """
    def test_command_center_v2_decision_item_is_actionable(self) -> None:
        html = _command_decision_item({
            "kind": "candidate", "eyebrow": "Potential finding", "title": "Review authorization boundary",
            "detail": "Compare two authorized test identities.", "href": "/bug-candidate?id=BC-1",
            "score": 91, "tone": "danger", "meta": "example.com · BOLA",
        }, 1)
        self.assertIn("data-decision-kind='candidate'", html)
        self.assertIn("Review authorization boundary", html)
        self.assertIn("91", html)
        self.assertIn("/bug-candidate?id=BC-1", html)

"""
if 'test_command_center_v2_decision_item_is_actionable' not in s:
    marker = '\n\nif __name__ == "__main__":\n'
    if marker not in s:
        raise RuntimeError('test insertion marker not found')
    s = s.replace(marker, method + marker, 1)
p.write_text(s, encoding='utf-8')

replace('app/core.py', 'APP_VERSION = "8.1.1"', 'APP_VERSION = "8.2.0"')
for rel in ['tests/test_stability_v451.py','tests/test_platform_v60.py','tests/test_workspace_v70.py','tests/test_safe_validation_v51.py','tests/test_product_platform_v50.py']:
    p=ROOT/rel
    s=p.read_text(encoding='utf-8').replace('"8.1.1"','"8.2.0"').replace("'8.1.1'","'8.2.0'")
    p.write_text(s,encoding='utf-8')
replace('config.env.example', '# Recon Monitor 8.1.1 configuration', '# Recon Monitor 8.2.0 configuration')
replace('config.env.example', 'ReconMonitor/8.1.1', 'ReconMonitor/8.2.0')
replace('README.md', '# Recon Monitor 8.1.1', '# Recon Monitor 8.2.0')
p=ROOT/'README.md'; s=p.read_text(encoding='utf-8')
section='''
## Command Center 2.0 in 8.2.0

The landing workspace is now decision-first. It ranks run failures, high-value potential findings, open cases, evidence gaps, and material re-check changes into one **Decision Inbox**, then surfaces a single **Next Best Action**. Workspace Pulse and Recent Research Activity provide context without turning the landing page back into an inventory dashboard.

'''
if '## Command Center 2.0 in 8.2.0' not in s:
    first=s.find('\n'); s=s[:first+1]+section+s[first+1:]
p.write_text(s,encoding='utf-8')
p=ROOT/'README_FA.md'; s=p.read_text(encoding='utf-8').replace('# راهنمای Recon Monitor 8.1.0','# راهنمای Recon Monitor 8.2.0',1).replace('# راهنمای Recon Monitor 8.1.1','# راهنمای Recon Monitor 8.2.0',1); p.write_text(s,encoding='utf-8')

p=ROOT/'CHANGELOG.md'; s=p.read_text(encoding='utf-8')
block='''# 8.2.0 — Command Center 2.0

- Rebuilt the landing workspace around a ranked Decision Inbox instead of passive dashboard cards.
- Added a single Next Best Action derived from run health, potential findings, evidence gaps and material surface changes.
- Added high-interest change, high-value finding and evidence-gap KPIs with target focus.
- Added compact Workspace Pulse and Recent Research Activity panels.
- Kept Recon, Analysis, Potential Findings and Alerts as the four primary workspaces.
- Preserved the permanent Command Center navigation entry introduced in 8.1.1.
- Database schema remains 16; no destructive migration is required.

'''
if not s.startswith('# 8.2.0 — Command Center 2.0'):
    s=block+s
p.write_text(s,encoding='utf-8')

(ROOT/'MIGRATION-v8.2.md').write_text('''# Migration to Recon Monitor 8.2.0

Recon Monitor 8.2.0 is a Dashboard/decision-workflow upgrade. The database schema remains **16**.

## What changes

- Command Center becomes a ranked Decision Inbox.
- The highest-value next action is surfaced explicitly.
- Material re-check changes and recent run activity are visible without opening specialist tools.
- Four primary workspaces remain Recon, Analysis, Potential Findings and Alerts.

## Upgrade

```bash
./recon-monitor.sh update check
./recon-monitor.sh update install
```

The updater creates backups before replacement and retains rollback behavior.
''', encoding='utf-8')

p=ROOT/'tests/test_update_v810.py'; s=p.read_text(encoding='utf-8')
s=s.replace('"tagName": "v8.2.0"','"tagName": "v8.3.0"',1).replace('"name": "Recon Monitor v8.2.0"','"name": "Recon Monitor v8.3.0"',1).replace('/tag/v8.2.0','/tag/v8.3.0',1).replace('"recon-monitor-v8.2.0.zip"','"recon-monitor-v8.3.0.zip"',1).replace('"recon-monitor-v8.2.0.zip.sha256"','"recon-monitor-v8.3.0.zip.sha256"',1).replace('self.assertEqual(result["available"], "8.2.0")','self.assertEqual(result["available"], "8.3.0")',1).replace('self.assertIn("recon-monitor-v8.2.0.zip", result["assets"])','self.assertIn("recon-monitor-v8.3.0.zip", result["assets"])',1)
p.write_text(s,encoding='utf-8')

(ROOT/'.github/workflows/publish-v820-command-center.yml').unlink(missing_ok=True)
(ROOT/'.github/scripts/publish_v820.py').unlink(missing_ok=True)
try:
    (ROOT/'.github/scripts').rmdir()
except OSError:
    pass

for p in list(ROOT.rglob('__pycache__')):
    if p.is_dir(): shutil.rmtree(p)
for p in list(ROOT.rglob('*.pyc')) + list(ROOT.rglob('*.pyo')):
    p.unlink(missing_ok=True)
entries=[]
for p in sorted(ROOT.rglob('*')):
    if not p.is_file(): continue
    rel=p.relative_to(ROOT).as_posix()
    if rel=='MANIFEST.sha256' or rel.startswith('.git/') or rel=='.DS_Store': continue
    entries.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
(ROOT/'MANIFEST.sha256').write_text('\n'.join(entries)+'\n',encoding='utf-8')
print(f'prepared Recon Monitor 8.2.0 with {len(entries)} manifest entries')
