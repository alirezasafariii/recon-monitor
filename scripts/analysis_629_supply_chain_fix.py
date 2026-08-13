from pathlib import Path

path = Path('app/raw_recon_v5_exact_source_supplement.py')
text = path.read_text(encoding='utf-8')
old = '''    "software_supply_chain_failure": {\n        "cve": "CVE-2026-45321",\n        "project_any": ("TanStack/router", "tanstack/router"),\n        "groups": (\n            ("malicious versions",),\n            ("published to the npm registry", "npm registry"),\n            ("credential-stealing malware", "supply-chain attack", "supply chain"),\n        ),\n    },'''
new = '''    "software_supply_chain_failure": {\n        "cve": "CVE-2025-30154",\n        "project_any": ("reviewdog/action-setup",),\n        "groups": (\n            ("was compromised", "compromised"),\n            ("malicious code added", "malicious code"),\n            ("dumps exposed secrets", "github actions workflow logs"),\n        ),\n    },'''
if text.count(old) != 1:
    raise SystemExit('expected exactly one TanStack supply-chain source block')
path.write_text(text.replace(old, new), encoding='utf-8')
print('fresh reviewdog supply-chain source staged for exact v5 firewall')
