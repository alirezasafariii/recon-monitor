from pathlib import Path

path = Path('app/raw_recon_v5_exact_source_supplement.py')
text = path.read_text(encoding='utf-8')
old = '''    "websocket_authorization": {\n        "cve": "CVE-2026-11807",\n        "project_any": ("cpe:redhat/ansible_automation_platform",),\n        "groups": (\n            ("websocket api", "websocket"),\n            ("does not verify user permissions", "missing authorization"),\n            ("arbitrary activation_id", "plaintext credentials", "oauth tokens"),\n        ),\n    },'''
new = '''    "websocket_authorization": {\n        "cve": "CVE-2025-68663",\n        "project_any": ("outline/outline",),\n        "groups": (\n            ("websocket authentication mechanism", "websocket"),\n            ("allows suspended users", "suspended users"),\n            ("continue receiving sensitive operational updates", "sensitive operational updates"),\n        ),\n    },'''
if text.count(old) != 1:
    raise SystemExit('expected exactly one Red Hat WebSocket source block')
path.write_text(text.replace(old, new), encoding='utf-8')
print('fresh Outline WebSocket authorization source staged for exact v5 firewall')
