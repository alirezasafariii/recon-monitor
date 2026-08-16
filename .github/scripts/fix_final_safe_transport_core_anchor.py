from pathlib import Path

path = Path('.github/scripts/final_safe_transport_core_hardening.py')
text = path.read_text(encoding='utf-8')
old = "start = text.index('def _perform_request(\\n')"
new = "start = text.index('def _perform_request(')"
if old not in text:
    raise RuntimeError('core transport hardening start anchor not found')
path.write_text(text.replace(old, new, 1), encoding='utf-8')
