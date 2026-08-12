from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "app" / "raw_recon_v4_exact_source_supplement.py"
text = path.read_text(encoding="utf-8")
old = '            ("person in the middle", "pitm", "man in the middle"),\n'
new = '            ("person in the middle", "pitm", "man in the middle", "impersonate a trusted upstream server"),\n'
if old not in text:
    raise SystemExit("unsafe API semantic group marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
