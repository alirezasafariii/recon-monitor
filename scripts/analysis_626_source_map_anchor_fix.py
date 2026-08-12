from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "app" / "raw_recon_v4_source_audit.py"
text = path.read_text(encoding="utf-8")
old = '    "source_map_exposure": (("source map", "sourcemap", "sourcemappingurl", ".js.map", ".map", "sourcescontent"), ("returned to the browser", "retrieve", "accessible", "served", "published", "public"), ("sensitive content", "sourcescontent", "outside the project root", "internal source", "source content", ".map")),\n'
new = '    "source_map_exposure": (("source map", "sourcemap", "sourcemappingurl", ".js.map", ".mjs.map", ".map", "sourcescontent"), ("returned to the browser", "retrieve", "accessible", "served", "published", "public", "read", "response", "curl"), ("sensitive content", "sourcescontent", "outside the project root", "internal source", "source content", "server file contents", ".map")),\n'
if old not in text:
    raise SystemExit("source-map hard-anchor marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
