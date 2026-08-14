from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for rel in (
    "app/raw_recon_v7_patch_probe.py",
    "app/raw_recon_v7_source_selection.py",
):
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    old = "from raw_recon_v5_source_audit import audit_row\n"
    new = "from v7_source_semantic_audit import audit_row\n"
    if old in text:
        text = text.replace(old, new, 1)
        path.write_text(text, encoding="utf-8")
        print(f"patched {rel}")
    elif new in text:
        print(f"already patched {rel}")
    else:
        raise RuntimeError(f"semantic audit import anchor missing: {rel}")
