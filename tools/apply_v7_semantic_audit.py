from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "app/raw_recon_v7_patch_probe.py": (
        "from raw_recon_v5_source_audit import audit_row\n",
        "from v7_source_semantic_audit import audit_row\n",
    ),
    "app/raw_recon_v7_source_selection.py": (
        "from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row\n",
        "from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION\nfrom v7_source_semantic_audit import audit_row\n",
    ),
}

for rel, (old, new) in TARGETS.items():
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if new in text:
        print(f"already patched {rel}")
        continue
    if old not in text:
        raise RuntimeError(f"semantic audit import anchor missing: {rel}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"patched {rel}")
