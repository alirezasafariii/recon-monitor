from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
p = ROOT / "app/v7_literal_patch_capture.py"
text = p.read_text(encoding="utf-8")

# The current collector already contains the stronger source-grounded near-miss
# helpers and may also contain later pre-freeze hardening (for example the v7.14
# label-blind raw boundary). In that state this compatibility refinement must be
# a no-op rather than trying to match and rewrite an obsolete source anchor.
modern_markers = (
    "def _non_decisive_narrative(family: str, text: str) -> list[str]:",
    "def _non_decisive_filenames(family: str, filenames: list[str]) -> list[str]:",
    '"adjacent_non_decisive_source_context": near,',
    '"near_miss_source_basis": near_basis,',
)
if all(marker in text for marker in modern_markers):
    print("v7 near-miss capture already contains source-grounded non-synthetic fallbacks")
    raise SystemExit(0)

anchor = '''def _non_decisive_context(family: str, lines: list[str]) -> list[str]:
    selected: list[str] = []
    for line in lines:
        candidate = {"summary": "", "description": line}
        signals, _ = audit_conditions(family, candidate)
        if not signals:
            selected.append(line)
        if len(selected) >= 24:
            break
    return selected
'''
replacement = anchor + '''

def _non_decisive_narrative(family: str, text: str) -> list[str]:
    # Independent source-grounded context only: split the real upstream narrative
    # into intact clauses/paragraphs and keep clauses that do not satisfy a
    # decisive preregistered condition. No positive-field deletion or mutation.
    import re
    selected: list[str] = []
    for segment in re.split(r"(?:\\n{2,}|(?<=[.!?])\\s+)", str(text or "")):
        value = segment.strip()
        if len(value) < 24:
            continue
        signals, _ = audit_conditions(family, {"summary": "", "description": value})
        if signals:
            continue
        selected.append(value[:1200])
        if len(selected) >= 12:
            break
    return selected


def _non_decisive_filenames(family: str, filenames: list[str]) -> list[str]:
    selected: list[str] = []
    for filename in filenames:
        value = str(filename or "").strip()
        if not value:
            continue
        signals, _ = audit_conditions(family, {"summary": "", "description": value})
        if signals:
            continue
        selected.append(value)
        if len(selected) >= 8:
            break
    return selected
'''
if replacement not in text:
    if anchor not in text:
        raise RuntimeError("v7 near-miss helper anchor missing")
    text = text.replace(anchor, replacement, 1)

old = '''        near = _non_decisive_context(family, context)
        if not near:
            # A near miss must be a genuine adjacent upstream observation that does
            # not satisfy the decisive condition. Do not mutate the positive row.
            raise RuntimeError(f"{family}: patch has no independent non-decisive context for near_miss")
'''
new = '''        near = _non_decisive_context(family, context)
        near_basis = "unchanged_patch_context"
        if not near:
            near = _non_decisive_narrative(family, source_text)
            near_basis = "independent_upstream_narrative_context"
        if not near:
            near = _non_decisive_filenames(family, filenames)
            near_basis = "adjacent_changed_file_context"
        if not near:
            # No synthetic fallback: replace the source instead of fabricating a near miss.
            raise RuntimeError(f"{family}: source has no independent non-decisive near-miss observation")
'''
if new not in text:
    if old not in text:
        raise RuntimeError("v7 near-miss selection anchor missing")
    text = text.replace(old, new, 1)

old_details = '''                    "adjacent_unchanged_patch_context": near,
                    "context_observation": "Adjacent upstream patch context was retained only after the pre-score condition audit found no decisive condition phrase in these lines.",
'''
new_details = '''                    "adjacent_non_decisive_source_context": near,
                    "near_miss_source_basis": near_basis,
                    "context_observation": "This intact upstream observation was retained only after the pre-score condition audit found no decisive condition phrase; it is not produced by deleting or mutating positive evidence.",
'''
if new_details not in text:
    if old_details not in text:
        raise RuntimeError("v7 near-miss raw-details anchor missing")
    text = text.replace(old_details, new_details, 1)

p.write_text(text, encoding="utf-8")
print("refined v7 near-miss capture with source-grounded non-synthetic fallbacks")
