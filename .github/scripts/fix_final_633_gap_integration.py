from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path

ROOT = Path('.')
path = ROOT / 'app/hypothesis_admission.py'
text = path.read_text(encoding='utf-8')

replacement = '''def assess_admission(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    raw_support_items = [dict(item) for item in support]
    raw_contradict_items = [dict(item) for item in (contradict or [])]
    support_scope = scope_family_evidence(
        family, raw_support_items, annotate_unscoped=False, channel="admission"
    )
    contradict_scope = scope_family_evidence(
        family, raw_contradict_items, annotate_unscoped=False, channel="admission"
    )
    support_items = list(support_scope["accepted"])
    contradict_items = list(contradict_scope["accepted"])

    # Only typed, family-compatible target-evidence records participate in
    # admission. Knowledge projections intentionally have no evidence ``type``.
    typed_support_items = [
        item for item in support_items if str(item.get("type") or "").strip()
    ]
    types = {str(item.get("type") or "") for item in typed_support_items}
    contradiction_types = {
        str(item.get("type") or "") for item in contradict_items
        if str(item.get("type") or "").strip()
    }
    sources = {
        str(item.get("source_group") or item.get("source") or item.get("type") or "unknown")
        for item in typed_support_items
    }
    policy = FAMILY_ADMISSION_POLICIES.get(family)
    scope_diagnostics = {
        "version": support_scope["version"],
        "rule_version": support_scope["rule_version"],
        "rejected_cross_family_support": int(support_scope["rejected_count"]),
        "rejected_cross_family_contradictions": int(contradict_scope["rejected_count"]),
    }

    # Unknown families fail closed. Candidate generation should never silently
    # promote a family that has no reviewed evidence contract.
    if not policy:
        result = {
            "state": "shadow_signal",
            "admitted": False,
            "policy": "missing-family-reasoning-policy",
            "required_satisfied": [],
            "required_missing": [["family reasoning policy"]],
            "independent_sources": len(sources),
            "decisive_signals": [],
            "blocking_contradictions": [],
            "confirmation_required": [],
            "validation_level": "offline",
            "reason": "Retained as a hidden hypothesis because no reviewed Family Reasoning policy exists for this family.",
            "family_reasoning_version": FAMILY_REASONING_VERSION,
            "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
            "evidence_scope": scope_diagnostics,
        }
        result["knowledge_references"] = knowledge_for_family(family)
        result["knowledge_context"] = _classification_context(
            family,
            support_items,
            contradict_items,
            admission_by_family={family: result},
        )
        return result

    satisfied: list[list[str]] = []
    missing: list[list[str]] = []
    decisive: set[str] = set()
    for group in policy.get("required", []):
        matches = sorted(set(group) & types)
        if matches:
            satisfied.append(matches)
            decisive.update(matches)
        else:
            missing.append(sorted(group))

    source_ok = len(sources) >= int(policy.get("min_independent_sources", 1))
    blocking = sorted(set(policy.get("blocking_contradictions", set())) & contradiction_types)
    override = bool(set(policy.get("override_signals", set())) & types)
    blocked = bool(blocking) and not override
    complete = not missing and source_ok and not blocked

    if complete:
        state = "admitted"
        reason = f"Admission complete: {policy.get('label')}."
    elif blocked:
        state = "shadow_contradicted"
        reason = f"Retained as a hidden hypothesis because stored target evidence supports an enforcing or non-vulnerable interpretation: {', '.join(blocking)}."
    elif satisfied:
        state = "shadow_partial"
        reason = f"Retained as a hidden hypothesis: partial evidence for {policy.get('label')}."
    else:
        state = "shadow_signal"
        reason = f"Retained as a hidden hypothesis: no decisive family-specific evidence yet for {policy.get('label')}."
    if not source_ok:
        reason += f" Independent-source requirement is not yet met ({len(sources)}/{policy.get('min_independent_sources', 1)})."

    result = {
        "state": state,
        "admitted": complete,
        "policy": policy.get("label"),
        "required_satisfied": satisfied,
        "required_missing": missing,
        "independent_sources": len(sources),
        "decisive_signals": sorted(decisive),
        "blocking_contradictions": blocking,
        "confirmation_required": [sorted(group) for group in policy.get("confirmation_required", [])],
        "validation_level": str(policy.get("validation_level") or "offline"),
        "reason": reason,
        "family_reasoning_version": FAMILY_REASONING_VERSION,
        "family_reasoning_rule_version": FAMILY_REASONING_RULE_VERSION,
        "evidence_scope": scope_diagnostics,
    }
    try:
        result["researcher_logic"] = researcher_logic_for_family(family)
    except KeyError:
        pass
    result["knowledge_references"] = knowledge_for_family(family)
    result["knowledge_context"] = _classification_context(
        family,
        support_items,
        contradict_items,
        admission_by_family={family: result},
    )
    return result
'''

pattern = re.compile(
    r'def assess_admission\(.*?\n\n(?=def _persist_classification_tags\()',
    flags=re.DOTALL,
)
updated, count = pattern.subn(replacement + '\n\n', text, count=1)
if count != 1:
    raise RuntimeError(f'assess_admission replacement count was {count}, expected 1')
path.write_text(updated, encoding='utf-8')

# The primary migration computed the manifest before this syntax-safe rewrite.
# Refresh only already-listed paths; temporary scripts/workflows stay excluded.
manifest = ROOT / 'MANIFEST.sha256'
paths: list[str] = []
for line in manifest.read_text(encoding='utf-8').splitlines():
    if '  ' not in line:
        continue
    _, file_path = line.split('  ', 1)
    if file_path and (ROOT / file_path).exists():
        paths.append(file_path)
rows = [
    f"{sha256((ROOT / file_path).read_bytes()).hexdigest()}  {file_path}"
    for file_path in sorted(set(paths))
]
manifest.write_text('\n'.join(rows) + '\n', encoding='utf-8')
