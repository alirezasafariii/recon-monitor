from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"expected text not found in {path}: {old[:120]!r}")
    text = text.replace(old, new, 1)
    p.write_text(text, encoding="utf-8")


replace_once(
    "app/core.py",
    'APP_VERSION = "8.4.4"',
    'APP_VERSION = "8.4.5"',
)

# Current Attack Surface must never pull candidate nodes from older analyses.
replace_once(
    "app/workspace_v7.py",
    '''    for row in db.all("SELECT candidate_id,endpoint,bug_family,candidate_state,priority_score FROM bug_candidates WHERE target=? ORDER BY priority_score DESC LIMIT 300", (target,)):\n        cid = add_node("candidate", str(row["candidate_id"]), family=str(row["bug_family"]), state=str(row["candidate_state"]), priority=int(row["priority_score"] or 0))\n        endpoint = str(row["endpoint"] or "")\n        parent = add_node("endpoint", endpoint) if endpoint else root\n        edges.append({"source": parent, "target": cid, "relation": "candidate"})\n''',
    '''    if analysis_id:\n        for row in db.all("SELECT candidate_id,endpoint,bug_family,candidate_state,priority_score FROM bug_candidates WHERE analysis_id=? AND target=? ORDER BY priority_score DESC LIMIT 300", (analysis_id, target)):\n            cid = add_node("candidate", str(row["candidate_id"]), family=str(row["bug_family"]), state=str(row["candidate_state"]), priority=int(row["priority_score"] or 0))\n            endpoint = str(row["endpoint"] or "")\n            parent = add_node("endpoint", endpoint) if endpoint else root\n            edges.append({"source": parent, "target": cid, "relation": "candidate"})\n''',
)

# Current Change Intelligence must never surface historical candidates from the same source run.
replace_once(
    "app/workspace_v7.py",
    '''    for row in db.all("SELECT candidate_id,title,priority_score,candidate_state FROM bug_candidates WHERE target=? AND source_run_id=? ORDER BY priority_score DESC LIMIT 8", (target, run_id)):\n        if int(row["priority_score"] or 0) >= 70:\n            important.append({"type": "candidate", "candidate_id": row["candidate_id"], "title": row["title"], "priority": row["priority_score"], "state": row["candidate_state"]})\n    result = {"target": target, "current_run": run_id, "previous_run": previous, "changes": changes, "important": important, "generated_at": utc_now()}\n''',
    '''    if analysis_id:\n        for row in db.all("SELECT candidate_id,title,priority_score,candidate_state FROM bug_candidates WHERE analysis_id=? AND target=? AND source_run_id=? ORDER BY priority_score DESC LIMIT 8", (analysis_id, target, run_id)):\n            if int(row["priority_score"] or 0) >= 70:\n                important.append({"type": "candidate", "candidate_id": row["candidate_id"], "title": row["title"], "priority": row["priority_score"], "state": row["candidate_state"]})\n    result = {"target": target, "analysis_id": analysis_id, "current_run": run_id, "previous_run": previous, "changes": changes, "important": important, "generated_at": utc_now()}\n''',
)

# Align tests that intentionally assert the current application version.
for p in Path("tests").glob("test_*.py"):
    text = p.read_text(encoding="utf-8")
    if "8.4.4" in text:
        p.write_text(text.replace("8.4.4", "8.4.5"), encoding="utf-8")

Path("MIGRATION-v8.4.5.md").write_text(
    """# Recon Monitor v8.4.5\n\nCurrent Analysis Projection Isolation hotfix.\n\n- Current Change Intelligence now reads candidate highlights only from the latest analysis for the target.\n- Current Attack Surface Graph now projects candidate nodes only from the latest analysis.\n- Historical candidate memory, target learning, and analyst history remain preserved and queryable.\n- No database schema change; schema remains 18.\n- This prevents historical candidates from reappearing as current findings after a newer analysis correctly abstains.\n""",
    encoding="utf-8",
)

print("v8.4.5 current analysis isolation patch applied")
