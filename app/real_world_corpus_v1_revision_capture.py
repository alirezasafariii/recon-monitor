from __future__ import annotations

"""Capture exact parent/fix source-revision pairs for Real-World Corpus V1.

For public advisory sources where a candidate fix commit has a single parent,
this stage records exact Git tree/blob identities for every changed file across
that boundary. It does not persist source contents or patch text; patch text is
used transiently only to compute SHA-256 fingerprints.

The boundary remains a *candidate advisory fix boundary* until human/source
review confirms its semantics. This module does not contact vulnerability
targets, run applications, use credentials, generate exploit payloads, mutate
external state, execute Analysis scoring, or create human labels.
"""

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

REVISION_CAPTURE_VERSION = "1.0.0"
REVISION_CAPTURE_RULE_VERSION = "2026.08.14.10"
EXPECTED_PAIR_CANDIDATES = 66


def _text(value: Any) -> str:
    return str(value or "").strip()


def _canonical_hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _api_get_json(url: str, token: str = "") -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-real-world-corpus-v1-revision-capture",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _commit(project: str, sha: str, *, token: str) -> Mapping[str, Any]:
    payload = _api_get_json(f"https://api.github.com/repos/{project}/commits/{sha}", token=token)
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_commit_payload")
    return payload


def _tree(project: str, tree_sha: str, *, token: str) -> dict[str, Any]:
    payload = _api_get_json(
        f"https://api.github.com/repos/{project}/git/trees/{tree_sha}?recursive=1",
        token=token,
    )
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_tree_payload")
    entries: dict[str, dict[str, Any]] = {}
    for item in payload.get("tree", []) or []:
        if not isinstance(item, Mapping) or _text(item.get("type")) != "blob":
            continue
        path = _text(item.get("path"))
        if not path:
            continue
        entries[path] = {
            "blob_sha": _text(item.get("sha")),
            "size": int(item.get("size") or 0),
            "mode": _text(item.get("mode")),
        }
    return {
        "tree_sha": _text(payload.get("sha")) or tree_sha,
        "truncated": bool(payload.get("truncated")),
        "blob_count": len(entries),
        "entries": entries,
    }


def _commit_tree_sha(payload: Mapping[str, Any]) -> str:
    commit = payload.get("commit") if isinstance(payload.get("commit"), Mapping) else {}
    tree = commit.get("tree") if isinstance(commit.get("tree"), Mapping) else {}
    return _text(tree.get("sha"))


def _changed_files(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in payload.get("files", []) or []:
        if not isinstance(item, Mapping):
            continue
        patch = _text(item.get("patch"))
        rows.append({
            "filename": _text(item.get("filename")),
            "previous_filename": _text(item.get("previous_filename")) or None,
            "status": _text(item.get("status")),
            "fix_blob_sha_from_commit": _text(item.get("sha")) or None,
            "additions": int(item.get("additions") or 0),
            "deletions": int(item.get("deletions") or 0),
            "changes": int(item.get("changes") or 0),
            "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest() if patch else None,
        })
    return sorted(rows, key=lambda row: (row["filename"], row["previous_filename"] or ""))


def _file_pair(
    changed: Mapping[str, Any],
    parent_tree: Mapping[str, Any],
    fix_tree: Mapping[str, Any],
) -> dict[str, Any]:
    filename = _text(changed.get("filename"))
    previous = _text(changed.get("previous_filename")) or filename
    status = _text(changed.get("status"))
    parent_entry = (parent_tree.get("entries") or {}).get(previous)
    fix_entry = (fix_tree.get("entries") or {}).get(filename)

    expected_parent_present = status not in {"added"}
    expected_fix_present = status not in {"removed"}
    parent_present = isinstance(parent_entry, Mapping) and bool(_text(parent_entry.get("blob_sha")))
    fix_present = isinstance(fix_entry, Mapping) and bool(_text(fix_entry.get("blob_sha")))

    complete = (parent_present == expected_parent_present) and (fix_present == expected_fix_present)
    fix_commit_blob = _text(changed.get("fix_blob_sha_from_commit"))
    if fix_present and fix_commit_blob and fix_commit_blob != _text(fix_entry.get("blob_sha")):
        complete = False

    result = {
        "filename": filename,
        "previous_filename": previous if previous != filename else None,
        "status": status,
        "parent_present": parent_present,
        "fix_present": fix_present,
        "parent_blob_sha": _text(parent_entry.get("blob_sha")) if parent_present else None,
        "fix_blob_sha": _text(fix_entry.get("blob_sha")) if fix_present else None,
        "parent_blob_size": int(parent_entry.get("size") or 0) if parent_present else 0,
        "fix_blob_size": int(fix_entry.get("size") or 0) if fix_present else 0,
        "patch_sha256": changed.get("patch_sha256"),
        "additions": int(changed.get("additions") or 0),
        "deletions": int(changed.get("deletions") or 0),
        "changes": int(changed.get("changes") or 0),
        "pair_complete": complete,
    }
    result["file_pair_sha256"] = _canonical_hash(result)
    return result


def capture_revision_pair(pack: Mapping[str, Any], *, token: str) -> dict[str, Any]:
    project = _text(pack.get("source_project")).lower()
    root = _text(pack.get("source_root")).upper()
    fix_sha = _text(pack.get("candidate_fix_commit_sha"))
    parent_sha = _text(pack.get("candidate_vulnerable_parent_sha"))
    if not project or not root or not fix_sha or not parent_sha:
        raise ValueError("revision_pair_identity_incomplete")

    fix_commit = _commit(project, fix_sha, token=token)
    resolved_fix_sha = _text(fix_commit.get("sha"))
    parents = [
        _text(item.get("sha"))
        for item in fix_commit.get("parents", []) or []
        if isinstance(item, Mapping) and _text(item.get("sha"))
    ]
    if resolved_fix_sha != fix_sha:
        raise ValueError("fix_sha_resolution_mismatch")
    if len(parents) != 1 or parents[0] != parent_sha:
        raise ValueError("single_parent_boundary_mismatch")

    parent_commit = _commit(project, parent_sha, token=token)
    if _text(parent_commit.get("sha")) != parent_sha:
        raise ValueError("parent_sha_resolution_mismatch")

    fix_tree_sha = _commit_tree_sha(fix_commit)
    parent_tree_sha = _commit_tree_sha(parent_commit)
    if not fix_tree_sha or not parent_tree_sha:
        raise ValueError("tree_sha_missing")

    fix_tree = _tree(project, fix_tree_sha, token=token)
    parent_tree = _tree(project, parent_tree_sha, token=token)
    changed = _changed_files(fix_commit)
    if not changed:
        raise ValueError("fix_commit_has_no_changed_files")

    file_pairs = [_file_pair(item, parent_tree, fix_tree) for item in changed]
    incomplete_files = [row["filename"] for row in file_pairs if not row["pair_complete"]]
    tree_truncated = bool(fix_tree["truncated"] or parent_tree["truncated"])
    complete = not incomplete_files and not tree_truncated

    result = {
        "source_root": root,
        "source_project": project,
        "family_target": pack.get("family_target"),
        "target_cwe": pack.get("target_cwe"),
        "candidate_fix_commit_sha": fix_sha,
        "candidate_vulnerable_parent_sha": parent_sha,
        "fix_tree_sha": fix_tree_sha,
        "parent_tree_sha": parent_tree_sha,
        "fix_tree_truncated": bool(fix_tree["truncated"]),
        "parent_tree_truncated": bool(parent_tree["truncated"]),
        "changed_file_count": len(file_pairs),
        "file_pairs": file_pairs,
        "incomplete_file_count": len(incomplete_files),
        "incomplete_files": incomplete_files,
        "revision_pair_complete": complete,
        "boundary_semantics_human_confirmed": False,
        "family_label_human_confirmed": False,
        "human_verified": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "source_contents_persisted": False,
        "patch_contents_persisted": False,
        "planned_variant_evidence": {
            "positive": "exact_parent_revision_tree_and_changed_blob_set_captured",
            "secure_negative": "exact_fix_revision_tree_and_changed_blob_set_captured",
        },
    }
    result["revision_pair_sha256"] = _canonical_hash(result)
    return result


def capture_all_pairs(source_packs: Iterable[Mapping[str, Any]], *, token: str) -> dict[str, Any]:
    candidates = [
        dict(pack)
        for pack in source_packs
        if _text(pack.get("candidate_fix_commit_sha")) and _text(pack.get("candidate_vulnerable_parent_sha"))
    ]
    if len(candidates) != EXPECTED_PAIR_CANDIDATES:
        raise ValueError(f"candidate_pair_count:{len(candidates)}!={EXPECTED_PAIR_CANDIDATES}")

    pairs: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    changed_file_total = 0
    pair_hashes: set[str] = set()
    family_counts: Counter[str] = Counter()

    for pack in sorted(candidates, key=lambda row: (_text(row.get("source_root")), _text(row.get("source_project")))):
        root = _text(pack.get("source_root")).upper()
        try:
            pair = capture_revision_pair(pack, token=token)
            if not pair["revision_pair_complete"]:
                raise ValueError("revision_pair_incomplete")
            pairs.append(pair)
            changed_file_total += int(pair["changed_file_count"])
            pair_hashes.add(str(pair["revision_pair_sha256"]))
            family = _text(pair.get("family_target")) or "unassigned_general_source"
            family_counts[family] += 1
        except Exception as exc:
            failures.append({"source_root": root, "error": type(exc).__name__})

    gates = {
        "all_66_candidate_pairs_captured": len(pairs) == EXPECTED_PAIR_CANDIDATES and not failures,
        "all_pair_hashes_unique": len(pair_hashes) == EXPECTED_PAIR_CANDIDATES,
        "all_pairs_complete": all(bool(pair.get("revision_pair_complete")) for pair in pairs),
        "no_source_contents_persisted": all(not bool(pair.get("source_contents_persisted")) for pair in pairs),
        "no_patch_contents_persisted": all(not bool(pair.get("patch_contents_persisted")) for pair in pairs),
        "no_human_labels_created": all(not bool(pair.get("human_verified")) for pair in pairs),
        "no_scoring_executed": all(not bool(pair.get("scoring_executed")) for pair in pairs),
        "no_target_contact_performed": all(not bool(pair.get("target_contact_performed")) for pair in pairs),
    }
    result = {
        "version": REVISION_CAPTURE_VERSION,
        "rule_version": REVISION_CAPTURE_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_exact_revision_pair_capture",
        "status": "revision_pair_capture_complete" if all(gates.values()) else "revision_pair_capture_incomplete",
        "candidate_pair_count": len(candidates),
        "captured_pair_count": len(pairs),
        "failure_count": len(failures),
        "failures": failures,
        "changed_file_pair_count": changed_file_total,
        "unique_revision_pair_hash_count": len(pair_hashes),
        "family_target_counts": dict(sorted(family_counts.items())),
        "literal_positive_source_boundary_count": len(pairs),
        "literal_secure_negative_source_boundary_count": len(pairs),
        "human_verified_record_count": 0,
        "gates": gates,
        "passed": all(gates.values()),
        "human_labels_created": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "source_contents_persisted": False,
        "patch_contents_persisted": False,
        "revision_pairs": pairs,
        "next_transition": "source_semantics_review_and_controlled_behavioral_replay",
    }
    result["capture_set_sha256"] = _canonical_hash(pairs)
    return result


def _load_packs(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("source_packs")
    if not isinstance(rows, list):
        raise ValueError("public_source_packs_missing")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture exact Corpus V1 revision pairs")
    parser.add_argument("--public-evidence", default="benchmarks/real_world/v1/public_source_evidence.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/revision_pair_evidence.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/revision_pair_evidence_report.json")
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    result = capture_all_pairs(
        _load_packs(Path(args.public_evidence)),
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "revision_pairs"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": result["passed"],
        "candidate_pairs": result["candidate_pair_count"],
        "captured_pairs": result["captured_pair_count"],
        "changed_file_pairs": result["changed_file_pair_count"],
        "failures": result["failure_count"],
    }, sort_keys=True))
    if not result["passed"]:
        raise SystemExit("revision_pair_capture_gate_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
