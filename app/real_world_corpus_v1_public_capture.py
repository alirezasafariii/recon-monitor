from __future__ import annotations

"""Capture real public-source boundary evidence for Real-World Corpus V1.

This collector reads only public GitHub advisory/repository metadata. It never
contacts a vulnerability target, starts a vulnerable service, sends an exploit
request, uses credentials, mutates an external target, runs Analysis scoring,
or creates a human label.

The resulting records are *source-boundary evidence packs*: exact advisory
snapshots plus public commit/compare/pull/release metadata and content hashes.
They are intentionally not treated as proof that a planned positive/negative
case is correct. Human/source adjudication remains mandatory before a replay
record can become human_verified.
"""

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

PUBLIC_CAPTURE_VERSION = "1.0.0"
PUBLIC_CAPTURE_RULE_VERSION = "2026.08.14.9"
EXPECTED_SOURCE_COUNT = 100
EXPECTED_CASE_COUNT = 400

_COMMIT_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:$|[?#])")
_PULL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:$|[/?#])")
_RELEASE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases/tag/([^?#]+)")
_COMPARE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/compare/([^?#]+)")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _api_get_json(url: str, token: str = "") -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-real-world-corpus-v1-public-capture",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _selected_advisory_snapshot(advisory: Mapping[str, Any]) -> dict[str, Any]:
    cwes = []
    for item in advisory.get("cwes", []) or []:
        if isinstance(item, Mapping):
            cwes.append({"cwe_id": _text(item.get("cwe_id")), "name": _text(item.get("name"))})
        elif _text(item):
            cwes.append({"cwe_id": _text(item), "name": ""})

    vulnerabilities = []
    for item in advisory.get("vulnerabilities", []) or []:
        if not isinstance(item, Mapping):
            continue
        package = item.get("package") if isinstance(item.get("package"), Mapping) else {}
        patched = item.get("first_patched_version")
        if isinstance(patched, Mapping):
            patched = patched.get("identifier") or patched.get("version")
        vulnerabilities.append({
            "ecosystem": _text(package.get("ecosystem")),
            "package": _text(package.get("name")),
            "vulnerable_version_range": _text(item.get("vulnerable_version_range")),
            "first_patched_version": _text(patched),
        })

    return {
        "ghsa_id": _text(advisory.get("ghsa_id")).upper(),
        "cve_id": _text(advisory.get("cve_id")).upper(),
        "summary": _text(advisory.get("summary")),
        "severity": _text(advisory.get("severity")).lower(),
        "published_at": _text(advisory.get("published_at")),
        "updated_at": _text(advisory.get("updated_at")),
        "withdrawn_at": _text(advisory.get("withdrawn_at")) or None,
        "repository_advisory_url": _text(advisory.get("repository_advisory_url")),
        "source_code_location": _text(advisory.get("source_code_location")),
        "cwes": sorted(cwes, key=lambda row: (row["cwe_id"], row["name"])),
        "vulnerabilities": sorted(vulnerabilities, key=lambda row: (row["ecosystem"], row["package"], row["vulnerable_version_range"])),
        "references": sorted({_text(item) for item in advisory.get("references", []) or [] if _text(item).startswith("https://")}),
    }


def _commit_snapshot(project: str, sha: str, *, token: str) -> dict[str, Any]:
    payload = _api_get_json(f"https://api.github.com/repos/{project}/commits/{sha}", token=token)
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_commit_payload")
    files = []
    for item in payload.get("files", []) or []:
        if not isinstance(item, Mapping):
            continue
        patch = _text(item.get("patch"))
        files.append({
            "filename": _text(item.get("filename")),
            "status": _text(item.get("status")),
            "additions": int(item.get("additions") or 0),
            "deletions": int(item.get("deletions") or 0),
            "changes": int(item.get("changes") or 0),
            "blob_url": _text(item.get("blob_url")),
            "raw_url": _text(item.get("raw_url")),
            "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest() if patch else None,
        })
    result = {
        "kind": "commit",
        "requested_sha": sha,
        "sha": _text(payload.get("sha")),
        "tree_sha": _text((payload.get("commit") or {}).get("tree", {}).get("sha") if isinstance(payload.get("commit"), Mapping) else ""),
        "parent_shas": [_text(item.get("sha")) for item in payload.get("parents", []) or [] if isinstance(item, Mapping) and _text(item.get("sha"))],
        "author_date": _text((payload.get("commit") or {}).get("author", {}).get("date") if isinstance(payload.get("commit"), Mapping) else ""),
        "committer_date": _text((payload.get("commit") or {}).get("committer", {}).get("date") if isinstance(payload.get("commit"), Mapping) else ""),
        "html_url": _text(payload.get("html_url")),
        "file_count": len(files),
        "files": sorted(files, key=lambda row: row["filename"]),
    }
    result["snapshot_sha256"] = _canonical_hash(result)
    return result


def _pull_snapshot(project: str, number: str, *, token: str) -> dict[str, Any]:
    payload = _api_get_json(f"https://api.github.com/repos/{project}/pulls/{number}", token=token)
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_pull_payload")
    result = {
        "kind": "pull_request",
        "number": int(payload.get("number") or number),
        "state": _text(payload.get("state")),
        "merged_at": _text(payload.get("merged_at")) or None,
        "merge_commit_sha": _text(payload.get("merge_commit_sha")) or None,
        "base_sha": _text((payload.get("base") or {}).get("sha") if isinstance(payload.get("base"), Mapping) else ""),
        "head_sha": _text((payload.get("head") or {}).get("sha") if isinstance(payload.get("head"), Mapping) else ""),
        "changed_files": int(payload.get("changed_files") or 0),
        "additions": int(payload.get("additions") or 0),
        "deletions": int(payload.get("deletions") or 0),
        "html_url": _text(payload.get("html_url")),
    }
    result["snapshot_sha256"] = _canonical_hash(result)
    return result


def _release_snapshot(project: str, tag: str, *, token: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(urllib.parse.unquote(tag), safe="")
    payload = _api_get_json(f"https://api.github.com/repos/{project}/releases/tags/{encoded}", token=token)
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_release_payload")
    result = {
        "kind": "release",
        "id": int(payload.get("id") or 0),
        "tag_name": _text(payload.get("tag_name")),
        "target_commitish": _text(payload.get("target_commitish")),
        "draft": bool(payload.get("draft")),
        "prerelease": bool(payload.get("prerelease")),
        "published_at": _text(payload.get("published_at")),
        "html_url": _text(payload.get("html_url")),
    }
    result["snapshot_sha256"] = _canonical_hash(result)
    return result


def _compare_snapshot(project: str, comparison: str, *, token: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(urllib.parse.unquote(comparison), safe="./-_~")
    payload = _api_get_json(f"https://api.github.com/repos/{project}/compare/{encoded}", token=token)
    if not isinstance(payload, Mapping):
        raise ValueError("unexpected_compare_payload")
    files = []
    for item in payload.get("files", []) or []:
        if isinstance(item, Mapping):
            files.append({
                "filename": _text(item.get("filename")),
                "status": _text(item.get("status")),
                "changes": int(item.get("changes") or 0),
            })
    result = {
        "kind": "compare",
        "comparison": comparison,
        "status": _text(payload.get("status")),
        "ahead_by": int(payload.get("ahead_by") or 0),
        "behind_by": int(payload.get("behind_by") or 0),
        "total_commits": int(payload.get("total_commits") or 0),
        "base_commit_sha": _text((payload.get("base_commit") or {}).get("sha") if isinstance(payload.get("base_commit"), Mapping) else ""),
        "merge_base_sha": _text((payload.get("merge_base_commit") or {}).get("sha") if isinstance(payload.get("merge_base_commit"), Mapping) else ""),
        "file_count": len(files),
        "files": sorted(files, key=lambda row: row["filename"]),
        "html_url": _text(payload.get("html_url")),
    }
    result["snapshot_sha256"] = _canonical_hash(result)
    return result


def _reference_snapshot(url: str, project: str, *, token: str) -> dict[str, Any]:
    for regex, function in (
        (_COMMIT_RE, lambda match: _commit_snapshot(project, match.group(3), token=token)),
        (_PULL_RE, lambda match: _pull_snapshot(project, match.group(3), token=token)),
        (_RELEASE_RE, lambda match: _release_snapshot(project, match.group(3), token=token)),
        (_COMPARE_RE, lambda match: _compare_snapshot(project, match.group(3), token=token)),
    ):
        match = regex.match(url)
        if match and f"{match.group(1)}/{match.group(2)}".lower() == project.lower():
            snapshot = function(match)
            snapshot["reference_url"] = url
            return snapshot
    return {"kind": "unhandled_reference", "reference_url": url, "snapshot_sha256": _canonical_hash({"reference_url": url})}


def capture_source(source: Mapping[str, Any], *, token: str, max_reference_snapshots: int = 4) -> dict[str, Any]:
    root = _text(source.get("source_root")).upper()
    project = _text(source.get("source_project")).lower()
    advisory_raw = _api_get_json(f"https://api.github.com/advisories/{root}", token=token)
    if not isinstance(advisory_raw, Mapping):
        raise ValueError("unexpected_advisory_payload")
    advisory = _selected_advisory_snapshot(advisory_raw)

    reference_inventory = source.get("reference_inventory") if isinstance(source.get("reference_inventory"), Mapping) else {}
    candidate_urls = []
    for key in ("commits", "compares", "pulls", "releases"):
        for url in reference_inventory.get(key, []) or []:
            if _text(url) and _text(url) not in candidate_urls:
                candidate_urls.append(_text(url))

    snapshots: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for url in candidate_urls[: max(0, int(max_reference_snapshots))]:
        try:
            snapshots.append(_reference_snapshot(url, project, token=token))
        except Exception as exc:
            failures.append({"reference_url": url, "error": type(exc).__name__})

    commit_snapshots = [item for item in snapshots if item.get("kind") == "commit" and item.get("sha")]
    primary_commit = commit_snapshots[0] if commit_snapshots else None
    parent_sha = None
    patch_sha = None
    if primary_commit:
        parents = primary_commit.get("parent_shas") or []
        parent_sha = parents[0] if len(parents) == 1 else None
        patch_sha = _canonical_hash([item.get("patch_sha256") for item in primary_commit.get("files", []) or []])

    source_pack = {
        "source_root": root,
        "source_project": project,
        "family_target": source.get("family_target"),
        "target_cwe": source.get("target_cwe"),
        "capture_feasibility": source.get("capture_feasibility"),
        "advisory_snapshot": advisory,
        "advisory_snapshot_sha256": _canonical_hash(advisory),
        "boundary_reference_snapshots": snapshots,
        "boundary_reference_failure_count": len(failures),
        "boundary_reference_failures": failures,
        "candidate_fix_commit_sha": primary_commit.get("sha") if primary_commit else None,
        "candidate_vulnerable_parent_sha": parent_sha,
        "candidate_fix_patch_set_sha256": patch_sha,
        "boundary_semantics_human_confirmed": False,
        "family_label_human_confirmed": False,
        "human_verified": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "capture_channels": {
            "advisory_snapshot": "captured",
            "revision_boundary": "captured_candidate" if primary_commit and parent_sha else "not_exactly_resolved",
            "version_boundary": "captured" if source.get("version_boundaries") else "missing",
        },
        "planned_variant_evidence": {
            "positive": (
                "candidate_vulnerable_parent_revision_captured"
                if parent_sha
                else "vulnerable_version_boundary_captured_requires_source_replay"
            ),
            "secure_negative": (
                "candidate_fix_revision_captured"
                if primary_commit
                else "patched_version_boundary_captured_requires_source_replay"
            ),
            "near_miss": "control_contract_ready_observation_pending",
            "sparse_noisy": "literal_public_advisory_snapshot_captured",
        },
    }
    source_pack["source_pack_sha256"] = _canonical_hash(source_pack)
    return source_pack


def capture_all_sources(sources: Iterable[Mapping[str, Any]], *, token: str) -> dict[str, Any]:
    rows = [dict(row) for row in sources]
    if len(rows) != EXPECTED_SOURCE_COUNT:
        raise ValueError(f"source_count:{len(rows)}!=100")
    packs: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    variant_counts: Counter[str] = Counter()
    revision_resolved = 0
    reference_failure_total = 0

    for source in sorted(rows, key=lambda row: (_text(row.get("source_root")), _text(row.get("source_project")))):
        root = _text(source.get("source_root")).upper()
        try:
            pack = capture_source(source, token=token)
            packs.append(pack)
            reference_failure_total += int(pack["boundary_reference_failure_count"])
            if pack["capture_channels"]["revision_boundary"] == "captured_candidate":
                revision_resolved += 1
            for status in pack["planned_variant_evidence"].values():
                variant_counts[str(status)] += 1
        except Exception as exc:
            failures.append({"source_root": root, "error": type(exc).__name__})

    advisory_hashes = [pack["advisory_snapshot_sha256"] for pack in packs]
    unique_advisory_hashes = len(set(advisory_hashes))
    gates = {
        "all_100_sources_captured": len(packs) == EXPECTED_SOURCE_COUNT and not failures,
        "all_advisory_snapshots_unique": unique_advisory_hashes == EXPECTED_SOURCE_COUNT,
        "no_human_labels_created": all(not bool(pack.get("human_verified")) for pack in packs),
        "no_scoring_executed": all(not bool(pack.get("scoring_executed")) for pack in packs),
        "no_target_contact_performed": all(not bool(pack.get("target_contact_performed")) for pack in packs),
    }
    result = {
        "version": PUBLIC_CAPTURE_VERSION,
        "rule_version": PUBLIC_CAPTURE_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_public_source_evidence_capture",
        "status": "public_source_capture_complete" if all(gates.values()) else "public_source_capture_incomplete",
        "source_count": len(rows),
        "captured_source_count": len(packs),
        "failure_count": len(failures),
        "failures": failures,
        "unique_advisory_snapshot_count": unique_advisory_hashes,
        "candidate_revision_pair_count": revision_resolved,
        "boundary_reference_failure_count": reference_failure_total,
        "planned_variant_evidence_counts": dict(sorted(variant_counts.items())),
        "literal_sparse_noisy_evidence_count": len(packs),
        "human_verified_record_count": 0,
        "gates": gates,
        "passed": all(gates.values()),
        "human_labels_created": False,
        "scoring_executed": False,
        "target_contact_performed": False,
        "source_packs": packs,
        "next_transition": "controlled_source_replay_batches_and_human_boundary_adjudication",
    }
    result["capture_set_sha256"] = _canonical_hash(packs)
    return result


def _load_sources(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("sources")
    if not isinstance(rows, list):
        raise ValueError("source_feasibility_sources_missing")
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture Corpus V1 public-source evidence")
    parser.add_argument("--sources", default="benchmarks/real_world/v1/source_feasibility_final.json")
    parser.add_argument("--output", default="benchmarks/real_world/v1/public_source_evidence.json")
    parser.add_argument("--report", default="benchmarks/real_world/v1/public_source_evidence_report.json")
    parser.add_argument("--github-token", default="")
    args = parser.parse_args(argv)

    result = capture_all_sources(
        _load_sources(Path(args.sources)),
        token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
    )
    _write(Path(args.output), result)
    report = {key: value for key, value in result.items() if key != "source_packs"}
    _write(Path(args.report), report)
    print(json.dumps({
        "ok": result["passed"],
        "captured_sources": result["captured_source_count"],
        "unique_advisories": result["unique_advisory_snapshot_count"],
        "revision_pairs": result["candidate_revision_pair_count"],
        "reference_failures": result["boundary_reference_failure_count"],
        "literal_sparse_noisy": result["literal_sparse_noisy_evidence_count"],
    }, sort_keys=True))
    if not result["passed"]:
        raise SystemExit("public_source_capture_gate_failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
