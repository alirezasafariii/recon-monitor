from __future__ import annotations

"""Acquire exact public-source boundaries for frozen Fresh Blind V7 sources.

This collector reads GitHub advisory/repository metadata only. It never runs
Analysis, executes third-party code, contacts a vulnerability target, or creates
a benchmark label. Commit/PR/release boundaries are candidates until literal
variant construction validates their semantics.
"""

import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.33.v7.boundary.1"
RESEARCH = ROOT / "benchmarks/raw/sources/v7_literal_source_research.json"
PLAN = ROOT / "benchmarks/raw/sources/v7_literal_capture_plan.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v7_boundary_evidence.json"
REPORT = ROOT / "benchmarks/raw/sources/v7_boundary_evidence_report.json"
EXPECTED = 36
COMMIT_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})(?:$|[?#])")
PULL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:$|[/?#])")
RELEASE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases/tag/([^?#]+)")
COMPARE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/compare/([^?#]+)")
URL_RE = re.compile(r"https://[^\s)\]>'\"]+")
TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)


def text(value: Any) -> str:
    return str(value or "").strip()


def canon_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def api(url: str, token: str) -> Any:
    headers = {"Accept":"application/vnd.github+json","User-Agent":"recon-monitor-v7-boundary","X-GitHub-Api-Version":"2022-11-28"}
    if token: headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return json.loads(response.read().decode())


def urls_from(value: Any) -> list[str]:
    found: set[str] = set()
    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for k, v in item.items():
                if k in {"patch", "diff"}: continue
                walk(v)
        elif isinstance(item, list):
            for v in item: walk(v)
        elif isinstance(item, str):
            if item.startswith("https://"): found.add(item.rstrip(".,;:"))
            for match in URL_RE.findall(item): found.add(match.rstrip(".,;:"))
    walk(value)
    return sorted(found)


def commit_snapshot(project: str, sha: str, token: str) -> dict[str, Any]:
    payload = api(f"https://api.github.com/repos/{project}/commits/{sha}", token)
    if not isinstance(payload, Mapping): raise ValueError("unexpected_commit_payload")
    files=[]
    for item in payload.get("files") or []:
        if not isinstance(item, Mapping): continue
        patch=text(item.get("patch")); path=text(item.get("filename"))
        files.append({
            "filename":path,"previous_filename":text(item.get("previous_filename")) or None,
            "status":text(item.get("status")),"additions":int(item.get("additions") or 0),
            "deletions":int(item.get("deletions") or 0),"changes":int(item.get("changes") or 0),
            "blob_url":text(item.get("blob_url")),"raw_url":text(item.get("raw_url")),
            "patch_sha256":hashlib.sha256(patch.encode()).hexdigest() if patch else None,
            "is_test_path":bool(TEST_PATH.search(path)),
        })
    commit=payload.get("commit") if isinstance(payload.get("commit"), Mapping) else {}
    result={
        "kind":"commit","sha":text(payload.get("sha")),"requested_sha":sha,
        "parent_shas":[text(x.get("sha")) for x in payload.get("parents") or [] if isinstance(x,Mapping) and text(x.get("sha"))],
        "tree_sha":text((commit.get("tree") or {}).get("sha") if isinstance(commit.get("tree"),Mapping) else ""),
        "message":text(commit.get("message"))[:1000],"html_url":text(payload.get("html_url")),
        "files":sorted(files,key=lambda x:x["filename"]),"file_count":len(files),
        "changed_test_file_count":sum(bool(x["is_test_path"]) for x in files),
    }
    result["snapshot_sha256"]=canon_hash(result)
    return result


def pull_snapshot(project: str, number: str, token: str) -> dict[str, Any]:
    p=api(f"https://api.github.com/repos/{project}/pulls/{number}",token)
    if not isinstance(p,Mapping): raise ValueError("unexpected_pull_payload")
    result={"kind":"pull_request","number":int(p.get("number") or number),"html_url":text(p.get("html_url")),
            "state":text(p.get("state")),"merged_at":text(p.get("merged_at")) or None,
            "merge_commit_sha":text(p.get("merge_commit_sha")) or None,
            "head_sha":text((p.get("head") or {}).get("sha") if isinstance(p.get("head"),Mapping) else ""),
            "base_sha":text((p.get("base") or {}).get("sha") if isinstance(p.get("base"),Mapping) else "")}
    result["snapshot_sha256"]=canon_hash(result); return result


def release_snapshot(project: str, tag: str, token: str) -> dict[str, Any]:
    encoded=urllib.parse.quote(urllib.parse.unquote(tag),safe="")
    p=api(f"https://api.github.com/repos/{project}/releases/tags/{encoded}",token)
    if not isinstance(p,Mapping): raise ValueError("unexpected_release_payload")
    result={"kind":"release","tag_name":text(p.get("tag_name")),"target_commitish":text(p.get("target_commitish")),
            "published_at":text(p.get("published_at")),"html_url":text(p.get("html_url")),
            "draft":bool(p.get("draft")),"prerelease":bool(p.get("prerelease"))}
    result["snapshot_sha256"]=canon_hash(result); return result


def compare_snapshot(project: str, comparison: str, token: str) -> dict[str, Any]:
    enc=urllib.parse.quote(urllib.parse.unquote(comparison),safe="./-_~")
    p=api(f"https://api.github.com/repos/{project}/compare/{enc}",token)
    if not isinstance(p,Mapping): raise ValueError("unexpected_compare_payload")
    result={"kind":"compare","comparison":comparison,"html_url":text(p.get("html_url")),"status":text(p.get("status")),
            "base_commit_sha":text((p.get("base_commit") or {}).get("sha") if isinstance(p.get("base_commit"),Mapping) else ""),
            "merge_base_sha":text((p.get("merge_base_commit") or {}).get("sha") if isinstance(p.get("merge_base_commit"),Mapping) else ""),
            "total_commits":int(p.get("total_commits") or 0)}
    result["snapshot_sha256"]=canon_hash(result); return result


def ref_snapshot(url: str, project: str, token: str) -> dict[str, Any] | None:
    for regex, fn in (
        (COMMIT_RE, lambda m: commit_snapshot(project,m.group(3),token)),
        (PULL_RE, lambda m: pull_snapshot(project,m.group(3),token)),
        (RELEASE_RE, lambda m: release_snapshot(project,m.group(3),token)),
        (COMPARE_RE, lambda m: compare_snapshot(project,m.group(3),token)),
    ):
        m=regex.match(url)
        if m and f"{m.group(1)}/{m.group(2)}".casefold()==project.casefold():
            r=fn(m); r["reference_url"]=url; return r
    return None


def version_boundaries(snapshot: Mapping[str, Any], global_adv: Mapping[str, Any]) -> list[dict[str,str]]:
    rows=[]
    for source in (snapshot,global_adv):
        for v in source.get("vulnerabilities") or []:
            if not isinstance(v,Mapping): continue
            pkg=v.get("package") if isinstance(v.get("package"),Mapping) else {}
            patched=v.get("first_patched_version")
            if isinstance(patched,Mapping): patched=patched.get("identifier") or patched.get("version")
            patched=patched or v.get("patched_versions")
            row={"ecosystem":text(pkg.get("ecosystem")),"package":text(pkg.get("name")),
                 "vulnerable_version_range":text(v.get("vulnerable_version_range")),"patched_version":text(patched)}
            if any(row.values()) and row not in rows: rows.append(row)
    return rows


def acquire(entry: Mapping[str, Any], token: str) -> dict[str, Any]:
    family=text(entry.get("family")); root=text(entry.get("source_root")); project=text(entry.get("source_project")).casefold()
    snapshot=entry.get("snapshot_payload") if isinstance(entry.get("snapshot_payload"),Mapping) else {}
    try:
        global_adv=api(f"https://api.github.com/advisories/{root}",token)
        if not isinstance(global_adv,Mapping): global_adv={}
        global_error=None
    except Exception as exc:
        global_adv={}; global_error=type(exc).__name__
    candidate_urls=[]
    for url in urls_from(snapshot)+urls_from(global_adv)+[text(x) for x in entry.get("discovered_upstream_links") or []]:
        if url and url not in candidate_urls: candidate_urls.append(url)
    refs=[]; failures=[]
    for url in candidate_urls:
        if len(refs)>=12: break
        try:
            ref=ref_snapshot(url,project,token)
            if ref is not None: refs.append(ref)
        except Exception as exc:
            failures.append({"reference_url":url,"error":type(exc).__name__})
    commits=[x for x in refs if x.get("kind")=="commit" and x.get("sha")]
    pulls=[x for x in refs if x.get("kind")=="pull_request"]
    # Resolve direct PR head/merge commits as additional candidate boundaries.
    known={text(x.get("sha")) for x in commits}
    for pr in pulls:
        for sha in (text(pr.get("merge_commit_sha")),text(pr.get("head_sha"))):
            if sha and sha not in known and len(commits)<8:
                try:
                    c=commit_snapshot(project,sha,token); c["derived_from_pull_request"]=pr.get("html_url"); commits.append(c); known.add(sha)
                except Exception as exc: failures.append({"reference_url":pr.get("html_url"),"derived_sha":sha,"error":type(exc).__name__})
    # Prefer an explicitly referenced commit with exactly one parent and changed files.
    fix=next((c for c in commits if len(c.get("parent_shas") or [])==1 and int(c.get("file_count") or 0)>0),None)
    parent_sha=(fix.get("parent_shas") or [None])[0] if fix else None
    parent=None
    if parent_sha:
        try: parent=commit_snapshot(project,parent_sha,token)
        except Exception as exc: failures.append({"reference_url":fix.get("html_url"),"parent_sha":parent_sha,"error":type(exc).__name__})
    result={
        "family":family,"source_root":root,"source_project":project,
        "audit_fallback_source":bool(entry.get("audit_fallback_source")),
        "family_literal_adjudication_required":bool(entry.get("family_literal_adjudication_required")),
        "canonical_snapshot_sha256":entry.get("snapshot_sha256"),"global_advisory_sha256":canon_hash(global_adv) if global_adv else None,
        "global_advisory_error":global_error,"version_boundaries":version_boundaries(snapshot,global_adv),
        "reference_snapshots":refs,"reference_failure_count":len(failures),"reference_failures":failures,
        "candidate_fix_commit":fix,"candidate_parent_commit":parent,
        "exact_revision_pair_available":bool(fix and parent),
        "changed_test_file_count":int(fix.get("changed_test_file_count") or 0) if fix else 0,
        "scoring_executed":False,"first_blind_consumed":False,"target_contact_performed":False,
    }
    result["boundary_pack_sha256"]=canon_hash(result); return result


def main() -> int:
    freeze=assert_capture_source_freeze()
    research=json.loads(RESEARCH.read_text()); plan=json.loads(PLAN.read_text())
    if research.get("source_assignment_commit")!=freeze["source_assignment_commit"]: raise RuntimeError("research assignment drift")
    if plan.get("source_assignment_commit")!=freeze["source_assignment_commit"]: raise RuntimeError("plan assignment drift")
    if research.get("scoring_executed") is not False or plan.get("scoring_executed") is not False: raise RuntimeError("pre-scoring contract violated")
    entries=[x for x in research.get("entries") or [] if isinstance(x,Mapping)]
    if len(entries)!=EXPECTED: raise RuntimeError(f"source_count:{len(entries)}!=36")
    token=os.environ.get("GITHUB_TOKEN","")
    packs=[]
    for entry in sorted(entries,key=lambda x:text(x.get("family"))): packs.append(acquire(entry,token))
    report={
        "version":VERSION,"rule_version":RULE_VERSION,"evaluation_kind":"fresh_blind_v7_public_boundary_acquisition",
        "source_count":len(packs),"exact_revision_pair_count":sum(bool(x["exact_revision_pair_available"]) for x in packs),
        "sources_with_version_boundary":sum(bool(x["version_boundaries"]) for x in packs),
        "sources_with_changed_tests":sum(int(x["changed_test_file_count"])>0 for x in packs),
        "reference_failure_count":sum(int(x["reference_failure_count"]) for x in packs),
        "literal_adjudication_required_count":sum(bool(x["family_literal_adjudication_required"]) for x in packs),
        "audit_fallback_count":sum(bool(x["audit_fallback_source"]) for x in packs),
        "engine_baseline_commit":freeze["engine_baseline_commit"],"source_assignment_commit":freeze["source_assignment_commit"],
        "scoring_executed":False,"first_blind_consumed":False,"target_contact_performed":False,
    }
    output=dict(report); output["sources"]=packs; output["capture_set_sha256"]=canon_hash(packs)
    OUTPUT.write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    REPORT.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True)); return 0


if __name__=="__main__": raise SystemExit(main())
