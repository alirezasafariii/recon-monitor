from __future__ import annotations

"""Mine test identifiers from changed upstream test files without executing code.

Only public fix-revision blobs are read. Source contents are transient and never
persisted. Identifiers are heuristic review candidates, not labels or evidence
of behavior.
"""

import argparse, base64, hashlib, json, os, re, urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

VERSION = "1.0.1"
RULE_VERSION = "2026.08.14.13"
EXPECTED_PAIRS = 66
TEST_PATH = re.compile(r"(^|/)(tests?|specs?|__tests__)(/|$)|[^/]*(test|spec)[._-]", re.I)
TEST_PATTERNS = (
    re.compile(r"\bdef\s+(test_[A-Za-z0-9_]+)\s*\("),
    re.compile(r"\b(?:it|test|describe)\s*\(\s*[\"'`]([^\"'`]{2,160})[\"'`]"),
    re.compile(r"\bfunc\s+(Test[A-Za-z0-9_]+)\s*\("),
    re.compile(r"#\[test\]\s*(?:\r?\n\s*)?(?:pub\s+)?fn\s+([A-Za-z0-9_]+)\s*\("),
    re.compile(r"\bfunction\s+(test[A-Za-z0-9_]+)\s*\("),
)
NEAR = {"valid","normal","benign","safe","allowed","legitimate","unaffected","plain","default","ordinary","without"}
SECURE = {"reject","rejected","deny","denied","block","blocked","sanitize","sanitized","escape","escaped","invalid","forbid","forbidden","prevent","protected"}
POSITIVE = {"exploit","vulnerable","vulnerability","bypass","injection","traversal","xss","ssrf","race","malicious","attack","exposure","leak"}
SECURE_STEMS = ("reject", "den", "block", "sanit", "escap", "invalid", "forbid", "prevent", "protect", "restrict", "disallow")
NEAR_STEMS = ("valid", "normal", "benign", "safe", "allow", "legitim", "unaffect", "ordinary")
POSITIVE_STEMS = ("exploit", "vulnerab", "bypass", "inject", "travers", "malicious", "attack", "expos", "leak")


def text(v: Any) -> str:
    return str(v or "").strip()


def api_json(url: str, token: str) -> Any:
    headers = {"Accept":"application/vnd.github+json","User-Agent":"recon-monitor-rwv1-controls","X-GitHub-Api-Version":"2022-11-28"}
    if token: headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.loads(r.read().decode())


def blob_text(project: str, sha: str, token: str) -> tuple[str,str]:
    p = api_json(f"https://api.github.com/repos/{project}/git/blobs/{sha}", token)
    if not isinstance(p, Mapping) or text(p.get("encoding")) != "base64": raise ValueError("unsupported_blob")
    raw = base64.b64decode(text(p.get("content")).replace("\n", ""))
    if len(raw) > 2_000_000: raise ValueError("blob_too_large")
    return raw.decode("utf-8", errors="replace"), hashlib.sha256(raw).hexdigest()


def identifiers(src: str) -> list[str]:
    out = {text(x)[:180] for pat in TEST_PATTERNS for x in pat.findall(src) if text(x)}
    return sorted(out)


def classify(name: str) -> str:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    tokens = {x for x in re.split(r"[^a-z0-9]+", normalized) if x}
    if tokens & SECURE or any(token.startswith(SECURE_STEMS) for token in tokens): return "secure_control_candidate"
    if tokens & NEAR or any(token.startswith(NEAR_STEMS) for token in tokens): return "near_miss_candidate"
    if tokens & POSITIVE or any(token.startswith(POSITIVE_STEMS) for token in tokens): return "positive_regression_candidate"
    return "unclassified"


def mine_pair(pair: Mapping[str,Any], token: str) -> dict[str,Any]:
    project, root = text(pair.get("source_project")).lower(), text(pair.get("source_root")).upper()
    files, failures, seen = [], [], set()
    for fp in pair.get("file_pairs", []) or []:
        if not isinstance(fp, Mapping): continue
        path, sha = text(fp.get("filename")), text(fp.get("fix_blob_sha"))
        if not path or not sha or sha in seen or not TEST_PATH.search(path): continue
        seen.add(sha)
        try:
            src, content_sha = blob_text(project, sha, token)
            ids = identifiers(src)
            files.append({"path":path,"fix_blob_sha":sha,"content_sha256":content_sha,"identifiers":[{"identifier":i,"classification":classify(i),"classification_is_final":False} for i in ids],"source_content_persisted":False})
        except Exception as exc:
            failures.append({"path":path,"error":type(exc).__name__})
    counts = Counter(i["classification"] for f in files for i in f["identifiers"])
    return {"source_root":root,"source_project":project,"family_target":pair.get("family_target"),"revision_pair_sha256":pair.get("revision_pair_sha256"),"test_file_count":len(files),"test_identifier_count":sum(len(f["identifiers"]) for f in files),"classification_counts":dict(sorted(counts.items())),"near_miss_candidate_count":counts["near_miss_candidate"],"secure_control_candidate_count":counts["secure_control_candidate"],"positive_regression_candidate_count":counts["positive_regression_candidate"],"failure_count":len(failures),"failures":failures,"test_files":files,"human_verified":False,"classification_is_final":False,"source_contents_persisted":False,"third_party_code_executed":False,"scoring_executed":False,"target_contact_performed":False}


def mine_all(pairs: list[dict[str,Any]], token: str) -> dict[str,Any]:
    if len(pairs) != EXPECTED_PAIRS: raise ValueError(f"pair_count:{len(pairs)}!=66")
    rows, failures = [], []
    for p in sorted(pairs, key=lambda x:(text(x.get("source_root")), text(x.get("source_project")))):
        try: rows.append(mine_pair(p, token))
        except Exception as exc: failures.append({"source_root":text(p.get("source_root")),"error":type(exc).__name__})
    totals = Counter()
    for row in rows: totals.update(row["classification_counts"])
    gates = {"all_pairs_processed":len(rows)==66 and not failures,"no_source_contents_persisted":all(not r["source_contents_persisted"] for r in rows),"no_code_executed":all(not r["third_party_code_executed"] for r in rows),"no_labels":all(not r["human_verified"] for r in rows),"no_scoring":all(not r["scoring_executed"] for r in rows),"no_target_contact":all(not r["target_contact_performed"] for r in rows)}
    return {"version":VERSION,"rule_version":RULE_VERSION,"evaluation_kind":"real_world_corpus_v1_upstream_test_control_mining","passed":all(gates.values()),"gates":gates,"processed_pair_count":len(rows),"failure_count":len(failures),"failures":failures,"sources_with_changed_test_files":sum(r["test_file_count"]>0 for r in rows),"sources_with_near_miss_test_candidates":sum(r["near_miss_candidate_count"]>0 for r in rows),"sources_with_secure_control_test_candidates":sum(r["secure_control_candidate_count"]>0 for r in rows),"test_file_count":sum(r["test_file_count"] for r in rows),"test_identifier_count":sum(r["test_identifier_count"] for r in rows),"classification_counts":dict(sorted(totals.items())),"human_verified_record_count":0,"source_contents_persisted":False,"third_party_code_executed":False,"scoring_executed":False,"target_contact_performed":False,"sources":rows}


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--revision-evidence",default="benchmarks/real_world/v1/revision_pair_evidence.json"); ap.add_argument("--output",default="benchmarks/real_world/v1/upstream_control_evidence.json"); ap.add_argument("--report",default="benchmarks/real_world/v1/upstream_control_evidence_report.json"); args=ap.parse_args()
    payload=json.loads(Path(args.revision_evidence).read_text()); result=mine_all([dict(x) for x in payload["revision_pairs"]], os.environ.get("GITHUB_TOKEN", "")); Path(args.output).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); Path(args.report).write_text(json.dumps({k:v for k,v in result.items() if k!="sources"},indent=2,sort_keys=True)+"\n"); print(json.dumps({"ok":result["passed"],"pairs":result["processed_pair_count"],"sources_with_tests":result["sources_with_changed_test_files"],"near":result["sources_with_near_miss_test_candidates"],"secure":result["sources_with_secure_control_test_candidates"],"identifiers":result["test_identifier_count"]},sort_keys=True)); return 0 if result["passed"] else 1

if __name__ == "__main__": raise SystemExit(main())
