from __future__ import annotations

"""Pre-score source discovery and exposure firewall for Real-World Corpus V1.

The module only works with public primary-source metadata. It does not contact
vulnerability targets, generate payloads, run Analysis scoring, create target
evidence, or mark records human verified.
"""

import argparse
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from family_reasoning import FAMILY_ORDER

REAL_WORLD_CORPUS_VERSION = "1.0.0"
REAL_WORLD_CORPUS_RULE_VERSION = "2026.08.14.1"
TARGET_SOURCE_ROOTS = 100
TARGET_RECORDS = 400
TARGET_MIN_FAMILIES = 50
VARIANTS_PER_ROOT = 4

EVALUATION_ROLES = frozenset({
    "fresh_candidate",
    "development_only",
    "consumed_benchmark",
    "reserved_blind",
})

HISTORICAL_CORPORA = (
    ("analysis_golden_v3", "agent/analysis-engine-6.0-owasp-admission", "benchmarks/golden/analysis_golden_v3.jsonl", "consumed_benchmark"),
    ("analysis_golden_v4", "agent/analysis-engine-6.6-postfreeze-blind", "benchmarks/golden/analysis_golden_v4.jsonl", "consumed_benchmark"),
    ("analysis_raw_v1", "agent/analysis-engine-6.11-blind-raw-recon-benchmark", "benchmarks/raw/analysis_raw_v1.jsonl", "consumed_benchmark"),
    ("analysis_raw_v2", "agent/analysis-engine-6.13-fresh-raw-holdout-v2", "benchmarks/raw/analysis_raw_v2.jsonl", "consumed_benchmark"),
    ("analysis_raw_v3", "agent/analysis-engine-6.15-fresh-raw-holdout-v3", "benchmarks/raw/analysis_raw_v3.jsonl", "consumed_benchmark"),
    ("analysis_raw_v6", "agent/analysis-engine-6.31-fresh-blind-v6-validation", "benchmarks/raw/sources/v6_shortlist.json", "reserved_blind"),
)

# Discovery hints only. Final family labels require source/human adjudication.
CWE_FAMILY_HINTS = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "dom_xss",
    "CWE-89": "sql_injection",
    "CWE-90": "ldap_injection",
    "CWE-200": "information_disclosure",
    "CWE-203": "account_enumeration",
    "CWE-287": "authentication_session",
    "CWE-294": "authentication_session",
    "CWE-311": "cryptographic_failure",
    "CWE-319": "cryptographic_failure",
    "CWE-327": "cryptographic_failure",
    "CWE-328": "cryptographic_failure",
    "CWE-346": "cors_misconfiguration",
    "CWE-359": "information_disclosure",
    "CWE-362": "race_condition",
    "CWE-400": "unrestricted_resource_consumption",
    "CWE-434": "file_upload",
    "CWE-532": "information_disclosure",
    "CWE-601": "open_redirect",
    "CWE-639": "broken_object_authorization",
    "CWE-770": "unrestricted_resource_consumption",
    "CWE-798": "secret_exposure",
    "CWE-862": "broken_function_authorization",
    "CWE-863": "broken_function_authorization",
    "CWE-915": "mass_assignment",
    "CWE-918": "ssrf",
    "CWE-942": "cors_misconfiguration",
    "CWE-943": "nosql_injection",
    "CWE-1336": "server_side_template_injection",
}

_GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_REPO_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+)", re.I)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    return _text(value).lower().rstrip("/")


def _project(value: Any) -> str:
    text = _text(value)
    match = _REPO_RE.match(text)
    if match:
        text = f"{match.group(1)}/{match.group(2)}"
    if text.endswith(".git"):
        text = text[:-4]
    return text.lower().strip("/")


def _walk(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key), child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def records_from_text(text: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return [json.loads(line) for line in stripped.splitlines() if line.strip()]
    return parsed if isinstance(parsed, list) else [parsed]


def identities_from_records(records: Iterable[Any]) -> dict[str, set[str]]:
    roots: set[str] = set()
    projects: set[str] = set()
    urls: set[str] = set()
    identifiers: set[str] = set()
    for record in records:
        for key, value in _walk(record):
            key = key.lower()
            values = value if isinstance(value, list) else [value]
            if key in {"source_root", "ghsa_id"}:
                roots.update(_text(item).upper() for item in values if _text(item))
            if key in {"source_project", "source_code_location"}:
                projects.update(_project(item) for item in values if _project(item))
            if key in {"url", "canonical_advisory_url", "repository_advisory_url", "source_code_location", "capture_reference", "reference", "references"}:
                for item in values:
                    token = _text(item)
                    if token.startswith("http"):
                        urls.add(_norm(token))
            if key == "identifiers":
                for item in values:
                    if isinstance(item, Mapping):
                        token = _text(item.get("value"))
                        if token:
                            identifiers.add(token.upper())
        blob = json.dumps(record, sort_keys=True)
        roots.update(item.upper() for item in _GHSA_RE.findall(blob))
        identifiers.update(item.upper() for item in _CVE_RE.findall(blob))
    identifiers.update(roots)
    return {"roots": roots, "projects": projects, "urls": urls, "identifiers": identifiers}


def merge_identities(parts: Iterable[Mapping[str, set[str]]]) -> dict[str, set[str]]:
    result = {"roots": set(), "projects": set(), "urls": set(), "identifiers": set()}
    for part in parts:
        for key in result:
            result[key].update(part.get(key, set()))
    return result


def exposure_reasons(candidate: Mapping[str, Any], exposed: Mapping[str, set[str]]) -> list[str]:
    identity = identities_from_records([candidate])
    checks = (
        ("roots", "historical_source_root_overlap"),
        ("projects", "historical_source_project_overlap"),
        ("identifiers", "historical_identifier_overlap"),
        ("urls", "historical_url_overlap"),
    )
    return sorted(reason for key, reason in checks if identity[key] & set(exposed.get(key, set())))


def partition_reviewed_records(records: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Enforce lifecycle roles before any train/holdout hashing or scoring."""
    forced_train, fresh, reserved, rejected = [], [], [], []
    for raw in records:
        row = dict(raw)
        role = _text(row.get("evaluation_role") or "fresh_candidate")
        if role not in EVALUATION_ROLES:
            rejected.append(row)
        elif role in {"development_only", "consumed_benchmark"}:
            forced_train.append(row)
        elif role == "reserved_blind":
            reserved.append(row)
        else:
            fresh.append(row)
    return {
        "forced_train": forced_train,
        "fresh_candidates": fresh,
        "reserved_blind": reserved,
        "rejected": rejected,
    }


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL)


def _ensure_ref(ref: str) -> str:
    remote_ref = f"refs/remotes/origin/{ref}"
    try:
        _git("rev-parse", "--verify", remote_ref)
    except subprocess.CalledProcessError:
        subprocess.check_call(["git", "fetch", "--no-tags", "origin", f"{ref}:{remote_ref}"], stdout=subprocess.DEVNULL)
    return remote_ref


def load_historical_exposure() -> tuple[dict[str, set[str]], list[dict[str, Any]]]:
    parts, reports = [], []
    for name, ref, path, role in HISTORICAL_CORPORA:
        try:
            remote_ref = _ensure_ref(ref)
            records = records_from_text(_git("show", f"{remote_ref}:{path}"))
            identity = identities_from_records(records)
            parts.append(identity)
            reports.append({
                "name": name,
                "ref": ref,
                "path": path,
                "role": role,
                "loaded": True,
                "record_count": len(records),
                "source_root_count": len(identity["roots"]),
                "source_project_count": len(identity["projects"]),
            })
        except Exception as exc:
            reports.append({"name": name, "ref": ref, "path": path, "role": role, "loaded": False, "error": type(exc).__name__})
    return merge_identities(parts), reports


def _api_get(url: str, token: str = "") -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "recon-monitor-real-world-corpus-v1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def normalize_advisory(row: Mapping[str, Any]) -> dict[str, Any]:
    cwes = sorted({_text(item.get("cwe_id") if isinstance(item, Mapping) else item).upper() for item in row.get("cwes", []) if _text(item.get("cwe_id") if isinstance(item, Mapping) else item)})
    canonical = set(str(item) for item in FAMILY_ORDER)
    hints = sorted({CWE_FAMILY_HINTS[cwe] for cwe in cwes if cwe in CWE_FAMILY_HINTS and CWE_FAMILY_HINTS[cwe] in canonical})
    ghsa = _text(row.get("ghsa_id")).upper()
    cve = _text(row.get("cve_id")).upper()
    refs = sorted({_text(item) for item in row.get("references", []) if _text(item).startswith("https://")})
    return {
        "source_root": ghsa,
        "source_project": _project(row.get("source_code_location")),
        "canonical_advisory_url": _text(row.get("html_url")),
        "repository_advisory_url": _text(row.get("repository_advisory_url")),
        "source_code_location": _text(row.get("source_code_location")),
        "identifiers": [item for item in (ghsa, cve) if item],
        "cwes": cwes,
        "family_hints": hints,
        "family_hint_basis": "cwe_only_not_final_adjudication",
        "severity": _text(row.get("severity")).lower(),
        "published_at": _text(row.get("published_at")),
        "updated_at": _text(row.get("updated_at")),
        "references": refs,
        "source_kind": "github_reviewed_advisory",
        "evaluation_role": "fresh_candidate",
        "capture_status": "not_started",
        "human_verified": False,
        "scoring_executed": False,
    }


def discover_candidates(exposed: Mapping[str, set[str]], *, token: str = "", max_pages: int = 10, selection_limit: int = 160) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: Counter[str] = Counter()
    seen_roots, seen_projects = set(), set()
    fetched = 0
    for page in range(1, max_pages + 1):
        query = urllib.parse.urlencode({"per_page": 100, "page": page, "type": "reviewed", "sort": "published", "direction": "desc"})
        rows = _api_get(f"https://api.github.com/advisories?{query}", token=token)
        if not isinstance(rows, list) or not rows:
            break
        fetched += len(rows)
        for raw in rows:
            if not isinstance(raw, Mapping):
                continue
            candidate = normalize_advisory(raw)
            root, project = _text(candidate["source_root"]), _project(candidate["source_project"])
            if not root or not project:
                rejected["missing_root_or_project"] += 1
                continue
            if raw.get("withdrawn_at"):
                rejected["withdrawn"] += 1
                continue
            reasons = exposure_reasons(candidate, exposed)
            if reasons:
                for reason in reasons:
                    rejected[reason] += 1
                continue
            if root in seen_roots:
                rejected["duplicate_new_root"] += 1
                continue
            if project in seen_projects:
                rejected["duplicate_new_project"] += 1
                continue
            seen_roots.add(root)
            seen_projects.add(project)
            accepted.append(candidate)
            if len(accepted) >= selection_limit:
                break
        if len(accepted) >= selection_limit:
            break
    family_counts = Counter(hint for row in accepted for hint in row.get("family_hints", []))
    return {
        "version": REAL_WORLD_CORPUS_VERSION,
        "rule_version": REAL_WORLD_CORPUS_RULE_VERSION,
        "evaluation_kind": "real_world_corpus_v1_pre_score_source_discovery",
        "scoring_executed": False,
        "target_contact_performed": False,
        "human_labels_created": False,
        "fetched_advisory_count": fetched,
        "selected_candidate_count": len(accepted),
        "unique_source_root_count": len(seen_roots),
        "unique_source_project_count": len(seen_projects),
        "family_hint_count": len(family_counts),
        "family_hint_counts": dict(sorted(family_counts.items())),
        "rejected_counts": dict(sorted(rejected.items())),
        "candidates": accepted,
    }


def _write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_discover(args: argparse.Namespace) -> int:
    exposed, reports = load_historical_exposure()
    missing = [item["name"] for item in reports if not item.get("loaded")]
    if missing:
        raise SystemExit("historical_exposure_incomplete:" + ",".join(missing))
    discovery = discover_candidates(exposed, token=args.github_token or os.environ.get("GITHUB_TOKEN", ""), max_pages=args.max_pages, selection_limit=args.selection_limit)
    if int(discovery["selected_candidate_count"]) < TARGET_SOURCE_ROOTS:
        raise SystemExit(f"insufficient_fresh_source_candidates:{discovery['selected_candidate_count']}")
    _write(Path(args.output), discovery)
    report = {
        "version": REAL_WORLD_CORPUS_VERSION,
        "rule_version": REAL_WORLD_CORPUS_RULE_VERSION,
        "status": "source_discovery_complete",
        "target_source_roots": TARGET_SOURCE_ROOTS,
        "target_records": TARGET_RECORDS,
        "target_minimum_families": TARGET_MIN_FAMILIES,
        "variants_per_root": VARIANTS_PER_ROOT,
        "historical_exposure": reports,
        "discovery_summary": {key: value for key, value in discovery.items() if key != "candidates"},
        "next_transition": "source_feasibility_and_family_adjudication",
        "scoring_executed": False,
        "target_contact_performed": False,
    }
    _write(Path(args.report), report)
    print(json.dumps({"ok": True, "selected": discovery["selected_candidate_count"], "projects": discovery["unique_source_project_count"], "family_hints": discovery["family_hint_count"]}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Real-World Corpus V1 pre-score tooling")
    sub = parser.add_subparsers(dest="action", required=True)
    discover = sub.add_parser("discover")
    discover.add_argument("--output", default="benchmarks/real_world/v1/source_candidates.json")
    discover.add_argument("--report", default="benchmarks/real_world/v1/source_discovery_report.json")
    discover.add_argument("--max-pages", type=int, default=10)
    discover.add_argument("--selection-limit", type=int, default=160)
    discover.add_argument("--github-token", default="")
    discover.set_defaults(func=command_discover)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
