from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from raw_recon_corpus import ROOT

SRC = ROOT / "benchmarks/raw/sources"
SOURCE = SRC / "v6_literal_source_research.json"
LINKED = SRC / "v6_literal_linked_research.json"
MANIFEST = SRC / "v6_remaining_capture_manifest.json"

REMAINING = {
    "authentication_session": ("authentication", "session", "ntlm", "authenticated user"),
    "dom_xss": ("xss", "javascript", "sanit", "v-html", "entity"),
    "file_upload": ("upload", "php", "extension", "webshell", "file"),
    "improper_inventory_management": ("old api", "older api", "legacy", "version", "deprecated"),
    "ldap_injection": ("ldap", "username", "filter", "injection"),
    "open_redirect": ("redirect", "location", "external", "url parameter", "phishing"),
    "race_condition": ("race", "concurrent", "timing", "privilege", "state"),
    "secret_exposure": ("hardcoded", "token", "secret", "credential"),
    "security_logging_alerting_failure": ("password", "log", "trace", "plaintext", "sensitive"),
    "security_misconfiguration": ("configuration", "error", "debug", "header", "insecure"),
    "server_side_template_injection": ("twig", "template", "expression", "sandbox", "render"),
    "sql_injection": ("sql", "database", "commentlist", "id parameter", "inject"),
    "unrestricted_resource_consumption": ("resource", "queue", "denial of service", "dos", "resize"),
    "unsafe_api_consumption": ("redirect", "cross-origin", "cookie", "proxy-authorization", "http client", "response"),
}

SURFACE = {
    "authentication_session": ("session negotiation", [], [], [], ["session"]),
    "dom_xss": ("browser rendering", [], [], [], []),
    "file_upload": ("file upload", [], ["file"], [], []),
    "improper_inventory_management": ("legacy api version", [], [], [], []),
    "ldap_injection": ("directory login", [], ["username"], [], []),
    "open_redirect": ("logout navigation", ["url"], [], [], []),
    "race_condition": ("privileged state transition", [], [], [], []),
    "secret_exposure": ("application source secret", [], [], [], []),
    "security_logging_alerting_failure": ("trace logging", [], [], [], []),
    "security_misconfiguration": ("deployed configuration", [], [], [], []),
    "server_side_template_injection": ("server template rendering", [], ["template"], [], []),
    "sql_injection": ("database query", ["id"], [], [], []),
    "unrestricted_resource_consumption": ("queue allocation", ["size"], [], [], []),
    "unsafe_api_consumption": ("third-party http client", [], [], [], []),
}

SECURE_PATH_MARKERS = ("patched_version", "patched_versions", "first_patched_version", "unaffected", "fixed_version", "fixed_versions")
SECURE_TEXT = (
    "patched in", "fixed in", "is fixed", "was fixed", "has been fixed", "unaffected",
    "not affected", "rejects", "rejected", "denies", "denied", "returns 403",
    "requires authentication", "not enabled by default", "disabled by default",
    "resolved in", "no longer", "prevents", "is restricted to", "only allows",
)
NORMATIVE_ONLY = ("should ", "should be", "recommend", "remediation", "would ", "could mitigate", "workaround", "acceptance criteria", "proposed")
NEAR_TEXT = ("requires", "prerequisite", "affected", "only", "scope", "version", "configuration", "default", "user interaction", "local attacker", "authenticated")


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def clean(value: str) -> str:
    value = html.unescape(value)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def chunks(value: str) -> list[str]:
    text = clean(value)
    if len(text) < 8:
        return [text] if text else []
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if 8 <= len(p.strip()) <= 2500] or [text[:2500]]


def walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from walk(child, path + (str(key),))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from walk(child, path + (str(i),))
    elif isinstance(value, str):
        for text in chunks(value):
            yield ".".join(path), text


def rows(source: Mapping[str, Any], linked: Mapping[str, Any], forbidden: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    def add(payload: Any, reference: str, digest: str, rtype: str, weight: int) -> None:
        for path, text in walk(payload):
            lower = text.casefold()
            if any(marker.casefold() in lower for marker in forbidden if marker):
                continue
            out.append({"path": path, "text": text, "reference": reference, "snapshot_sha256": digest, "resource_type": rtype, "weight": weight})
    add(source.get("snapshot_payload"), str(source.get("canonical_reference") or ""), str(source.get("snapshot_sha256") or ""), "canonical", 2)
    for item in linked.get("linked_resources") or []:
        if not isinstance(item, Mapping) or item.get("fetch_status") != 200 or item.get("snapshot_payload") is None:
            continue
        rtype = str(item.get("resource_type") or "linked")
        add(item.get("snapshot_payload"), str(item.get("reference") or ""), str(item.get("snapshot_sha256") or ""), rtype, 6 if rtype in {"commit", "pull_request"} else 4)
    unique: dict[str, dict[str, Any]] = {}
    for row in out:
        key = sha(row["text"])
        if key not in unique or row["weight"] > unique[key]["weight"]:
            unique[key] = row
    return list(unique.values())


def term_count(text: str, terms: Iterable[str]) -> int:
    lower = text.casefold()
    return sum(1 for term in terms if term.casefold() in lower)


def choose_positive(family: str, values: list[dict[str, Any]], used: set[str]) -> dict[str, Any] | None:
    choices = [r for r in values if sha(r["text"]) not in used]
    choices.sort(key=lambda r: (term_count(r["text"], REMAINING[family]) * 30 + r["weight"] + (12 if any(k in r["path"].casefold() for k in ("body","description","summary")) else 0), len(r["text"])), reverse=True)
    return choices[0] if choices and term_count(choices[0]["text"], REMAINING[family]) >= 2 else None


def secure_strength(row: Mapping[str, Any]) -> int:
    path = str(row["path"]).casefold(); text = str(row["text"]).casefold()
    path_hit = any(marker in path for marker in SECURE_PATH_MARKERS)
    text_hits = term_count(text, SECURE_TEXT)
    normative = any(marker in text for marker in NORMATIVE_ONLY)
    if path_hit:
        return 100 + int(row["weight"])
    if text_hits and not normative:
        return text_hits * 30 + int(row["weight"])
    # A sentence can contain a remediation heading and still assert an already-fixed
    # version; require an explicit completed-state word in that case.
    if text_hits and normative and any(x in text for x in ("patched in", "fixed in", "has been fixed", "resolved in", "unaffected")):
        return text_hits * 20 + int(row["weight"])
    return 0


def choose_secure(values: list[dict[str, Any]], used: set[str]) -> dict[str, Any] | None:
    choices = [r for r in values if sha(r["text"]) not in used and secure_strength(r) > 0]
    choices.sort(key=lambda r: (secure_strength(r), len(r["text"])), reverse=True)
    return choices[0] if choices else None


def choose_near(values: list[dict[str, Any]], used: set[str]) -> dict[str, Any] | None:
    choices = [r for r in values if sha(r["text"]) not in used]
    choices.sort(key=lambda r: (term_count(r["text"], NEAR_TEXT) * 12 + r["weight"], len(r["text"])), reverse=True)
    return choices[0] if choices else None


def emit(out: Path, family: str, source: Mapping[str, Any], kind: str, selected: Mapping[str, Any] | None, signal: str) -> None:
    context, query, body, path_params, auth = SURFACE[family]
    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if selected is None:
        payload = source.get("snapshot_payload") if isinstance(source.get("snapshot_payload"), Mapping) else {}
        meta = {key: payload.get(key) for key in ("published_at","updated_at","severity","type","cve_id","ghsa_id") if payload.get(key) is not None}
        reference = str(source.get("canonical_reference") or "")
        snapshot = {"literal_metadata": meta, "upstream_snapshot_sha256": source.get("snapshot_sha256")}
        details = {"capture_environment":"sealed passive public-source snapshot; no target contacted","observation_variant":kind,"source_metadata":meta}
    else:
        reference = str(selected["reference"])
        snapshot = {"literal_excerpt":selected["text"],"source_path":selected["path"],"resource_type":selected["resource_type"],"upstream_snapshot_sha256":selected["snapshot_sha256"]}
        details = {"capture_environment":"sealed passive public-source snapshot; no target contacted","observation_variant":kind,"response_text":selected["text"],"source_path":selected["path"],"source_resource_type":selected["resource_type"]}
    token = sha(canonical(snapshot) + family + kind)[:16]
    raw = {"target":"public-source-snapshot.invalid","endpoint":f"/observation/{token}","method":"GET","endpoint_schema":{"query_parameters":list(query),"body_fields":list(body),"path_parameters":list(path_params),"object_identifiers":[],"authentication_hints":list(auth)},"business_context":context,"category":"public source security observation","details":details}
    doc = {
        "family":family,"case_kind":kind,"captured_at":captured_at,"capture_reference":reference,"capture_method":"cli_output",
        "collector":{"tool":"Analysis 6.31 strict sealed-snapshot collector","command":"PYTHONPATH=app python app/v6_remaining_strict_snapshot_collector.py captured","source_file":"v6_literal_source_research.json + v6_literal_linked_research.json"},
        "source_snapshot":{"reference":reference,"retrieved_at":captured_at,"payload":snapshot},
        "adjudication":{"basis":"patched_control" if kind=="secure_negative" else "source_observation","notes":"Source-grounded sealed observation selected without detector, admission, ranking, or scoring output. Secure-negative selection requires explicit fixed/unaffected/implemented-control evidence, not recommendation text.","expected_condition_signals":[signal] if kind=="positive" else [],"detector_output_used":False,"admission_output_used":False,"ranking_output_used":False},
        "raw":raw,
    }
    folder=out/family; folder.mkdir(parents=True,exist_ok=True); (folder/f"{kind}.json").write_text(json.dumps(doc,indent=2,sort_keys=True,ensure_ascii=False)+"\n",encoding="utf-8")


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("output",type=Path); args=parser.parse_args()
    source_doc=json.loads(SOURCE.read_text(encoding="utf-8")); linked_doc=json.loads(LINKED.read_text(encoding="utf-8")); manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
    source_by={str(r.get("family") or ""):r for r in source_doc.get("entries") or []}; linked_by={str(r.get("family") or ""):r for r in linked_doc.get("entries") or []}; manifest_by={str(r.get("family") or ""):r for r in manifest.get("families") or []}
    forbidden=set(source_by)
    for row in manifest_by.values(): forbidden.update(str(v) for v in row.get("condition_signals") or [])
    completed=[]; blocked=[]
    for family in sorted(REMAINING):
        source=source_by[family]; values=rows(source,linked_by.get(family,{}),forbidden); used=set()
        positive=choose_positive(family,values,used)
        if positive: used.add(sha(positive["text"]))
        secure=choose_secure(values,used)
        if secure: used.add(sha(secure["text"]))
        near=choose_near(values,used)
        missing=[name for name,val in (("positive",positive),("secure_negative",secure),("near_miss",near)) if val is None]
        if missing:
            blocked.append({"family":family,"missing":missing,"candidate_count":len(values)})
            continue
        signals=[str(v) for v in manifest_by[family].get("condition_signals") or [] if str(v)]
        if not signals: raise RuntimeError(f"{family}: missing sealed condition signal")
        for kind,selected in (("positive",positive),("near_miss",near),("secure_negative",secure),("sparse_noisy",None)):
            emit(args.output,family,source,kind,selected,signals[0])
        completed.append(family)
    report={"completed_families":completed,"completed_count":len(completed),"evidence_count":len(completed)*4,"blocked":blocked,"blocked_count":len(blocked),"scoring_executed":False,"first_blind_consumed":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
