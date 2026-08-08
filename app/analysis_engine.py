from __future__ import annotations

import datetime as dt
import json
import math
import re
import statistics
import urllib.parse
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import APP_VERSION, AppPaths, Database, json_dumps, parse_int, sha256_text, utc_now
from bug_candidates import generate_bug_candidates
from candidate_intelligence import analysis_profile, build_candidate_bundles, enhance_candidates, generate_semantic_intelligence
from behavioral_intelligence import generate_behavioral_candidates, generate_behavioral_intelligence
from security_reasoning import apply_security_reasoning, reasoning_regression_gate
from product_platform import platform_sync

ENGINE_VERSION = "5.1.0"
RULE_VERSION = "2026.08.8"

RULES: dict[str, dict[str, Any]] = {
    "evidence-public-200": {"weight": 8, "description": "Public HTTP 200 observation"},
    "evidence-auth-protected": {"weight": -12, "description": "Endpoint appears authentication-protected"},
    "evidence-semantic-js": {"weight": 10, "description": "Semantic JavaScript change"},
    "evidence-raw-only-js": {"weight": -14, "description": "Raw-only JavaScript change"},
    "evidence-sensitive-class": {"weight": 15, "description": "Sensitive endpoint classification"},
    "feedback-noisy-rule": {"weight": -12, "description": "Historically noisy category"},
    "feedback-useful-rule": {"weight": 8, "description": "Historically useful category"},
    "target-anomaly": {"weight": 15, "description": "Unusual volume for target baseline"},
    "business-critical-context": {"weight": 12, "description": "Business-critical application context"},
    "business-marketing-context": {"weight": -6, "description": "Low-sensitivity marketing context"},
}

SENSITIVE_CLASSES = {"admin", "authentication", "authorization", "payment", "personal_data", "internal", "debug", "export", "upload"}
USEFUL_STATES = {"interesting", "reported", "resolved"}
NOISY_STATES = {"false_positive", "ignored", "out_of_scope"}

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "authentication": {
        "title": "Authentication and session review",
        "checks": [
            "Confirm the endpoint and affected host are in scope.",
            "Identify the expected authentication and session mechanism.",
            "Compare documented anonymous and authenticated behavior without accessing another user's data.",
            "Record role, object and session identifiers visible in the client.",
            "Capture minimal reproducible evidence and contradictory evidence.",
        ],
    },
    "authorization": {
        "title": "Authorization boundary review",
        "checks": [
            "Identify object, account, tenant or role identifiers.",
            "Document the expected authorization boundary.",
            "Use only accounts and objects you are explicitly allowed to test.",
            "Compare responses and side effects using the minimum safe request set.",
            "Stop if the test could expose unrelated user data.",
        ],
    },
    "javascript": {
        "title": "JavaScript change review",
        "checks": [
            "Review semantic additions before formatting-only changes.",
            "Inspect new API versions, object identifiers and client-side restrictions.",
            "Link new endpoints to the functions and assets that reference them.",
            "Review source-map evidence and data-flow candidates.",
            "Do not treat a static source/sink match as a confirmed vulnerability.",
        ],
    },
    "endpoint": {
        "title": "Endpoint intelligence review",
        "checks": [
            "Confirm the endpoint is current, in scope and not only historical.",
            "Identify HTTP method, path parameters, query parameters and content type.",
            "Review authentication hints and business context.",
            "Prefer safe passive evidence before active validation.",
            "Record why the endpoint is or is not security-relevant.",
        ],
    },
    "infrastructure": {
        "title": "Infrastructure change review",
        "checks": [
            "Confirm the observation from more than one source where possible.",
            "Review DNS, TLS, IP, service and deployment timing together.",
            "Distinguish temporary availability from a stable exposure.",
            "Check whether the asset is new, reappeared or retired.",
            "Avoid active service testing unless the target policy explicitly permits it.",
        ],
    },
    "general": {
        "title": "General evidence review",
        "checks": [
            "Confirm scope and freshness.",
            "Review supporting and contradicting evidence.",
            "Connect the signal to related assets and historical observations.",
            "State a falsifiable security hypothesis.",
            "Choose the minimum safe next step.",
        ],
    },
}


def _loads(value: Any, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _mapping_candidates(value: Any) -> list[Mapping[str, Any]]:
    """Return mapping candidates from legacy/current JSON shapes.

    Historical alerts may store endpoint classifications as null, a single
    mapping, a list of mappings, or a mixed list. Analysis must never fail
    merely because optional enrichment data is absent or uses an older shape.
    """
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _best_endpoint_classification(details: Mapping[str, Any]) -> Mapping[str, Any]:
    direct = _mapping_candidates(details.get("endpoint_classification"))
    if direct:
        return max(direct, key=lambda item: parse_int(item.get("confidence"), 0))

    summary = details.get("diff_summary")
    if not isinstance(summary, Mapping):
        return {}
    candidates = _mapping_candidates(summary.get("added_endpoints"))
    if not candidates:
        return {}
    return max(candidates, key=lambda item: parse_int(item.get("confidence"), 0))


def _median_mad(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    med = float(statistics.median(values))
    deviations = [abs(value - med) for value in values]
    return med, float(statistics.median(deviations)) if deviations else 0.0


def _anomaly_score(current: float, history: list[float]) -> tuple[float, dict[str, Any]]:
    med, mad = _median_mad(history)
    if len(history) < 3:
        return 0.0, {"sample_count": len(history), "median": med, "mad": mad, "status": "insufficient_history"}
    if mad == 0:
        score = 5.0 if current > med and current >= med + 3 else 0.0
    else:
        score = 0.6745 * (current - med) / mad
    return round(max(0.0, score), 2), {"sample_count": len(history), "median": med, "mad": mad, "robust_z": round(score, 2)}


def _target_run_counts(db: Database, target: str, category: str, exclude_run: str) -> list[float]:
    rows = db.all(
        "SELECT last_run_id,COUNT(*) AS count FROM alerts WHERE target=? AND category=? AND COALESCE(last_run_id,'')<>? GROUP BY last_run_id ORDER BY MAX(last_seen) DESC LIMIT 30",
        (target, category, exclude_run),
    )
    return [float(row["count"] or 0) for row in rows]


def _feedback_stats(db: Database, target: str, category: str) -> dict[str, Any]:
    rows = db.all("SELECT status,COUNT(*) AS count FROM alerts WHERE target=? AND category=? GROUP BY status", (target, category))
    counts = {str(row["status"]): int(row["count"] or 0) for row in rows}
    total = sum(counts.values())
    useful = sum(counts.get(state, 0) for state in USEFUL_STATES)
    noisy = sum(counts.get(state, 0) for state in NOISY_STATES)
    useful_rate = useful / total if total else 0.0
    noisy_rate = noisy / total if total else 0.0
    adjustment = 0
    reason = "No historical analyst feedback"
    if total >= 5 and noisy_rate >= 0.65:
        adjustment = int(RULES["feedback-noisy-rule"]["weight"])
        reason = f"Historical noisy rate is {noisy_rate:.0%} across {total} alerts"
    elif total >= 5 and useful_rate >= 0.45:
        adjustment = int(RULES["feedback-useful-rule"]["weight"])
        reason = f"Historical useful rate is {useful_rate:.0%} across {total} alerts"
    return {"total": total, "useful": useful, "noisy": noisy, "useful_rate": round(useful_rate, 3), "noisy_rate": round(noisy_rate, 3), "adjustment": adjustment, "reason": reason, "states": counts}


def _business_context(target: str, item: str, category: str, tags: Iterable[str]) -> tuple[str, int, list[str]]:
    text = " ".join([target, item, category, *tags]).lower()
    contexts = [
        ("payment", 15, ["payment", "billing", "checkout", "invoice", "card", "wallet"]),
        ("identity", 13, ["identity", "sso", "oauth", "login", "account", "profile"]),
        ("customer_data", 12, ["customer", "user", "address", "profile", "export", "pii"]),
        ("administration", 12, ["admin", "backoffice", "management", "staff"]),
        ("partner_portal", 8, ["partner", "vendor", "supplier", "portal"]),
        ("development", 5, ["staging", "preprod", "uat", "dev", "test"]),
        ("marketing", -6, ["marketing", "campaign", "blog", "press", "static", "cdn"]),
    ]
    for name, adjustment, tokens in contexts:
        matched = [token for token in tokens if token in text]
        if matched:
            return name, adjustment, [f"Matched business-context marker: {token}" for token in matched[:5]]
    return "general", 0, ["No specialized business context matched"]


def _endpoint_schema(value: str, details: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = str(value or details.get("value") or details.get("resolved_url") or "")
    if "@" in endpoint and endpoint.startswith(("endpoint:", "absolute_url:")):
        endpoint = endpoint.split(":", 1)[1].rsplit("@", 1)[0]
    parsed = urllib.parse.urlsplit(endpoint if "://" in endpoint else "https://placeholder.invalid" + (endpoint if endpoint.startswith("/") else "/" + endpoint))
    path = parsed.path or "/"
    path_parameters = re.findall(r"\{([^{}]+)\}|:([A-Za-z_][A-Za-z0-9_]*)", path)
    path_parameters = [a or b for a, b in path_parameters]
    object_identifiers = sorted(set(re.findall(r"(?i)(accountId|userId|customerId|tenantId|orgId|orderId|invoiceId|profileId|objectId|id)", endpoint + " " + json_dumps(details))))
    method = str(details.get("method") or details.get("http_method") or "UNKNOWN").upper()
    query_parameters = sorted(urllib.parse.parse_qs(parsed.query).keys())
    body_fields = details.get("body_fields") if isinstance(details.get("body_fields"), list) else []
    authentication_hints = []
    haystack = json_dumps(details).lower()
    for token in ("authorization", "bearer", "cookie", "session", "csrf", "oauth", "jwt"):
        if token in haystack:
            authentication_hints.append(token)
    return {
        "endpoint": endpoint,
        "method": method,
        "path": path,
        "path_parameters": path_parameters,
        "query_parameters": query_parameters,
        "body_fields": body_fields[:100],
        "object_identifiers": object_identifiers,
        "content_type": str(details.get("content_type") or ""),
        "authentication_hints": authentication_hints,
    }


def _evidence(alert: Mapping[str, Any], details: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, list[str]]:
    item = str(alert.get("item") or "")
    category = str(alert.get("category") or "")
    evidence_for: list[dict[str, Any]] = []
    evidence_against: list[dict[str, Any]] = []
    adjustment = 0
    rules: list[str] = []

    status_code = details.get("status_code")
    if isinstance(details.get("new"), Mapping):
        status_code = details["new"].get("status_code", status_code)
    if status_code == 200:
        weight = int(RULES["evidence-public-200"]["weight"]); adjustment += weight; rules.append("evidence-public-200")
        evidence_for.append({"type": "reachability", "weight": weight, "text": "Public HTTP 200 response observed"})
    if status_code in {401, 403}:
        weight = int(RULES["evidence-auth-protected"]["weight"]); adjustment += weight; rules.append("evidence-auth-protected")
        evidence_against.append({"type": "access_control", "weight": weight, "text": f"Endpoint returned {status_code}, indicating an access-control boundary"})

    if category == "changed_js":
        if details.get("semantic_changed"):
            weight = int(RULES["evidence-semantic-js"]["weight"]); adjustment += weight; rules.append("evidence-semantic-js")
            evidence_for.append({"type": "javascript", "weight": weight, "text": "Semantic JavaScript content changed"})
        else:
            weight = int(RULES["evidence-raw-only-js"]["weight"]); adjustment += weight; rules.append("evidence-raw-only-js")
            evidence_against.append({"type": "javascript", "weight": weight, "text": "Change appears formatting or build-noise only"})

    classification = _best_endpoint_classification(details)
    primary = str(classification.get("primary_category") or "") if isinstance(classification, Mapping) else ""
    if primary in SENSITIVE_CLASSES:
        weight = int(RULES["evidence-sensitive-class"]["weight"]); adjustment += weight; rules.append("evidence-sensitive-class")
        evidence_for.append({"type": "classification", "weight": weight, "text": f"Endpoint classified as {primary}"})

    occurrences = parse_int(alert.get("occurrences"), 1)
    if occurrences >= 5:
        evidence_against.append({"type": "novelty", "weight": -4, "text": f"Signal has repeated {occurrences} times without a stronger analyst decision"})
        adjustment -= 4
    if details.get("reachable") is False:
        evidence_against.append({"type": "reachability", "weight": -8, "text": "Safe validation did not confirm reachability"}); adjustment -= 8
    if details.get("redacted"):
        evidence_for.append({"type": "sensitive_marker", "weight": 8, "text": "A sensitive value pattern was redacted before storage"}); adjustment += 8
    if re.search(r"(?i)(admin|oauth|sso|export|payment|internal|debug|graphql)", item):
        evidence_for.append({"type": "semantic_marker", "weight": 5, "text": "Security-relevant marker appears in the item"}); adjustment += 5
    return evidence_for, evidence_against, adjustment, rules


def _playbook_key(category: str, change_class: str, schema: Mapping[str, Any]) -> str:
    text = f"{category} {change_class} {json_dumps(schema)}".lower()
    if "auth" in text or "session" in text or "login" in text:
        return "authentication"
    if schema.get("object_identifiers") or "authorization" in text:
        return "authorization"
    if "js" in text or "javascript" in text:
        return "javascript"
    if schema.get("endpoint") or "endpoint" in text or "api" in text:
        return "endpoint"
    if any(token in text for token in ("dns", "port", "subdomain", "infrastructure", "tls")):
        return "infrastructure"
    return "general"


def _hypothesis(alert: Mapping[str, Any], details: Mapping[str, Any], schema: Mapping[str, Any], context: str) -> str:
    category = str(alert.get("category") or "signal")
    item = str(alert.get("item") or "the observed item")
    primary = ""
    classification = _best_endpoint_classification(details)
    if classification:
        primary = str(classification.get("primary_category") or "")
    if schema.get("object_identifiers"):
        ids = ", ".join(schema["object_identifiers"][:4])
        return f"The observed endpoint may expose an object-level authorization boundary involving {ids}; this is unverified and should be checked only with authorized test objects."
    if primary in {"admin", "authorization", "authentication", "export", "payment", "personal_data"}:
        return f"A new or changed {primary} capability may have been deployed at {item}; authentication, role and data-boundary enforcement remain unverified."
    if category == "changed_js":
        return f"The JavaScript change at {item} may represent a meaningful client or API deployment; the security relevance depends on the new data flows and endpoints."
    if category in {"new_subdomain", "new_port", "new_live_http", "dns_change", "fingerprint_change"}:
        return f"The infrastructure observation at {item} may represent a new, moved or reactivated service; exposure and ownership should be confirmed from correlated evidence."
    return f"The signal at {item} may represent a security-relevant change in the {context} context; available evidence is not sufficient to confirm a vulnerability."


def _next_action(playbook_key: str, schema: Mapping[str, Any], evidence_against: list[dict[str, Any]]) -> str:
    if schema.get("object_identifiers"):
        return "Document the expected object-authorization boundary and compare only explicitly authorized test objects."
    if playbook_key == "authentication":
        return "Identify the expected authentication and session controls, then compare documented anonymous and authenticated behavior."
    if playbook_key == "javascript":
        return "Review semantic additions, source-map context and static source-to-sink candidates before any active test."
    if playbook_key == "infrastructure":
        return "Confirm the observation from DNS, TLS and HTTP history and wait for stability confirmation if it may be transient."
    if evidence_against:
        return "Review the contradicting evidence first and decide whether the signal should be suppressed, monitored or investigated."
    return "Confirm scope and freshness, connect related evidence, and record the minimum safe verification step."


def _cluster_key(alert: Mapping[str, Any], details: Mapping[str, Any]) -> str:
    item = str(alert.get("item") or "").lower()
    item = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", item)
    item = re.sub(r"\b\d{2,}\b", "{n}", item)
    item = re.sub(r"[?&](?:utm_[^=&]+|cb|cache|timestamp|ts)=[^&]+", "", item)
    item = re.sub(r"[._-][0-9a-f]{8,}(?=\.)", ".{hash}", item)
    classification = _best_endpoint_classification(details)
    primary = str(classification.get("primary_category") or "")
    return sha256_text(json_dumps([alert.get("target"), alert.get("category"), primary, item]))[:24]


def _temporal(alert: Mapping[str, Any]) -> dict[str, Any]:
    first = str(alert.get("first_seen") or "")
    last = str(alert.get("last_seen") or "")
    age_hours = None
    try:
        a = dt.datetime.fromisoformat(first.replace("Z", "+00:00")); b = dt.datetime.fromisoformat(last.replace("Z", "+00:00")); age_hours = round((b-a).total_seconds()/3600, 2)
    except ValueError:
        pass
    return {"first_seen": first, "last_seen": last, "age_hours": age_hours, "occurrences": parse_int(alert.get("occurrences"), 1), "is_recurrent": parse_int(alert.get("occurrences"), 1) > 1}


def _scan_js_intelligence(paths: AppPaths, db: Database, run_id: str, target: str, analysis_id: str) -> dict[str, int]:
    rows = db.all("SELECT url,blob_path,source_map_url,raw_hash FROM js_files WHERE target=? AND (last_run_id=? OR last_changed IS NOT NULL) ORDER BY last_seen DESC LIMIT 500", (target, run_id))
    flow_count = secret_count = source_map_count = 0
    source_patterns = {
        "location.search": re.compile(r"location\.search|URLSearchParams", re.I),
        "location.hash": re.compile(r"location\.hash", re.I),
        "localStorage": re.compile(r"localStorage", re.I),
        "sessionStorage": re.compile(r"sessionStorage", re.I),
        "postMessage": re.compile(r"postMessage|message\.data", re.I),
        "document.cookie": re.compile(r"document\.cookie", re.I),
        "form_input": re.compile(r"FormData|\.value\b|event\.target", re.I),
    }
    sink_patterns = {
        "fetch": re.compile(r"\bfetch\s*\(", re.I),
        "xhr": re.compile(r"XMLHttpRequest|\.open\s*\(", re.I),
        "innerHTML": re.compile(r"innerHTML|outerHTML|insertAdjacentHTML", re.I),
        "eval": re.compile(r"\beval\s*\(|new\s+Function\s*\(", re.I),
        "navigation": re.compile(r"window\.location|location\.href|location\.assign", re.I),
        "websocket": re.compile(r"new\s+WebSocket\s*\(", re.I),
    }
    for row in rows:
        path = Path(str(row["blob_path"] or ""))
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        compact = text[:5_000_000]
        sources = [(name, match.start()) for name, pattern in source_patterns.items() for match in pattern.finditer(compact)]
        sinks = [(name, match.start()) for name, pattern in sink_patterns.items() for match in pattern.finditer(compact)]
        for source_name, source_pos in sources[:200]:
            nearby = [(sink_name, sink_pos) for sink_name, sink_pos in sinks if 0 <= sink_pos-source_pos <= 1600]
            for sink_name, sink_pos in nearby[:10]:
                snippet = compact[max(0, source_pos-160):min(len(compact), sink_pos+220)]
                confidence = 72 if sink_pos-source_pos < 500 else 55
                db.execute(
                    "INSERT OR REPLACE INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (analysis_id,target,run_id,row["url"],source_name,sink_name,confidence,snippet,utc_now()),
                )
                flow_count += 1
        if row["source_map_url"]:
            indicators = db.all("SELECT value FROM js_indicators WHERE target=? AND js_url=? AND kind='source_map_source' LIMIT 5000", (target,row["url"]))
            names = [str(value["value"]) for value in indicators]
            internal = [name for name in names if re.search(r"(?i)(src/|internal|admin|auth|payment|checkout|graphql|api)", name)]
            db.execute(
                "INSERT OR REPLACE INTO source_map_intelligence(analysis_id,target,run_id,js_url,source_map_url,source_count,internal_source_count,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (analysis_id,target,run_id,row["url"],row["source_map_url"],len(names),len(internal),json_dumps(internal[:200]),utc_now()),
            ); source_map_count += 1
    secret_rows = db.all("SELECT js_url,kind,value,redacted FROM js_indicators WHERE target=? AND last_run_id=? AND (redacted=1 OR kind='sensitive_marker')", (target,run_id))
    for row in secret_rows:
        value = str(row["value"] or "")
        placeholder = bool(re.search(r"(?i)(example|sample|placeholder|changeme|dummy|test|xxxx)", value))
        confidence = 25 if placeholder else 70 if row["redacted"] else 55
        reasons = ["Known placeholder marker" if placeholder else "Sensitive-pattern indicator extracted from JavaScript", "Stored value is redacted" if row["redacted"] else "Value was not marked redacted"]
        db.execute(
            "INSERT OR REPLACE INTO secret_intelligence(analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (analysis_id,target,run_id,row["js_url"],row["kind"],sha256_text(value)[:20],confidence,"likely_placeholder" if placeholder else "candidate",json_dumps(reasons),utc_now()),
        ); secret_count += 1
    return {"dataflows": flow_count, "source_maps": source_map_count, "secrets": secret_count}


def _graphql_intelligence(db: Database, analysis_id: str, target: str, run_id: str) -> int:
    rows = db.all("SELECT js_url,value FROM js_indicators WHERE target=? AND last_run_id=? AND kind='graphql_operation'", (target,run_id))
    count = 0
    for row in rows:
        operation = str(row["value"])
        operation_type = "mutation" if operation.lower().startswith("mutation") else "query" if operation.lower().startswith("query") else "operation"
        identifiers = sorted(set(re.findall(r"(?i)\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID))\b", operation)))
        sensitive = sorted(set(token for token in ("user", "account", "payment", "admin", "export", "token", "role") if token in operation.lower()))
        confidence = min(95, 60 + len(identifiers)*8 + len(sensitive)*5)
        db.execute(
            "INSERT OR REPLACE INTO graphql_intelligence(analysis_id,target,run_id,js_url,operation_name,operation_type,identifiers_json,sensitive_fields_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (analysis_id,target,run_id,row["js_url"],operation[:500],operation_type,json_dumps(identifiers),json_dumps(sensitive),confidence,utc_now()),
        ); count += 1
    return count


def _api_relationships(db: Database, analysis_id: str, target: str, run_id: str) -> int:
    rows = db.all("SELECT endpoint,kind,primary_category,confidence,sources_json FROM endpoint_intelligence WHERE target=? AND last_run_id=?", (target,run_id))
    parsed: list[tuple[str,str,str]] = []
    for row in rows:
        endpoint = str(row["endpoint"])
        value = urllib.parse.urlsplit(endpoint if "://" in endpoint else "https://placeholder.invalid" + (endpoint if endpoint.startswith("/") else "/"+endpoint))
        segments = [segment for segment in value.path.split("/") if segment]
        prefix = "/" + "/".join(segments[:2]) if segments else "/"
        parsed.append((endpoint,prefix,str(row["primary_category"])))
    groups: dict[tuple[str,str], list[str]] = defaultdict(list)
    for endpoint,prefix,category in parsed:
        groups[(prefix,category)].append(endpoint)
    count=0
    for (prefix,category), endpoints in groups.items():
        if len(endpoints)<2: continue
        for left,right in zip(sorted(endpoints),sorted(endpoints)[1:]):
            db.execute("INSERT OR REPLACE INTO api_relationships(analysis_id,target,run_id,source_endpoint,relation,destination_endpoint,confidence,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(analysis_id,target,run_id,left,"same_api_family",right,80,json_dumps({"prefix":prefix,"category":category}),utc_now())); count+=1
    return count


def _deployment_signatures(db: Database, analysis_id: str, target: str, run_id: str) -> int:
    incidents=db.all("SELECT * FROM change_incidents WHERE target=? AND last_run_id=?",(target,run_id)); count=0
    for incident in incidents:
        events=db.all("SELECT category,item FROM incident_events WHERE incident_id=?",(incident["id"],))
        categories=Counter(str(row["category"]) for row in events)
        signature=sha256_text(json_dumps([target,sorted(categories.items()),[str(row["item"]) for row in events][:100]]))[:24]
        db.execute("INSERT OR REPLACE INTO deployment_signatures(analysis_id,target,run_id,incident_id,signature,affected_items_json,change_summary_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(analysis_id,target,run_id,incident["id"],signature,json_dumps([str(row["item"]) for row in events][:500]),json_dumps(dict(categories)),min(95,50+len(events)*5),utc_now())); count+=1
    return count


def _quality_snapshot(db: Database, analysis_id: str, target: str | None = None) -> dict[str, Any]:
    where=" WHERE target=?" if target else ""; params=(target,) if target else ()
    rows=db.all(f"SELECT category,status,COUNT(*) AS count FROM alerts{where} GROUP BY category,status",params)
    by_category: dict[str,Counter[str]]=defaultdict(Counter)
    for row in rows: by_category[str(row["category"])][str(row["status"])]=int(row["count"])
    total=sum(sum(counter.values()) for counter in by_category.values()); useful=sum(sum(counter[state] for state in USEFUL_STATES) for counter in by_category.values()); noisy=sum(sum(counter[state] for state in NOISY_STATES) for counter in by_category.values())
    unresolved=db.one(f"SELECT COUNT(*) AS count FROM alerts{where + (' AND ' if where else ' WHERE ') }status IN ('new','triaged','acknowledged','investigating')",params)
    metrics={"alerts":total,"useful":useful,"noisy":noisy,"precision_proxy":round(useful/max(1,useful+noisy),3),"false_positive_proxy":round(noisy/max(1,total),3),"unreviewed_backlog":int(unresolved["count"] if unresolved else 0),"categories":{category:dict(counter) for category,counter in by_category.items()}}
    db.execute("INSERT INTO analysis_quality_snapshots(analysis_id,target,metrics_json,created_at) VALUES(?,?,?,?)",(analysis_id,target or "*",json_dumps(metrics),utc_now()))
    return metrics


def _run_analysis_impl(paths: AppPaths, db: Database, run_id: str, target: str | None = None, *, mode: str = "analysis", persist: bool = True, profile: str | None = None) -> dict[str, Any]:
    profile = profile or analysis_profile()
    analysis_id=f"analysis-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    started=utc_now()
    db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at) VALUES(?,?,?,?,?,?,?,?)",(analysis_id,run_id,target or "*",ENGINE_VERSION,RULE_VERSION,mode,"running",started))
    for rule_id, rule in RULES.items():
        db.execute("INSERT OR REPLACE INTO analysis_rules(rule_id,rule_version,category,weight,enabled,description,created_at) VALUES(?,?,?,?,1,?,?)",(rule_id,RULE_VERSION,rule_id.split('-',1)[0],int(rule["weight"]),str(rule["description"]),started))
    params:[Any]=[run_id]; where="last_run_id=?"
    if target: where+=" AND target=?"; params.append(target)
    alerts=db.all(f"SELECT * FROM alerts WHERE {where} ORDER BY risk_score DESC,id",tuple(params))
    if not alerts:
        db.execute("UPDATE analysis_runs SET status='success',finished_at=?,summary_json=? WHERE id=?",(utc_now(),json_dumps({"alerts":0}),analysis_id)); return {"analysis_id":analysis_id,"run_id":run_id,"alerts":0,"message":"No alerts found for run"}
    category_counts=Counter(str(row["category"]) for row in alerts)
    cluster_members: dict[str,list[int]]=defaultdict(list)
    adjusted_scores=[]
    for row in alerts:
        alert=dict(row); details=_loads(alert.get("details_json"),{})
        evidence_for,evidence_against,evidence_adjust,rules=_evidence(alert,details)
        feedback=_feedback_stats(db,str(alert["target"]),str(alert["category"]))
        history=_target_run_counts(db,str(alert["target"]),str(alert["category"]),run_id)
        anomaly,baseline=_anomaly_score(float(category_counts[str(alert["category"])]),history)
        anomaly_adjust=min(15,int(round(anomaly*3))) if anomaly>=2 else 0
        if anomaly_adjust: evidence_for.append({"type":"target_anomaly","weight":anomaly_adjust,"text":f"Category volume is unusual for target baseline (robust z={anomaly})"}); rules.append("target-anomaly")
        tags=[str(tag["tag"]) for tag in db.all("SELECT tag FROM entity_tags WHERE target=? AND entity_type IN ('alert','asset','endpoint') AND entity_value IN (?,?)",(alert["target"],str(alert["id"]),str(alert.get("item") or "")))]
        business_context,business_adjust,business_reasons=_business_context(str(alert["target"]),str(alert.get("item") or ""),str(alert["category"]),tags)
        schema=_endpoint_schema(str(alert.get("item") or ""),details)
        change_class=str(details.get("change_class") or alert.get("category") or "")
        playbook_key=_playbook_key(str(alert["category"]),change_class,schema)
        hypothesis=_hypothesis(alert,details,schema,business_context)
        next_action=_next_action(playbook_key,schema,evidence_against)
        adjusted=max(0,min(100,parse_int(alert["risk_score"],0)+evidence_adjust+int(feedback["adjustment"])+anomaly_adjust+business_adjust))
        confidence=max(10,min(99,45+len(evidence_for)*9-len(evidence_against)*4+min(20,parse_int(alert.get("occurrences"),1)*2)))
        cluster=_cluster_key(alert,details); cluster_members[cluster].append(int(alert["id"])); temporal=_temporal(alert)
        db.execute(
            "INSERT OR REPLACE INTO analysis_results(analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,hypothesis,next_action,playbook_id,business_context,evidence_for_json,evidence_against_json,anomaly_score,baseline_json,feedback_json,duplicate_cluster,rule_ids_json,temporal_json,endpoint_schema_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (analysis_id,alert["id"],alert["target"],run_id,alert["category"],alert["risk_score"],adjusted,confidence,hypothesis,next_action,playbook_key,business_context,json_dumps(evidence_for),json_dumps(evidence_against),anomaly,json_dumps(baseline),json_dumps(feedback),cluster,json_dumps(rules),json_dumps(temporal),json_dumps(schema),utc_now()),
        )
        db.execute("INSERT OR REPLACE INTO endpoint_schemas(analysis_id,target,source_run_id,alert_id,endpoint,method,path_parameters_json,query_parameters_json,body_fields_json,object_identifiers_json,auth_hints_json,content_type,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(analysis_id,alert["target"],run_id,alert["id"],schema["endpoint"],schema["method"],json_dumps(schema["path_parameters"]),json_dumps(schema["query_parameters"]),json_dumps(schema["body_fields"]),json_dumps(schema["object_identifiers"]),json_dumps(schema["authentication_hints"]),schema["content_type"],utc_now()))
        db.execute("INSERT OR REPLACE INTO business_contexts(analysis_id,target,entity_type,entity_value,context,adjustment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(analysis_id,alert["target"],"alert",str(alert["id"]),business_context,business_adjust,json_dumps(business_reasons),utc_now()))
        adjusted_scores.append(adjusted)
    for cluster,members in cluster_members.items():
        primary=max(members,key=lambda alert_id: next(parse_int(row["risk_score"],0) for row in alerts if int(row["id"])==alert_id))
        db.execute("INSERT OR REPLACE INTO analysis_clusters(analysis_id,cluster_key,primary_alert_id,member_count,members_json,created_at) VALUES(?,?,?,?,?,?)",(analysis_id,cluster,primary,len(members),json_dumps(members),utc_now()))
    targets=sorted({str(row["target"]) for row in alerts})
    static={"dataflows":0,"source_maps":0,"secrets":0,"graphql":0,"api_relationships":0,"deployments":0}
    for current_target in targets:
        scan=_scan_js_intelligence(paths,db,run_id,current_target,analysis_id)
        for key,value in scan.items(): static[key]+=value
        static["graphql"]+=_graphql_intelligence(db,analysis_id,current_target,run_id)
        static["api_relationships"]+=_api_relationships(db,analysis_id,current_target,run_id)
        static["deployments"]+=_deployment_signatures(db,analysis_id,current_target,run_id)
    semantic = generate_semantic_intelligence(paths, db, analysis_id, run_id, targets)
    behavioral = generate_behavioral_intelligence(paths, db, analysis_id, run_id, targets)
    candidate_summary=generate_bug_candidates(db,analysis_id,run_id,target)
    behavioral_candidates=generate_behavioral_candidates(db,analysis_id,run_id)
    reliability=enhance_candidates(db,analysis_id,profile)
    security_reasoning=apply_security_reasoning(db,analysis_id)
    security_reasoning["regression_gate"] = reasoning_regression_gate(db,analysis_id,persist=True)
    build_candidate_bundles(db,analysis_id)
    product_platform = platform_sync(paths, db, analysis_id)
    try:
        from core import Config
        from workspace_v7 import workspace_v7_sync
        workspace_v7 = workspace_v7_sync(paths, Config(paths), db, target=target or "", actor="analysis")
    except Exception as exc:
        # Workspace intelligence is advisory and must never make the core analysis fail.
        workspace_v7 = {
            "version": APP_VERSION,
            "status": "degraded",
            "error_type": type(exc).__name__,
            "error": str(exc)[:300],
        }
    total_candidates=db.one("SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=?",(analysis_id,))
    strong_candidates=db.one("SELECT COUNT(*) count FROM bug_candidates WHERE analysis_id=? AND candidate_state='strong_candidate'",(analysis_id,))
    candidate_summary["total"] = int(total_candidates["count"] if total_candidates else 0)
    candidate_summary["from_behavioral_intelligence"] = sum(behavioral_candidates.values())
    candidate_summary["strong_candidates"] = int(strong_candidates["count"] if strong_candidates else 0)
    candidate_summary["reliability"] = reliability
    candidate_summary["semantic_intelligence"] = semantic
    candidate_summary["behavioral_candidates"] = behavioral_candidates
    candidate_summary["behavioral_intelligence"] = behavioral
    candidate_summary["security_reasoning"] = security_reasoning
    candidate_summary["product_platform"] = product_platform
    candidate_summary["workspace_v7"] = workspace_v7
    quality=_quality_snapshot(db,analysis_id,target)
    summary={"alerts":len(alerts),"analysis_profile":profile,"average_original_score":round(sum(parse_int(row["risk_score"],0) for row in alerts)/len(alerts),2),"average_adjusted_score":round(sum(adjusted_scores)/len(adjusted_scores),2),"clusters":len(cluster_members),"duplicate_members":sum(max(0,len(values)-1) for values in cluster_members.values()),"static_intelligence":static,"bug_candidates":candidate_summary,"quality":quality}
    previous=db.one("SELECT id,summary_json FROM analysis_runs WHERE source_run_id=? AND id<>? AND status='success' ORDER BY finished_at DESC LIMIT 1",(run_id,analysis_id))
    if previous:
        old=_loads(previous["summary_json"],{}); comparison={"previous_analysis_id":previous["id"],"alert_delta":summary["alerts"]-parse_int(old.get("alerts"),0),"cluster_delta":summary["clusters"]-parse_int(old.get("clusters"),0),"average_score_delta":round(summary["average_adjusted_score"]-float(old.get("average_adjusted_score") or 0),2)}
        summary["replay_comparison"]=comparison
        db.execute("INSERT INTO analysis_replays(analysis_id,previous_analysis_id,source_run_id,comparison_json,created_at) VALUES(?,?,?,?,?)",(analysis_id,previous["id"],run_id,json_dumps(comparison),utc_now()))
    db.execute("UPDATE analysis_runs SET status='success',finished_at=?,summary_json=? WHERE id=?",(utc_now(),json_dumps(summary),analysis_id))
    db.audit("analysis_completed",target=target or "*",entity_type="run",entity_value=run_id,details={"analysis_id":analysis_id,"engine_version":ENGINE_VERSION,"summary":summary})
    return {"analysis_id":analysis_id,"run_id":run_id,"engine_version":ENGINE_VERSION,"rule_version":RULE_VERSION,**summary}


def run_analysis(paths: AppPaths, db: Database, run_id: str, target: str | None = None, *, mode: str = "analysis", persist: bool = True, profile: str | None = None) -> dict[str, Any]:
    """Run analysis and always finalize the analysis-run state.

    Stabilization wrapper: older versions could leave a row permanently marked
    ``running`` when a parser or legacy-data edge case raised unexpectedly.
    Partial evidence is preserved for debugging, while the run is marked failed
    with a bounded error message and audit entry.
    """
    try:
        return _run_analysis_impl(paths, db, run_id, target, mode=mode, persist=persist, profile=profile)
    except Exception as exc:
        row = db.one(
            "SELECT id FROM analysis_runs WHERE source_run_id=? AND target=? AND engine_version=? AND status='running' ORDER BY started_at DESC LIMIT 1",
            (run_id, target or "*", ENGINE_VERSION),
        )
        analysis_id = str(row["id"]) if row else ""
        error = f"{type(exc).__name__}: {exc}"[:4000]
        if analysis_id:
            db.execute(
                "UPDATE analysis_runs SET status='failed',finished_at=?,error=? WHERE id=? AND status='running'",
                (utc_now(), error, analysis_id),
            )
        try:
            db.audit(
                "analysis_failed",
                target=target or "*",
                entity_type="run",
                entity_value=run_id,
                details={"analysis_id": analysis_id, "engine_version": ENGINE_VERSION, "error": error},
            )
        except Exception:
            pass
        raise


def replay_analysis(paths: AppPaths, db: Database, run_id: str, target: str | None = None, profile: str | None = None) -> dict[str, Any]:
    return run_analysis(paths,db,run_id,target,mode="replay",profile=profile)


def analysis_quality(db: Database, target: str | None = None) -> dict[str, Any]:
    latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
    if not latest:
        return {"message":"No completed analysis run"}
    return _quality_snapshot(db,str(latest["id"]),target)


def calibration_report(db: Database, target: str | None = None) -> dict[str, Any]:
    where=" WHERE r.target=?" if target else ""; params=(target,) if target else ()
    rows=db.all(f"SELECT r.confidence,a.status FROM analysis_results r JOIN alerts a ON a.id=r.alert_id{where}",params)
    buckets={"0-39":[],"40-59":[],"60-79":[],"80-100":[]}
    for row in rows:
        confidence=parse_int(row["confidence"],0); key="0-39" if confidence<40 else "40-59" if confidence<60 else "60-79" if confidence<80 else "80-100"; buckets[key].append(str(row["status"]))
    result={}
    for key,states in buckets.items():
        useful=sum(1 for state in states if state in USEFUL_STATES); noisy=sum(1 for state in states if state in NOISY_STATES); observed=useful/max(1,useful+noisy)
        midpoint={"0-39":0.2,"40-59":0.5,"60-79":0.7,"80-100":0.9}[key]
        result[key]={"count":len(states),"useful":useful,"noisy":noisy,"observed_useful_rate":round(observed,3),"expected_midpoint":midpoint,"calibration_gap":round(observed-midpoint,3),"status":"overconfident" if observed+0.15<midpoint else "underconfident" if observed-0.15>midpoint else "reasonable"}
    return {"target":target or "*","buckets":result}


def feedback_report(db: Database, target: str | None = None) -> dict[str, Any]:
    where = " WHERE target=?" if target else ""
    params = (target,) if target else ()
    rows = db.all(f"SELECT target,category,status,COUNT(*) AS count FROM alerts{where} GROUP BY target,category,status", params)
    grouped: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    for row in rows:
        grouped[str(row["target"])][str(row["category"])][str(row["status"])] = int(row["count"] or 0)
    result: dict[str, Any] = {}
    for current_target, categories in grouped.items():
        result[current_target] = {}
        for category, counts in categories.items():
            total = sum(counts.values())
            useful = sum(counts[state] for state in USEFUL_STATES)
            noisy = sum(counts[state] for state in NOISY_STATES)
            result[current_target][category] = {
                "total": total,
                "useful": useful,
                "noisy": noisy,
                "useful_rate": round(useful / total, 3) if total else 0.0,
                "noisy_rate": round(noisy / total, 3) if total else 0.0,
                "states": dict(counts),
            }
    return {"target": target or "*", "targets": result}

