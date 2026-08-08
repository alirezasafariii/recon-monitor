from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import urllib.parse
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import AppPaths, Database, json_dumps, parse_int, sha256_text, utc_now

SEMANTIC_ENGINE_VERSION = "5.0.1"
SEMANTIC_RULE_VERSION = "2026.08.8.1"
PROFILES = {
    "quiet": {"minimum_sources": 3, "minimum_evidence": 62, "minimum_likelihood": 50, "stale_days": 21},
    "balanced": {"minimum_sources": 2, "minimum_evidence": 42, "minimum_likelihood": 32, "stale_days": 30},
    "research": {"minimum_sources": 1, "minimum_evidence": 18, "minimum_likelihood": 18, "stale_days": 45},
}

SENSITIVE_KEYS = {
    "email", "phone", "address", "token", "secret", "password", "ssn", "card", "account", "role", "permission",
    "balance", "invoice", "customer", "user", "tenant", "session", "refresh_token", "access_token",
}
OBJECT_IDS = ("tenantId", "orgId", "accountId", "customerId", "userId", "profileId", "orderId", "invoiceId", "objectId", "ownerId", "id")


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def analysis_profile() -> str:
    value = str(os.environ.get("ANALYSIS_PROFILE", "balanced") or "balanced").strip().lower()
    return value if value in PROFILES else "balanced"


def _source_group(item: Mapping[str, Any]) -> str:
    return str(item.get("source_group") or item.get("source") or item.get("type") or "rule").strip().lower()


def independent_evidence(items: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Keep the strongest item in each source group to avoid double counting."""
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in items:
        item = dict(raw)
        group = _source_group(item)
        item["source_group"] = group
        grouped[group].append(item)
    selected: list[dict[str, Any]] = []
    for group, values in grouped.items():
        values.sort(key=lambda value: abs(parse_int(value.get("weight"), 0)), reverse=True)
        strongest = values[0]
        strongest["correlated_signal_count"] = len(values)
        selected.append(strongest)
    selected.sort(key=lambda value: abs(parse_int(value.get("weight"), 0)), reverse=True)
    metadata = {
        "independent_groups": len(grouped),
        "raw_signals": sum(len(values) for values in grouped.values()),
        "groups": {group: len(values) for group, values in grouped.items()},
        "double_counted_signals_suppressed": sum(max(0, len(values) - 1) for values in grouped.values()),
    }
    return selected, metadata


def _json_shape(value: Any, prefix: str = "", depth: int = 0) -> tuple[list[str], dict[str, str]]:
    keys: list[str] = []
    types: dict[str, str] = {}
    if depth > 5:
        return keys, types
    if isinstance(value, Mapping):
        for key, child in list(value.items())[:300]:
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(path)
            types[path] = "object" if isinstance(child, Mapping) else "array" if isinstance(child, list) else type(child).__name__
            child_keys, child_types = _json_shape(child, path, depth + 1)
            keys.extend(child_keys); types.update(child_types)
    elif isinstance(value, list) and value:
        path = f"{prefix}[]" if prefix else "[]"
        types[path] = "array"
        child_keys, child_types = _json_shape(value[0], path, depth + 1)
        keys.extend(child_keys); types.update(child_types)
    return keys, types


def _extract_response_shape(details: Mapping[str, Any]) -> tuple[list[str], dict[str, str], list[str], int]:
    candidates: list[Any] = []
    for key in ("response_json", "response", "body_json", "new", "current", "after"):
        value = details.get(key)
        if isinstance(value, Mapping):
            if key in {"new", "current", "after"}:
                for nested in ("response_json", "response", "body_json", "json"):
                    if isinstance(value.get(nested), (Mapping, list)):
                        candidates.append(value.get(nested))
            else:
                candidates.append(value)
        elif isinstance(value, list):
            candidates.append(value)
    if not candidates:
        raw = details.get("response_body") or details.get("body")
        if isinstance(raw, str) and raw.strip().startswith(("{", "[")):
            parsed = _loads(raw, None)
            if isinstance(parsed, (Mapping, list)):
                candidates.append(parsed)
    if not candidates:
        return [], {}, [], 0
    keys, types = _json_shape(candidates[0])
    sensitive = sorted({key for key in keys if any(token in key.lower() for token in SENSITIVE_KEYS)})
    confidence = _clamp(45 + min(30, len(keys)) + (10 if sensitive else 0), 20, 95)
    return sorted(set(keys)), types, sensitive, confidence


def _auth_boundary(schema: Mapping[str, Any], details: Mapping[str, Any], endpoint: str) -> tuple[str, int, list[dict[str, Any]]]:
    hints = [str(value).lower() for value in schema.get("authentication_hints", []) if value]
    explicit_auth_values = [details.get(key) for key in ("authentication", "auth", "auth_type", "request_headers", "authorization_header", "session_required") if details.get(key) is not None]
    auth_text = " ".join([endpoint, " ".join(hints), json_dumps(explicit_auth_values)]).lower()
    semantic_text = " ".join([endpoint, json_dumps(details), " ".join(hints)]).lower()
    status = details.get("status_code")
    if status is None and isinstance(details.get("new"), Mapping):
        status = details["new"].get("status_code")
    evidence: list[dict[str, Any]] = []
    boundary = "unknown"; confidence = 25
    if any(token in auth_text for token in ("bearer", "authorization")):
        boundary = "bearer_required"; confidence = 72
        evidence.append({"type": "auth_header", "source": "endpoint_contract", "source_group": "authentication", "text": "Bearer or Authorization header hint was observed"})
    elif any(token in auth_text for token in ("session", "cookie", "csrf")):
        boundary = "session_required"; confidence = 68
        evidence.append({"type": "session_hint", "source": "endpoint_contract", "source_group": "authentication", "text": "Session, cookie or CSRF hint was observed"})
    elif any(token in auth_text for token in ("api-key", "x-api-key", "apikey")):
        boundary = "api_key_required"; confidence = 70
        evidence.append({"type": "api_key", "source": "endpoint_contract", "source_group": "authentication", "text": "API-key hint was observed"})
    if any(token in semantic_text for token in ("role", "permission", "/admin", "staff", "backoffice")):
        if boundary == "unknown": boundary = "role_gated_hint"
        elif boundary not in {"role_gated_hint", "mixed"}: boundary = "mixed"
        confidence = max(confidence, 60)
        evidence.append({"type": "role_hint", "source": "semantic", "source_group": "authorization", "text": "Role or privileged-function marker was observed"})
    if status in {401, 403}:
        if boundary == "unknown": boundary = "authentication_required"
        confidence = max(confidence, 75)
        evidence.append({"type": "http_boundary", "source": "http", "source_group": "http", "text": f"Observed HTTP {status} response"})
    elif status == 200 and not hints and not any(token in auth_text for token in ("session", "bearer", "authorization", "api-key", "csrf")):
        boundary = "public"; confidence = 55
        evidence.append({"type": "public_observation", "source": "http", "source_group": "http", "text": "HTTP 200 was observed without a client-visible authentication hint"})
    return boundary, confidence, evidence


def _extract_semantic_units(text: str) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    patterns = [
        ("api_call", re.compile(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*['\"]([^'\"]{1,500})", re.I)),
        ("route", re.compile(r"['\"]((?:/api/|/graphql|/v\d+/|/admin/|/auth/)[^'\"\s]{1,500})['\"]", re.I)),
        ("storage_key", re.compile(r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*['\"]([^'\"]{1,120})", re.I)),
        ("websocket_channel", re.compile(r"(?:subscribe|channel|room)\s*\(\s*['\"]([^'\"]{1,180})", re.I)),
        ("websocket_url", re.compile(r"""new\s+WebSocket\s*\(\s*['"]([^'"]{1,500})""", re.I)),
        ("oauth_parameter", re.compile(r"\b(redirect_uri|client_id|response_type|code_verifier|code_challenge|code_challenge_method|nonce|state|openid|authorization_code|pkce)\b", re.I)),
        ("postmessage_handler", re.compile(r"addEventListener\(\s*['\"]message['\"]|onmessage\s*=", re.I)),
        ("authorization_check", re.compile(r"(?:hasRole|hasPermission|canAccess|isAdmin|permissions?\.(?:includes|has))", re.I)),
    ]
    for unit_type, pattern in patterns:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            units.append({"unit_type": unit_type, "unit_key": sha256_text(f"{unit_type}|{value}")[:24], "value": value[:1000], "confidence": 78 if match.lastindex else 64})
    # Boolean-ish feature flags. Keep names with strong flag semantics.
    flag_pattern = re.compile(r"\b((?:enable|disable|use|allow|beta|experimental|feature)[A-Z_][A-Za-z0-9_]{2,80})\s*[:=]\s*(true|false|0|1|['\"][^'\"]{0,80}['\"])", re.I)
    for match in flag_pattern.finditer(text):
        name, value = match.group(1), match.group(2)
        units.append({"unit_type": "feature_flag", "unit_key": name.lower(), "value": value.strip("'\""), "confidence": 82})
    return units[:5000]


def generate_semantic_intelligence(paths: AppPaths, db: Database, analysis_id: str, run_id: str, targets: Iterable[str]) -> dict[str, int]:
    counts = Counter()
    for target in sorted(set(targets)):
        # Endpoint contracts, response shapes and authentication boundaries from analysis results.
        rows = db.all(
            "SELECT r.*,a.details_json,a.item FROM analysis_results r JOIN alerts a ON a.id=r.alert_id WHERE r.analysis_id=? AND r.target=?",
            (analysis_id, target),
        )
        for row in rows:
            schema = _loads(row["endpoint_schema_json"], {})
            details = _loads(row["details_json"], {})
            if schema.get("is_endpoint") is False:
                continue
            endpoint = str(schema.get("endpoint") or row["item"] or "")
            method = str(schema.get("method") or "UNKNOWN").upper()
            body_fields = [str(value) for value in schema.get("body_fields", []) if value]
            query_fields = [str(value) for value in schema.get("query_parameters", []) if value]
            path_fields = [str(value) for value in schema.get("path_parameters", []) if value]
            boundary, boundary_confidence, boundary_evidence = _auth_boundary(schema, details, endpoint)
            keys, types, sensitive, shape_confidence = _extract_response_shape(details)
            output_fields = keys[:1000]
            relations: list[dict[str, Any]] = []
            ordered_ids = [value for value in path_fields + query_fields + body_fields if value.lower().endswith("id") or value.lower() == "id"]
            for parent, child in zip(ordered_ids, ordered_ids[1:]):
                relation = "contains" if any(token in parent.lower() for token in ("tenant", "org", "account")) else "parent_of"
                relations.append({"parent": parent, "child": child, "relation": relation, "confidence": 64})
                db.execute(
                    "INSERT OR REPLACE INTO parameter_relationships(analysis_id,target,endpoint,parent_parameter,child_parameter,relation,confidence,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (analysis_id, target, endpoint, parent, child, relation, 64, json_dumps({"path_order": ordered_ids}), utc_now()),
                ); counts["parameter_relationships"] += 1
            contract_confidence = _clamp(35 + len(body_fields + query_fields + path_fields) * 4 + boundary_confidence * .25 + shape_confidence * .20, 20, 96)
            db.execute(
                "INSERT OR REPLACE INTO endpoint_contracts(analysis_id,target,source_run_id,alert_id,endpoint,method,input_fields_json,output_fields_json,auth_boundary,object_relations_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (analysis_id, target, run_id, row["alert_id"], endpoint, method, json_dumps({"path": path_fields, "query": query_fields, "body": body_fields}), json_dumps(output_fields), boundary, json_dumps(relations), contract_confidence, utc_now()),
            ); counts["endpoint_contracts"] += 1
            db.execute(
                "INSERT OR REPLACE INTO authentication_boundaries(analysis_id,target,endpoint,boundary,confidence,evidence_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (analysis_id, target, endpoint, boundary, boundary_confidence, json_dumps(boundary_evidence), utc_now()),
            ); counts["authentication_boundaries"] += 1
            if keys:
                status = details.get("status_code")
                if status is None and isinstance(details.get("new"), Mapping): status = details["new"].get("status_code")
                shape_hash = sha256_text(json_dumps({"keys": keys, "types": types}))
                db.execute(
                    "INSERT OR REPLACE INTO response_shape_fingerprints(analysis_id,target,endpoint,status_code,shape_hash,keys_json,types_json,sensitive_keys_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (analysis_id, target, endpoint, status, shape_hash, json_dumps(keys), json_dumps(types), json_dumps(sensitive), shape_confidence, utc_now()),
                ); counts["response_shapes"] += 1

        # Semantic JS units and feature flags.
        js_rows = db.all("SELECT url,blob_path FROM js_files WHERE target=? AND (last_run_id=? OR last_changed IS NOT NULL) ORDER BY last_seen DESC LIMIT 500", (target, run_id))
        for js in js_rows:
            path = Path(str(js["blob_path"] or ""))
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:5_000_000]
            except OSError:
                continue
            for unit in _extract_semantic_units(text):
                db.execute(
                    "INSERT OR REPLACE INTO semantic_js_units(analysis_id,target,run_id,js_url,unit_type,unit_key,value_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (analysis_id, target, run_id, js["url"], unit["unit_type"], unit["unit_key"], json_dumps({"value": unit["value"]}), unit["confidence"], utc_now()),
                ); counts["semantic_js_units"] += 1
                if unit["unit_type"] == "feature_flag":
                    related = [value for value in re.findall(r"['\"]((?:/api/|/graphql|/admin/)[^'\"]+)['\"]", text[max(0, text.find(str(unit["value"])) - 1000):][:2500], re.I)][:20]
                    db.execute(
                        "INSERT OR REPLACE INTO feature_flags(analysis_id,target,run_id,js_url,flag_name,observed_value,confidence,related_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (analysis_id, target, run_id, js["url"], unit["unit_key"], str(unit["value"]), unit["confidence"], json_dumps(related), utc_now()),
                    ); counts["feature_flags"] += 1
    return dict(counts)


def _historical_noise(db: Database, family: str, target: str) -> tuple[int, dict[str, Any]]:
    rows = db.all("SELECT analyst_decision,COUNT(*) count FROM bug_candidates WHERE bug_family=? AND target=? GROUP BY analyst_decision", (family, target))
    counts = {str(row["analyst_decision"]): int(row["count"] or 0) for row in rows}
    reviewed = sum(value for key, value in counts.items() if key != "unreviewed")
    noisy = sum(counts.get(key, 0) for key in ("rejected", "duplicate", "out_of_scope"))
    rate = noisy / reviewed if reviewed else 0.0
    return _clamp(rate * 100), {"reviewed": reviewed, "noisy": noisy, "noise_rate": round(rate, 3), "decisions": counts}


def _lifecycle(db: Database, fingerprint: str, analysis_id: str, now: str, stale_days: int) -> tuple[str, int, str, str, int]:
    rows = db.all("SELECT candidate_state,created_at,updated_at,source_run_id FROM bug_candidates WHERE candidate_fingerprint=? AND analysis_id<>? ORDER BY updated_at", (fingerprint, analysis_id))
    if not rows:
        return "observed", 1, now, now, 100
    first = str(rows[0]["created_at"] or now); last = str(rows[-1]["updated_at"] or now); seen = len(rows) + 1
    unique_runs = len({str(row["source_run_id"]) for row in rows})
    state = "persistent" if unique_runs >= 2 else "tracked"
    novelty = max(20, 100 - min(70, len(rows) * 12))
    try:
        last_dt = dt.datetime.fromisoformat(last.replace("Z", "+00:00")); now_dt = dt.datetime.fromisoformat(now.replace("Z", "+00:00"))
        if (now_dt - last_dt).days > stale_days:
            state = "recurring"; novelty = max(novelty, 70)
    except ValueError:
        pass
    return state, seen, first, now, novelty


def enhance_candidates(db: Database, analysis_id: str, profile: str | None = None) -> dict[str, Any]:
    profile = profile or analysis_profile(); config = PROFILES[profile]
    rows = db.all("SELECT * FROM bug_candidates WHERE analysis_id=?", (analysis_id,))
    now = utc_now(); updated = suppressed = 0
    for row in rows:
        item = dict(row)
        support_raw = [dict(value) for value in _loads(item["supporting_evidence_json"], []) if isinstance(value, Mapping)]
        against_raw = [dict(value) for value in _loads(item["contradicting_evidence_json"], []) if isinstance(value, Mapping)]
        analysis_row = db.one("SELECT confidence,endpoint_schema_json FROM analysis_results WHERE analysis_id=? AND alert_id=?", (analysis_id, item["alert_id"])) if item["alert_id"] is not None else None
        analysis_confidence = parse_int(analysis_row["confidence"], 50) if analysis_row else 62
        contract = db.one("SELECT * FROM endpoint_contracts WHERE analysis_id=? AND alert_id=?", (analysis_id, item["alert_id"])) if item["alert_id"] is not None else None
        boundary = db.one("SELECT * FROM authentication_boundaries WHERE analysis_id=? AND endpoint=?", (analysis_id, item["endpoint"])) if item["endpoint"] else None
        shape = db.one("SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND endpoint=?", (analysis_id, item["endpoint"])) if item["endpoint"] else None
        boundary_diff = db.one("SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, item["endpoint"])) if item["endpoint"] else None
        shape_diff = db.one("SELECT * FROM response_shape_diffs WHERE analysis_id=? AND endpoint=? ORDER BY confidence DESC LIMIT 1", (analysis_id, item["endpoint"])) if item["endpoint"] else None
        protocol_finding = db.one("SELECT * FROM protocol_findings WHERE analysis_id=? AND entity=? ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,confidence DESC LIMIT 1", (analysis_id, item["endpoint"])) if item["endpoint"] else None
        semantic_bonus = 0
        behavioral_bonus = 0
        if boundary:
            boundary_name = str(boundary["boundary"])
            if boundary_name == "public" and item["bug_family"] in {"broken_object_authorization","broken_function_authorization","information_disclosure","graphql_data_exposure"}:
                support_raw.append({"type":"authentication_boundary","source":"authentication_boundary","source_group":"authentication","weight":10,"text":"The observed endpoint currently appears public from available HTTP and client evidence"}); semantic_bonus += 8
            elif boundary_name in {"authentication_required","session_required","bearer_required","api_key_required","mixed"}:
                against_raw.append({"type":"protected_boundary","source":"authentication_boundary","source_group":"authentication","weight":-4,"text":f"Observed boundary is {boundary_name}; object-, role- or field-level enforcement is still unknown"})
        if shape:
            sensitive_keys = _loads(shape["sensitive_keys_json"], [])
            if sensitive_keys and item["bug_family"] in {"information_disclosure","broken_object_authorization","graphql_data_exposure"}:
                support_raw.append({"type":"sensitive_response_shape","source":"response_shape","source_group":"response_shape","weight":12,"text":f"Response structure includes sensitive-looking fields: {', '.join(map(str,sensitive_keys[:8]))}"}); semantic_bonus += 7
        if contract:
            inputs = _loads(contract["input_fields_json"], {})
            output_fields = _loads(contract["output_fields_json"], [])
            if item["bug_family"] == "mass_assignment":
                flattened = [str(value) for values in inputs.values() for value in (values if isinstance(values,list) else [])]
                privileged = [value for value in flattened if any(token in value.lower() for token in ("role","admin","permission","owner","tenant","status"))]
                if privileged:
                    support_raw.append({"type":"privileged_contract_fields","source":"endpoint_contract","source_group":"endpoint_contract","weight":14,"text":f"Writable contract exposes privilege-sensitive fields: {', '.join(privileged[:8])}"}); semantic_bonus += 10
            if output_fields and item["bug_family"] in {"information_disclosure","graphql_data_exposure"}:
                support_raw.append({"type":"structured_output_contract","source":"endpoint_contract","source_group":"endpoint_contract","weight":6,"text":f"Endpoint contract exposes {len(output_fields)} structured output field(s)"}); semantic_bonus += 3
        if boundary_diff:
            transition = str(boundary_diff["transition"] or "")
            if transition == "boundary_regression" and item["bug_family"] in {"authentication_session","broken_object_authorization","broken_function_authorization","information_disclosure","graphql_authorization","graphql_data_exposure"}:
                if not str(item.get("source_ref") or "").startswith("boundary-diff:"):
                    support_raw.append({"type":"authentication_boundary_regression","source":"behavioral_diff","source_group":"behavioral_boundary","weight":24,"text":f"Stored authentication boundary changed from {boundary_diff['previous_boundary']} to {boundary_diff['current_boundary']}"}); behavioral_bonus += 18
            elif transition == "boundary_hardening":
                against_raw.append({"type":"authentication_boundary_hardening","source":"behavioral_diff","source_group":"behavioral_boundary","weight":-8,"text":f"Stored boundary became more restrictive: {boundary_diff['previous_boundary']} to {boundary_diff['current_boundary']}"})
        if shape_diff:
            transition = str(shape_diff["transition"] or "")
            sensitive_added = _loads(shape_diff["sensitive_added_json"], [])
            if transition in {"protected_to_data","error_to_data","sensitive_expansion"} and item["bug_family"] in {"information_disclosure","broken_object_authorization","graphql_data_exposure","authentication_session"}:
                if not str(item.get("source_ref") or "").startswith("shape-diff:"):
                    text = f"Stored response structure changed: {transition.replace('_',' ')}"
                    if sensitive_added: text += f"; sensitive-looking fields added: {', '.join(map(str,sensitive_added[:8]))}"
                    support_raw.append({"type":"structural_response_diff","source":"behavioral_diff","source_group":"response_shape_diff","weight":22,"text":text}); behavioral_bonus += 15
        if protocol_finding and str(protocol_finding["severity"]) in {"high","critical"}:
            protocol = str(protocol_finding["protocol"])
            family_protocols = {"graphql_authorization":"graphql","graphql_data_exposure":"graphql","websocket_authorization":"websocket","open_redirect":"oauth_oidc","sensitive_caching":"cache"}
            if family_protocols.get(str(item["bug_family"])) == protocol:
                support_raw.append({"type":"protocol_specific_finding","source":f"{protocol}_engine","source_group":f"protocol_{protocol}","weight":16,"text":str(protocol_finding["summary"])}); behavioral_bonus += 10
        if item["endpoint"]:
            like = f"%{item['endpoint']}%"
            flag = db.one("SELECT flag_name,observed_value,confidence FROM feature_flags WHERE analysis_id=? AND related_json LIKE ? ORDER BY confidence DESC LIMIT 1", (analysis_id, like))
            semantic_unit = db.one("SELECT unit_type,value_json,confidence FROM semantic_js_units WHERE analysis_id=? AND value_json LIKE ? ORDER BY confidence DESC LIMIT 1", (analysis_id, like))
            if flag:
                support_raw.append({"type":"feature_flag_context","source":"feature_flag","source_group":"feature_flag","weight":8,"text":f"Related feature flag {flag['flag_name']} is observed with value {flag['observed_value']}"}); semantic_bonus += 5
            if semantic_unit:
                support_raw.append({"type":"semantic_js_unit","source":"semantic_js","source_group":"semantic_js","weight":8,"text":f"Endpoint is referenced by semantic JavaScript unit {semantic_unit['unit_type']}"}); semantic_bonus += 5
        support, support_meta = independent_evidence(support_raw)
        against, against_meta = independent_evidence(against_raw)
        groups = support_meta["independent_groups"]
        contract_conf = parse_int(contract["confidence"], 0) if contract else 0
        boundary_conf = parse_int(boundary["confidence"], 0) if boundary else 0
        shape_conf = parse_int(shape["confidence"], 0) if shape else 0
        boundary_diff_conf = parse_int(boundary_diff["confidence"], 0) if boundary_diff else 0
        shape_diff_conf = parse_int(shape_diff["confidence"], 0) if shape_diff else 0
        protocol_conf = parse_int(protocol_finding["confidence"], 0) if protocol_finding else 0
        observation_quality = _clamp(16 + min(34, groups * 11) + analysis_confidence * .23 + contract_conf * .10 + boundary_conf * .07 + shape_conf * .07 + boundary_diff_conf * .08 + shape_diff_conf * .08 + protocol_conf * .05 - against_meta["independent_groups"] * 3, 10, 98)
        noise, noise_meta = _historical_noise(db, str(item["bug_family"]), str(item["target"]))
        state, seen, first, last, novelty = _lifecycle(db, str(item["candidate_fingerprint"]), analysis_id, now, int(config["stale_days"]))
        likelihood = _clamp(parse_int(item["likelihood_score"], 0) + semantic_bonus + behavioral_bonus, 0, 100)
        if item["analyst_decision"] != "confirmed_by_analyst":
            likelihood = min(likelihood, 96)
        evidence = _clamp(parse_int(item["evidence_strength"], 0) * .72 + observation_quality * .28 - noise * .08, 5, 96)
        impact = parse_int(item["impact_potential"], 0)
        investigation = _clamp(likelihood * .31 + evidence * .24 + impact * .20 + observation_quality * .17 + novelty * .08 - noise * .18, 0, 100)
        automatic_state = str(item["candidate_state"])
        if groups < int(config["minimum_sources"]) or evidence < int(config["minimum_evidence"]) or likelihood < int(config["minimum_likelihood"]):
            automatic_state = "weak_signal"; suppressed += 1
        elif likelihood >= 75 and evidence >= 65 and observation_quality >= 60:
            automatic_state = "strong_candidate"
        elif likelihood >= 55 and evidence >= 42:
            automatic_state = "plausible"
        else:
            automatic_state = "possible"
        if item["analyst_decision"] == "confirmed_by_analyst": automatic_state = "confirmed_by_analyst"
        elif item["analyst_decision"] == "rejected": automatic_state = "rejected"
        quality = {
            "profile": profile,
            "independent_support_groups": groups,
            "raw_support_signals": support_meta["raw_signals"],
            "suppressed_correlated_signals": support_meta["double_counted_signals_suppressed"],
            "observation_quality": observation_quality,
            "historical_noise": noise_meta,
            "contract_confidence": contract_conf,
            "authentication_boundary": dict(boundary) if boundary else {},
            "response_shape": dict(shape) if shape else {},
            "authentication_boundary_diff": dict(boundary_diff) if boundary_diff else {},
            "response_shape_diff": dict(shape_diff) if shape_diff else {},
            "protocol_finding": dict(protocol_finding) if protocol_finding else {},
            "behavioral_bonus": behavioral_bonus,
            "would_strengthen": _loads(item["missing_evidence_json"], []),
            "would_reject": [value.get("text") for value in against],
        }
        db.execute(
            "UPDATE bug_candidates SET likelihood_score=?,evidence_strength=?,priority_score=?,candidate_state=?,supporting_evidence_json=?,contradicting_evidence_json=?,observation_quality=?,investigation_value=?,novelty_score=?,historical_noise=?,lifecycle_state=?,evidence_groups_json=?,quality_explanation_json=?,analysis_profile=?,first_observed_at=?,last_observed_at=?,seen_count=?,updated_at=? WHERE candidate_id=?",
            (likelihood, evidence, investigation, automatic_state, json_dumps(support), json_dumps(against), observation_quality, investigation, novelty, noise, state, json_dumps({"support": support_meta, "against": against_meta}), json_dumps(quality), profile, first, last, seen, now, item["candidate_id"]),
        ); updated += 1
    bundle_count = build_candidate_bundles(db, analysis_id)
    metrics = candidate_evaluation(db, analysis_id, profile=profile, persist=True)
    return {"updated": updated, "profile": profile, "weak_or_suppressed": suppressed, "bundles": bundle_count, "evaluation": metrics}


def build_candidate_bundles(db: Database, analysis_id: str) -> int:
    db.execute("DELETE FROM candidate_bundles WHERE analysis_id=?", (analysis_id,))
    rows = [dict(row) for row in db.all("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY investigation_value DESC", (analysis_id,))]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        endpoint = str(row.get("endpoint") or row.get("source_ref") or "")
        endpoint = re.sub(r"\b\d{2,}\b", "{n}", endpoint.lower())
        endpoint = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "{uuid}", endpoint, flags=re.I)
        base = f"{row['target']}|{row.get('alert_id') or 0}|{endpoint}"
        groups[sha256_text(base)[:24]].append(row)
    count = 0
    for key, members in groups.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda value: parse_int(value.get("investigation_value"), 0), reverse=True)
        primary = members[0]
        families = [str(value["bug_family"]) for value in members]
        bundle_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:bundle:{analysis_id}:{key}"))
        title = f"{primary['title']} and {len(members)-1} related candidate(s)"
        summary = "Related bug-family hypotheses share the same alert, endpoint, or semantic source and should be reviewed as one boundary."
        db.execute(
            "INSERT OR REPLACE INTO candidate_bundles(bundle_id,analysis_id,target,bundle_key,title,summary,primary_family,members_json,priority_score,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (bundle_id, analysis_id, primary["target"], key, title, summary, primary["bug_family"], json_dumps([value["candidate_id"] for value in members]), max(parse_int(value.get("investigation_value"), 0) for value in members), utc_now()),
        )
        for value in members:
            db.execute("UPDATE bug_candidates SET bundle_id=? WHERE candidate_id=?", (bundle_id, value["candidate_id"]))
        count += 1
    return count


def record_candidate_feedback(db: Database, candidate_id: str, decision: str, reason_code: str, note: str, actor: str) -> None:
    row = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
    if not row:
        return
    db.execute(
        "INSERT INTO candidate_feedback(candidate_fingerprint,candidate_id,analysis_id,decision,reason_code,note,actor,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (row["candidate_fingerprint"], candidate_id, row["analysis_id"], decision, reason_code, note, actor, utc_now()),
    )


def candidate_calibration(db: Database, target: str | None = None) -> dict[str, Any]:
    where = " WHERE target=?" if target else ""; params = (target,) if target else ()
    rows = db.all(f"SELECT bug_family,likelihood_score,analyst_decision FROM bug_candidates{where}", params)
    grouped: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for row in rows: grouped[str(row["bug_family"])].append((parse_int(row["likelihood_score"], 0), str(row["analyst_decision"])))
    result: dict[str, Any] = {}
    for family, values in grouped.items():
        reviewed = [(score, decision) for score, decision in values if decision != "unreviewed"]
        confirmed = sum(1 for _, decision in reviewed if decision == "confirmed_by_analyst")
        useful = sum(1 for _, decision in reviewed if decision in {"confirmed_by_analyst", "needs_more_evidence"})
        predicted = sum(score for score, _ in reviewed) / max(1, len(reviewed)) / 100
        observed = confirmed / max(1, len(reviewed))
        result[family] = {"total": len(values), "reviewed": len(reviewed), "confirmed": confirmed, "useful": useful, "average_predicted": round(predicted, 3), "observed_confirmed_rate": round(observed, 3), "calibration_gap": round(observed - predicted, 3), "status": "insufficient_data" if len(reviewed) < 5 else "overconfident" if observed + .15 < predicted else "underconfident" if observed - .15 > predicted else "reasonable"}
    return {"target": target or "*", "families": result}


def candidate_evaluation(db: Database, analysis_id: str, profile: str = "balanced", persist: bool = False) -> dict[str, Any]:
    rows = db.all("SELECT * FROM bug_candidates WHERE analysis_id=?", (analysis_id,))
    total = len(rows); reviewed = [row for row in rows if row["analyst_decision"] != "unreviewed"]
    confirmed = sum(1 for row in reviewed if row["analyst_decision"] == "confirmed_by_analyst")
    rejected = sum(1 for row in reviewed if row["analyst_decision"] in {"rejected", "out_of_scope"})
    duplicates = sum(1 for row in reviewed if row["analyst_decision"] == "duplicate")
    strong = sum(1 for row in rows if row["candidate_state"] in {"strong_candidate", "confirmed_by_analyst"})
    independent_average = 0.0
    if rows:
        independent_average = sum(parse_int(_loads(row["evidence_groups_json"], {}).get("support", {}).get("independent_groups"), 0) for row in rows) / len(rows)
    metrics = {"analysis_id": analysis_id, "profile": profile, "candidates": total, "strong": strong, "reviewed": len(reviewed), "confirmed": confirmed, "rejected": rejected, "duplicates": duplicates, "precision_proxy": round(confirmed / max(1, confirmed + rejected), 3), "duplicate_rate": round(duplicates / max(1, total), 3), "average_independent_sources": round(independent_average, 2)}
    if persist:
        db.execute("INSERT INTO candidate_evaluations(analysis_id,profile,metrics_json,created_at) VALUES(?,?,?,?)", (analysis_id, profile, json_dumps(metrics), utc_now()))
    return metrics


def set_gold_label(db: Database, candidate_id: str, label: str, expected_family: str = "", note: str = "") -> dict[str, Any]:
    row = db.one("SELECT * FROM bug_candidates WHERE candidate_id=?", (candidate_id,))
    if not row:
        raise ValueError(f"Candidate not found: {candidate_id}")
    db.execute(
        "INSERT INTO candidate_gold_labels(source_run_id,target,candidate_fingerprint,expected_family,label,note,created_at) VALUES(?,?,?,?,?,?,?)",
        (row["source_run_id"], row["target"], row["candidate_fingerprint"], expected_family or row["bug_family"], label, note, utc_now()),
    )
    return {"candidate_id": candidate_id, "label": label, "expected_family": expected_family or row["bug_family"]}
