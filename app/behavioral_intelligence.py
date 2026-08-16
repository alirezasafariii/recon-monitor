from __future__ import annotations

import json
import re
import urllib.parse
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import AppPaths, Database, json_dumps, parse_int, sha256_text, utc_now

BEHAVIORAL_ENGINE_VERSION = "5.0.0"
BEHAVIORAL_RULE_VERSION = "2026.08.7"

PROTECTED_BOUNDARIES = {
    "authentication_required", "session_required", "bearer_required", "api_key_required",
    "role_gated_hint", "mixed",
}
PUBLIC_BOUNDARIES = {"public"}
SENSITIVE_MARKERS = {
    "email", "phone", "address", "balance", "invoice", "card", "token", "secret", "password",
    "role", "permission", "account", "customer", "user", "tenant", "session", "order", "payment",
}
IDENTITY_MARKERS = {
    "user", "userid", "account", "accountid", "tenant", "tenantid", "organization", "organizationid",
    "org", "orgid", "customer", "customerid", "profile", "profileid", "member", "memberid", "role",
    "permission", "order", "orderid", "invoice", "invoiceid", "project", "projectid", "team", "teamid",
}


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _latest_previous_analysis(db: Database, analysis_id: str, target: str) -> str:
    row = db.one(
        """
        SELECT ar.id
        FROM analysis_runs ar
        JOIN analysis_results r ON r.analysis_id=ar.id
        WHERE ar.status='success' AND ar.id<>? AND r.target=?
        GROUP BY ar.id
        ORDER BY COALESCE(ar.finished_at,ar.started_at) DESC
        LIMIT 1
        """,
        (analysis_id, target),
    )
    return str(row["id"]) if row else ""


def _boundary_transition(previous: str, current: str) -> tuple[str, str, int]:
    previous = previous or "unknown"
    current = current or "unknown"
    if previous == current:
        return "stable", "informational", 35
    if previous in PROTECTED_BOUNDARIES and current in PUBLIC_BOUNDARIES:
        return "boundary_regression", "high", 92
    if previous in PUBLIC_BOUNDARIES and current in PROTECTED_BOUNDARIES:
        return "boundary_hardening", "low", 76
    if previous in PROTECTED_BOUNDARIES and current == "unknown":
        return "visibility_lost", "medium", 58
    if previous == "unknown" and current in PUBLIC_BOUNDARIES:
        return "new_public_boundary", "medium", 62
    if previous == "unknown" and current in PROTECTED_BOUNDARIES:
        return "new_protected_boundary", "informational", 55
    return "boundary_changed", "medium", 60


def _shape_diff(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    previous_keys = set(map(str, _loads(previous.get("keys_json"), [])))
    current_keys = set(map(str, _loads(current.get("keys_json"), [])))
    previous_types = {str(k): str(v) for k, v in _loads(previous.get("types_json"), {}).items()}
    current_types = {str(k): str(v) for k, v in _loads(current.get("types_json"), {}).items()}
    added = sorted(current_keys - previous_keys)
    removed = sorted(previous_keys - current_keys)
    type_changes = [
        {"key": key, "before": previous_types[key], "after": current_types[key]}
        for key in sorted(previous_keys & current_keys)
        if previous_types.get(key) != current_types.get(key)
    ]
    sensitive_added = sorted({
        key for key in added
        if any(marker in key.lower() for marker in SENSITIVE_MARKERS)
    })
    previous_sensitive = set(map(str, _loads(previous.get("sensitive_keys_json"), [])))
    current_sensitive = set(map(str, _loads(current.get("sensitive_keys_json"), [])))
    sensitive_added = sorted(set(sensitive_added) | (current_sensitive - previous_sensitive))
    before_status = previous.get("status_code")
    after_status = current.get("status_code")
    before_error = any("error" in key.lower() or "message" in key.lower() for key in previous_keys)
    after_data = bool(current_keys - {"error", "message", "code", "status"})
    if before_status in {401, 403} and after_status == 200:
        transition = "protected_to_data"
    elif before_error and after_data and added:
        transition = "error_to_data"
    elif sensitive_added:
        transition = "sensitive_expansion"
    elif added or removed or type_changes:
        transition = "schema_changed"
    else:
        transition = "stable"
    confidence = _clamp(
        38
        + min(28, len(added) * 4)
        + min(18, len(removed) * 3)
        + min(18, len(type_changes) * 4)
        + (18 if sensitive_added else 0)
        + (12 if transition in {"error_to_data", "protected_to_data"} else 0),
        20,
        98,
    )
    severity = "high" if transition in {"protected_to_data", "sensitive_expansion"} else "medium" if transition in {"error_to_data", "schema_changed"} else "informational"
    return {
        "added": added,
        "removed": removed,
        "type_changes": type_changes,
        "sensitive_added": sensitive_added,
        "transition": transition,
        "confidence": confidence,
        "severity": severity,
    }


def _normalize_headers(details: Mapping[str, Any]) -> dict[str, str]:
    candidates: list[Any] = []
    for key in ("headers", "response_headers", "headers_json", "new_headers", "current_headers"):
        value = details.get(key)
        if value:
            candidates.append(value)
    for key in ("new", "current", "after", "response"):
        nested = details.get(key)
        if isinstance(nested, Mapping):
            for hkey in ("headers", "response_headers", "headers_json"):
                if nested.get(hkey):
                    candidates.append(nested.get(hkey))
    result: dict[str, str] = {}
    for value in candidates:
        decoded = _loads(value, value)
        if isinstance(decoded, Mapping):
            for key, item in decoded.items():
                result[str(key).strip().lower()] = str(item).strip()
        elif isinstance(decoded, list):
            for item in decoded:
                if isinstance(item, str) and ":" in item:
                    key, content = item.split(":", 1)
                    result[key.strip().lower()] = content.strip()
    return result


def _stored_context_observations(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    raw = details.get("context_observations") or details.get("observations") or details.get("contexts")
    decoded = _loads(raw, raw)
    if isinstance(decoded, Mapping):
        iterable = decoded.items()
    elif isinstance(decoded, list):
        iterable = [(str(item.get("context") or f"context-{index}"), item) for index, item in enumerate(decoded) if isinstance(item, Mapping)]
    else:
        iterable = []
    for context, item in iterable:
        if not isinstance(item, Mapping):
            continue
        response = item.get("response") if isinstance(item.get("response"), Mapping) else item
        observations.append({
            "context": str(context),
            "status_code": response.get("status_code"),
            "auth_state": str(item.get("auth_state") or item.get("authentication") or context),
            "shape_hash": str(item.get("shape_hash") or ""),
            "headers": _normalize_headers(response),
            "confidence": parse_int(item.get("confidence"), 60),
        })
    return observations


def _protocol_from_endpoint(endpoint: str) -> str:
    lower = endpoint.lower()
    if lower.startswith(("ws://", "wss://")) or "websocket" in lower or "/socket" in lower:
        return "websocket"
    if "graphql" in lower:
        return "graphql"
    if any(token in lower for token in ("oauth", "openid", "/authorize", "/callback", "/token")):
        return "oauth_oidc"
    return "rest"


def _severity_rank(value: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def _insert_protocol_finding(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    protocol: str,
    entity: str,
    kind: str,
    confidence: int,
    severity: str,
    summary: str,
    evidence: Mapping[str, Any] | list[Any],
) -> None:
    finding_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"recon-monitor:{analysis_id}:{target}:{protocol}:{entity}:{kind}"))
    db.execute(
        """INSERT OR REPLACE INTO protocol_findings(
        finding_id,analysis_id,target,protocol,entity,kind,confidence,severity,summary,evidence_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (finding_id, analysis_id, target, protocol, entity, kind, _clamp(confidence), severity, summary, json_dumps(evidence), utc_now()),
    )


def _entity_type(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    for marker in sorted(IDENTITY_MARKERS, key=len, reverse=True):
        if marker in normalized:
            return marker[:-2] if marker.endswith("id") else marker
    return "object"


def _insert_entity(db: Database, analysis_id: str, target: str, entity_type: str, entity_value: str, confidence: int, evidence: Mapping[str, Any]) -> None:
    db.execute(
        "INSERT OR REPLACE INTO identity_entities(analysis_id,target,entity_type,entity_value,confidence,evidence_json,created_at) VALUES(?,?,?,?,?,?,?)",
        (analysis_id, target, entity_type, entity_value, _clamp(confidence), json_dumps(evidence), utc_now()),
    )


def _insert_relation(
    db: Database,
    analysis_id: str,
    target: str,
    source_type: str,
    source_value: str,
    relation: str,
    destination_type: str,
    destination_value: str,
    confidence: int,
    evidence: Mapping[str, Any],
) -> None:
    db.execute(
        """INSERT OR REPLACE INTO identity_relations(
        analysis_id,target,source_type,source_value,relation,destination_type,destination_value,confidence,evidence_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (analysis_id, target, source_type, source_value, relation, destination_type, destination_value, _clamp(confidence), json_dumps(evidence), utc_now()),
    )


def generate_behavioral_intelligence(paths: AppPaths, db: Database, analysis_id: str, run_id: str, targets: Iterable[str]) -> dict[str, Any]:
    del paths  # Reserved for future artifact-backed protocol adapters.
    counts = Counter()
    per_target: dict[str, Any] = {}
    for target in sorted(set(targets)):
        previous_analysis = _latest_previous_analysis(db, analysis_id, target)
        target_summary = Counter()

        # Persist context observations already present in stored evidence. No network calls are made.
        alert_rows = db.all(
            "SELECT r.alert_id,r.endpoint_schema_json,a.details_json,a.item FROM analysis_results r JOIN alerts a ON a.id=r.alert_id WHERE r.analysis_id=? AND r.target=?",
            (analysis_id, target),
        )
        for alert in alert_rows:
            details = _loads(alert["details_json"], {})
            schema = _loads(alert["endpoint_schema_json"], {})
            endpoint = str(schema.get("endpoint") or alert["item"] or "")
            for observation in _stored_context_observations(details):
                db.execute(
                    """INSERT OR REPLACE INTO behavioral_observations(
                    analysis_id,target,endpoint,context,auth_state,status_code,shape_hash,headers_json,source_ref,confidence,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        analysis_id, target, endpoint, observation["context"], observation["auth_state"], observation["status_code"],
                        observation["shape_hash"], json_dumps(observation["headers"]), f"alert:{alert['alert_id']}", observation["confidence"], utc_now(),
                    ),
                )
                counts["context_observations"] += 1
                target_summary["context_observations"] += 1

        # Authentication-boundary history and diffs.
        boundaries = db.all("SELECT * FROM authentication_boundaries WHERE analysis_id=? AND target=?", (analysis_id, target))
        for current in boundaries:
            endpoint = str(current["endpoint"])
            previous = db.one(
                "SELECT * FROM authentication_boundaries WHERE analysis_id=? AND target=? AND endpoint=?",
                (previous_analysis, target, endpoint),
            ) if previous_analysis else None
            if not previous:
                continue
            transition, severity, base_confidence = _boundary_transition(str(previous["boundary"]), str(current["boundary"]))
            confidence = _clamp((parse_int(previous["confidence"], 0) + parse_int(current["confidence"], 0)) * 0.35 + base_confidence * 0.30)
            evidence = {
                "previous_evidence": _loads(previous["evidence_json"], []),
                "current_evidence": _loads(current["evidence_json"], []),
                "offline_comparison": True,
            }
            db.execute(
                """INSERT OR REPLACE INTO authentication_boundary_diffs(
                analysis_id,target,endpoint,previous_analysis_id,previous_boundary,current_boundary,transition,confidence,severity,evidence_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (analysis_id, target, endpoint, previous_analysis, previous["boundary"], current["boundary"], transition, confidence, severity, json_dumps(evidence), utc_now()),
            )
            counts["boundary_diffs"] += 1
            target_summary[f"boundary_{transition}"] += 1
            if transition == "boundary_regression":
                _insert_protocol_finding(
                    db, analysis_id=analysis_id, target=target, protocol=_protocol_from_endpoint(endpoint), entity=endpoint,
                    kind="authentication_boundary_regression", confidence=confidence, severity="high",
                    summary=f"Stored observations changed from {previous['boundary']} to {current['boundary']}.", evidence=evidence,
                )
                counts["protocol_findings"] += 1

        # Structural response diffs.
        shapes = db.all("SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND target=?", (analysis_id, target))
        for current in shapes:
            endpoint = str(current["endpoint"])
            previous = db.one(
                "SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND target=? AND endpoint=? ORDER BY confidence DESC LIMIT 1",
                (previous_analysis, target, endpoint),
            ) if previous_analysis else None
            if not previous:
                continue
            diff = _shape_diff(dict(previous), dict(current))
            db.execute(
                """INSERT OR REPLACE INTO response_shape_diffs(
                analysis_id,target,endpoint,previous_analysis_id,previous_shape_hash,current_shape_hash,previous_status_code,current_status_code,
                added_keys_json,removed_keys_json,type_changes_json,sensitive_added_json,transition,confidence,severity,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    analysis_id, target, endpoint, previous_analysis, previous["shape_hash"], current["shape_hash"],
                    previous["status_code"], current["status_code"], json_dumps(diff["added"]), json_dumps(diff["removed"]),
                    json_dumps(diff["type_changes"]), json_dumps(diff["sensitive_added"]), diff["transition"], diff["confidence"], diff["severity"], utc_now(),
                ),
            )
            counts["response_shape_diffs"] += 1
            target_summary[f"shape_{diff['transition']}"] += 1
            if diff["transition"] in {"protected_to_data", "error_to_data", "sensitive_expansion"}:
                _insert_protocol_finding(
                    db, analysis_id=analysis_id, target=target, protocol=_protocol_from_endpoint(endpoint), entity=endpoint,
                    kind=f"response_{diff['transition']}", confidence=diff["confidence"], severity=diff["severity"],
                    summary=f"Stored response structure changed: {diff['transition'].replace('_', ' ')}.", evidence=diff,
                )
                counts["protocol_findings"] += 1

        # REST endpoint semantics and identity/authorization graph.
        contracts = db.all("SELECT * FROM endpoint_contracts WHERE analysis_id=? AND target=?", (analysis_id, target))
        for contract in contracts:
            endpoint = str(contract["endpoint"])
            method = str(contract["method"] or "UNKNOWN").upper()
            protocol = _protocol_from_endpoint(endpoint)
            inputs = _loads(contract["input_fields_json"], {})
            object_relations = _loads(contract["object_relations_json"], [])
            fields = [str(value) for group in inputs.values() if isinstance(group, list) for value in group]
            _insert_entity(db, analysis_id, target, "endpoint", endpoint, parse_int(contract["confidence"], 60), {"method": method, "protocol": protocol})
            action = "reads" if method in {"GET", "HEAD"} else "creates" if method == "POST" else "updates" if method in {"PUT", "PATCH"} else "deletes" if method == "DELETE" else "accesses"
            for field in fields:
                entity_type = _entity_type(field)
                if entity_type == "object" and not field.lower().endswith("id"):
                    continue
                entity_value = field
                _insert_entity(db, analysis_id, target, entity_type, entity_value, 68, {"endpoint": endpoint, "field": field})
                _insert_relation(db, analysis_id, target, "endpoint", endpoint, action, entity_type, entity_value, 72, {"method": method, "source": "endpoint_contract"})
                counts["identity_entities"] += 1
                counts["identity_relations"] += 1
            for relation in object_relations:
                if not isinstance(relation, Mapping):
                    continue
                parent = str(relation.get("parent") or "")
                child = str(relation.get("child") or "")
                if not parent or not child:
                    continue
                parent_type = _entity_type(parent); child_type = _entity_type(child)
                _insert_entity(db, analysis_id, target, parent_type, parent, parse_int(relation.get("confidence"), 64), relation)
                _insert_entity(db, analysis_id, target, child_type, child, parse_int(relation.get("confidence"), 64), relation)
                _insert_relation(db, analysis_id, target, parent_type, parent, str(relation.get("relation") or "parent_of"), child_type, child, parse_int(relation.get("confidence"), 64), relation)
                counts["identity_relations"] += 1
            if protocol == "rest":
                version = re.search(r"/(v\d+)(?:/|$)", endpoint, re.I)
                if version:
                    _insert_protocol_finding(
                        db, analysis_id=analysis_id, target=target, protocol="rest", entity=endpoint, kind="versioned_api_contract",
                        confidence=parse_int(contract["confidence"], 60), severity="informational",
                        summary=f"Versioned REST contract {version.group(1)} observed with {method} semantics.", evidence={"contract": dict(contract)},
                    )
                    counts["protocol_findings"] += 1

        # GraphQL engine.
        graphql_rows = db.all("SELECT * FROM graphql_intelligence WHERE analysis_id=? AND target=?", (analysis_id, target))
        for item in graphql_rows:
            identifiers = _loads(item["identifiers_json"], [])
            sensitive = _loads(item["sensitive_fields_json"], [])
            kind = "graphql_mutation_boundary" if str(item["operation_type"]).lower() == "mutation" else "graphql_query_surface"
            severity = "high" if sensitive and identifiers else "medium" if sensitive or identifiers else "informational"
            confidence = _clamp(parse_int(item["confidence"], 50) + (8 if identifiers else 0) + (8 if sensitive else 0))
            evidence = {"identifiers": identifiers, "sensitive_fields": sensitive, "operation_type": item["operation_type"], "js_url": item["js_url"]}
            _insert_protocol_finding(
                db, analysis_id=analysis_id, target=target, protocol="graphql", entity=str(item["operation_name"]), kind=kind,
                confidence=confidence, severity=severity,
                summary=f"GraphQL {item['operation_type']} {item['operation_name']} exposes {len(identifiers)} identifier(s) and {len(sensitive)} sensitive marker(s).",
                evidence=evidence,
            )
            _insert_entity(db, analysis_id, target, "graphql_operation", str(item["operation_name"]), confidence, evidence)
            for identifier in identifiers:
                entity_type = _entity_type(str(identifier))
                _insert_entity(db, analysis_id, target, entity_type, str(identifier), confidence, evidence)
                _insert_relation(db, analysis_id, target, "graphql_operation", str(item["operation_name"]), "references", entity_type, str(identifier), confidence, evidence)
                counts["identity_relations"] += 1
            counts["protocol_findings"] += 1

        # WebSocket and OAuth/OIDC engines from stored semantic JavaScript units.
        units = db.all("SELECT * FROM semantic_js_units WHERE analysis_id=? AND target=?", (analysis_id, target))
        oauth_by_js: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for unit in units:
            value = str(_loads(unit["value_json"], {}).get("value") or "")
            lower = value.lower()
            if unit["unit_type"] in {"websocket_channel", "websocket_url"}:
                identifiers = [token for token in re.findall(r"[A-Za-z][A-Za-z0-9_]{1,80}", value) if token.lower().endswith("id") or token.lower() in {"room", "channel", "tenant", "user"}]
                evidence = {"channel": value, "identifiers": identifiers, "js_url": unit["js_url"]}
                _insert_protocol_finding(
                    db, analysis_id=analysis_id, target=target, protocol="websocket", entity=value, kind="channel_authorization_surface",
                    confidence=parse_int(unit["confidence"], 60), severity="medium" if identifiers else "low",
                    summary="A client-visible WebSocket subscription or channel surface was observed.", evidence=evidence,
                )
                counts["protocol_findings"] += 1
            if any(token in lower for token in ("redirect_uri", "code_verifier", "code_challenge", "openid", "oauth", "nonce", "pkce", "authorization_code")):
                oauth_by_js[str(unit["js_url"])].append({"unit_type": unit["unit_type"], "value": value, "confidence": unit["confidence"]})
        for js_url, evidence_items in oauth_by_js.items():
            text = " ".join(item["value"] for item in evidence_items).lower()
            markers = [token for token in ("redirect_uri", "state", "nonce", "code_verifier", "code_challenge", "pkce", "openid") if token in text]
            confidence = _clamp(45 + len(set(markers)) * 8 + max(parse_int(item["confidence"], 0) for item in evidence_items) * 0.25)
            kind = "oauth_callback_controls" if "redirect_uri" in markers else "oauth_flow_observation"
            severity = "medium" if "redirect_uri" in markers and not any(token in markers for token in ("state", "nonce", "pkce", "code_verifier", "code_challenge")) else "informational"
            _insert_protocol_finding(
                db, analysis_id=analysis_id, target=target, protocol="oauth_oidc", entity=js_url, kind=kind,
                confidence=confidence, severity=severity,
                summary=f"OAuth/OIDC flow markers observed: {', '.join(markers) or 'generic flow markers'}.", evidence=evidence_items,
            )
            counts["protocol_findings"] += 1

        # Cache engine from stored alert response headers.
        for alert in alert_rows:
            details = _loads(alert["details_json"], {})
            schema = _loads(alert["endpoint_schema_json"], {})
            endpoint = str(schema.get("endpoint") or alert["item"] or "")
            headers = _normalize_headers(details)
            if not headers:
                continue
            cache_control = headers.get("cache-control", "")
            vary = headers.get("vary", "")
            has_auth = any(key in headers for key in ("www-authenticate", "set-cookie", "authorization")) or "cookie" in json_dumps(details).lower()
            cacheable = any(token in cache_control.lower() for token in ("public", "s-maxage", "max-age")) and "no-store" not in cache_control.lower()
            if cacheable:
                severity = "high" if has_auth and not vary else "medium" if has_auth else "low"
                confidence = 82 if has_auth else 62
                evidence = {"cache_control": cache_control, "vary": vary, "has_auth_context": has_auth, "headers_present": sorted(headers)}
                _insert_protocol_finding(
                    db, analysis_id=analysis_id, target=target, protocol="cache", entity=endpoint, kind="cacheable_response_context",
                    confidence=confidence, severity=severity,
                    summary="A stored response observation contains cacheable directives; user specificity and cache-key behavior require review.", evidence=evidence,
                )
                counts["protocol_findings"] += 1

        per_target[target] = {"previous_analysis_id": previous_analysis, **dict(target_summary)}

    return {"engine_version": BEHAVIORAL_ENGINE_VERSION, "rule_version": BEHAVIORAL_RULE_VERSION, "counts": dict(counts), "targets": per_target}


def generate_behavioral_candidates(db: Database, analysis_id: str, run_id: str) -> dict[str, int]:
    """Route behavioral observations through canonical hypothesis admission.

    Behavioral diffs are valuable target context, but a boundary transition,
    response-shape change, or protocol heuristic is not itself a vulnerability
    condition. Preserve those observations in the hypothesis ledger and create
    a Candidate only when the canonical Family Reasoning contract admits the
    combined target-specific evidence.
    """
    # Import lazily to avoid module cycles during CLI startup.
    from bug_candidates import BUG_FAMILIES, _insert_candidate
    from hypothesis_admission import mark_promoted, record_hypothesis

    counts = Counter()

    def emit(
        *,
        target: str,
        endpoint: str,
        source_ref: str,
        family: str,
        variant: str,
        likelihood: int,
        evidence_strength: int,
        impact_potential: int,
        support: list[dict[str, Any]],
        contradict: list[dict[str, Any]],
        missing: list[str],
        rule_ids: list[str],
        summary: str,
    ) -> bool:
        hypothesis = record_hypothesis(
            db,
            analysis_id=analysis_id,
            source_run_id=run_id,
            target=target,
            alert_id=None,
            asset="",
            endpoint=endpoint,
            source_ref=source_ref,
            family=family,
            variant=variant,
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rule_ids,
            summary=summary,
        )
        assessment = hypothesis["assessment"]
        if not bool(assessment.get("admitted")):
            return False

        admitted_support = list(hypothesis["support"])
        admitted_contradict = list(hypothesis["contradict"])
        admitted_missing = list(hypothesis["missing"])
        admitted_rules = list(hypothesis["rule_ids"])
        independent = {
            str(item.get("source_group") or item.get("source") or item.get("type") or "rule")
            for item in admitted_support
        }
        if len(admitted_support) < 2 or len(independent) < 2:
            return False

        candidate_id = _insert_candidate(
            db,
            analysis_id=analysis_id,
            source_run_id=run_id,
            target=target,
            alert_id=None,
            asset="",
            endpoint=endpoint,
            source_ref=source_ref,
            family=family,
            variant=variant,
            likelihood=likelihood,
            evidence_strength=evidence_strength,
            impact_potential=impact_potential,
            support=admitted_support,
            contradict=admitted_contradict,
            missing=admitted_missing,
            rule_ids=admitted_rules,
            summary=summary,
        )
        mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
        counts[family] += 1
        return True

    boundary_rows = db.all(
        "SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? AND transition='boundary_regression'",
        (analysis_id,),
    )
    for row in boundary_rows:
        endpoint = str(row["endpoint"])
        support = [
            {"type": "authentication_boundary_regression", "source": "behavioral_diff", "source_group": "behavioral_boundary", "weight": 30, "text": f"Stored boundary changed from {row['previous_boundary']} to {row['current_boundary']}"},
            {"type": "cross_run_confirmation", "source": "analysis_history", "source_group": "temporal", "weight": 14, "text": f"The transition was observed across analysis runs {row['previous_analysis_id']} and {analysis_id}"},
        ]
        emit(
            target=str(row["target"]), endpoint=endpoint,
            source_ref=f"boundary-diff:{analysis_id}:{sha256_text(endpoint)[:12]}",
            family="authentication_session", variant="boundary_regression",
            likelihood=_clamp(58 + parse_int(row["confidence"], 0) * 0.35),
            evidence_strength=_clamp(58 + parse_int(row["confidence"], 0) * 0.32),
            impact_potential=BUG_FAMILIES["authentication_session"]["impact"], support=support,
            contradict=[{"type": "stored_observation_only", "source": "safety", "source_group": "validation", "weight": -5, "text": "No active validation was performed; the transition may reflect routing, deployment or observation context."}],
            missing=["Expected anonymous and authenticated behavior", "Whether response content changed with the boundary", "Scope-authorized reproduction context"],
            rule_ids=["behavioral-auth-boundary-regression"],
            summary="Stored observations suggest an authentication boundary became more permissive. This remains a behavioral hypothesis until family-specific vulnerability evidence exists.",
        )

    shape_rows = db.all(
        "SELECT * FROM response_shape_diffs WHERE analysis_id=? AND transition IN ('protected_to_data','error_to_data','sensitive_expansion')",
        (analysis_id,),
    )
    for row in shape_rows:
        endpoint = str(row["endpoint"])
        sensitive = _loads(row["sensitive_added_json"], [])
        support = [
            {"type": "structural_response_diff", "source": "behavioral_diff", "source_group": "response_shape", "weight": 24, "text": f"Stored response shape transition: {row['transition']}"},
            {"type": "cross_run_confirmation", "source": "analysis_history", "source_group": "temporal", "weight": 12, "text": "The structural change was calculated across two stored analysis runs"},
        ]
        if sensitive:
            support.append({"type": "sensitive_fields_added", "source": "response_shape", "source_group": "sensitive_shape", "weight": 20, "text": f"Sensitive-looking fields appeared: {', '.join(map(str, sensitive[:8]))}"})
        emit(
            target=str(row["target"]), endpoint=endpoint,
            source_ref=f"shape-diff:{analysis_id}:{sha256_text(endpoint)[:12]}",
            family="information_disclosure", variant=str(row["transition"]),
            likelihood=_clamp(45 + parse_int(row["confidence"], 0) * 0.38 + (8 if sensitive else 0)),
            evidence_strength=_clamp(48 + parse_int(row["confidence"], 0) * 0.38),
            impact_potential=BUG_FAMILIES["information_disclosure"]["impact"] + (8 if sensitive else 0), support=support,
            contradict=[{"type": "shape_not_value", "source": "safety", "source_group": "validation", "weight": -4, "text": "Only redacted structure was compared; field values and intended disclosure are unknown."}],
            missing=["Intended public response schema", "Authentication context for both observations", "Whether added fields contain real sensitive data"],
            rule_ids=["behavioral-structural-response-diff"],
            summary="The stored response structure became more data-rich or exposed sensitive-looking fields. This remains a behavioral hypothesis until actual sensitive visibility is established.",
        )

    protocol_rows = db.all(
        "SELECT * FROM protocol_findings WHERE analysis_id=? AND severity IN ('high','critical')",
        (analysis_id,),
    )
    for row in protocol_rows:
        protocol = str(row["protocol"])
        kind = str(row["kind"])
        family = "websocket_authorization" if protocol == "websocket" else "graphql_authorization" if protocol == "graphql" else "sensitive_caching" if protocol == "cache" else "open_redirect" if protocol == "oauth_oidc" and "callback" in kind else ""
        if not family:
            continue
        if family in {"graphql_authorization", "websocket_authorization", "sensitive_caching"}:
            continue
        support = [
            {"type": "protocol_specific_finding", "source": f"{protocol}_engine", "source_group": protocol, "weight": 22, "text": str(row["summary"])},
            {"type": "stored_protocol_evidence", "source": "semantic_intelligence", "source_group": "protocol_evidence", "weight": 10, "text": "The finding is based on stored protocol-specific evidence"},
        ]
        emit(
            target=str(row["target"]), endpoint=str(row["entity"]),
            source_ref=f"protocol:{row['finding_id']}", family=family, variant=kind,
            likelihood=_clamp(35 + parse_int(row["confidence"], 0) * 0.42),
            evidence_strength=_clamp(40 + parse_int(row["confidence"], 0) * 0.35),
            impact_potential=BUG_FAMILIES[family]["impact"], support=support,
            contradict=[{"type": "no_active_validation", "source": "safety", "source_group": "validation", "weight": -6, "text": "No active protocol validation was performed."}],
            missing=["Expected protocol policy", "Authorized behavioral comparison", "Server-side enforcement evidence"],
            rule_ids=[f"behavioral-protocol-{protocol}-{kind}"],
            summary=f"The {protocol} engine produced high-priority stored protocol context. It remains a hypothesis until the family evidence contract is satisfied.",
        )
    return dict(counts)


def behavioral_summary(db: Database, analysis_id: str) -> dict[str, Any]:
    if not analysis_id:
        return {}
    boundary = [dict(row) for row in db.all("SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,confidence DESC", (analysis_id,))]
    shapes = [dict(row) for row in db.all("SELECT * FROM response_shape_diffs WHERE analysis_id=? ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,confidence DESC", (analysis_id,))]
    protocols = [dict(row) for row in db.all("SELECT * FROM protocol_findings WHERE analysis_id=? ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,confidence DESC", (analysis_id,))]
    entities = [dict(row) for row in db.all("SELECT * FROM identity_entities WHERE analysis_id=? ORDER BY confidence DESC", (analysis_id,))]
    relations = [dict(row) for row in db.all("SELECT * FROM identity_relations WHERE analysis_id=? ORDER BY confidence DESC", (analysis_id,))]
    contexts = [dict(row) for row in db.all("SELECT * FROM behavioral_observations WHERE analysis_id=? ORDER BY confidence DESC", (analysis_id,))]
    return {
        "analysis_id": analysis_id,
        "engine_version": BEHAVIORAL_ENGINE_VERSION,
        "boundary_diffs": boundary,
        "response_shape_diffs": shapes,
        "protocol_findings": protocols,
        "identity_entities": entities,
        "identity_relations": relations,
        "context_observations": contexts,
        "counts": {
            "boundary_diffs": len(boundary), "response_shape_diffs": len(shapes), "protocol_findings": len(protocols),
            "identity_entities": len(entities), "identity_relations": len(relations), "context_observations": len(contexts),
            "high_priority": sum(1 for row in boundary + shapes + protocols if _severity_rank(str(row.get("severity") or "")) >= 3),
        },
    }
