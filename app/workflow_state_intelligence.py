from __future__ import annotations

"""Offline workflow/state-machine intelligence for business-logic analysis.

The engine derives a conservative workflow graph from stored endpoint contracts.
It identifies multi-step resources, privileged approval paths and single-use or
financial operations. All output is context-only and non-decisive: route names
and inferred ordering can guide investigation but cannot prove a workflow flaw.
"""

import re
import urllib.parse
import uuid
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from core import Database, json_dumps, parse_int, utc_now

WORKFLOW_STATE_ENGINE_VERSION = "1.0.1"
WORKFLOW_STATE_RULE_VERSION = "2026.08.14.2"

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ACTION_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("create", ("create", "new", "register", "init", "initialize", "start", "open")),
    ("submit", ("submit", "send", "request", "apply", "checkout")),
    ("review", ("review", "inspect", "validate", "verify")),
    ("approve", ("approve", "accept", "authorize", "confirm")),
    ("reject", ("reject", "deny", "decline")),
    ("cancel", ("cancel", "void", "abort")),
    ("pay", ("pay", "payment", "charge", "checkout", "purchase")),
    ("transfer", ("transfer", "withdraw", "deposit", "payout")),
    ("refund", ("refund", "reimburse", "chargeback")),
    ("redeem", ("redeem", "claim", "consume", "use")),
    ("complete", ("complete", "finish", "close", "finalize", "settle")),
    ("update", ("update", "edit", "patch", "modify", "change")),
    ("delete", ("delete", "remove", "destroy")),
)
ACTION_ORDER = {
    "create": 10,
    "submit": 20,
    "review": 30,
    "approve": 40,
    "pay": 50,
    "transfer": 50,
    "redeem": 50,
    "refund": 60,
    "complete": 70,
    "reject": 80,
    "cancel": 80,
    "update": 90,
    "delete": 100,
    "access": 110,
}
PRIVILEGED_ACTIONS = {"approve", "reject", "refund", "transfer", "delete"}
SINGLE_USE_OR_FINANCIAL = {"pay", "transfer", "refund", "redeem", "approve"}
RESOURCE_STOPWORDS = {
    "api", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
    "create", "new", "register", "init", "initialize", "start", "open",
    "submit", "send", "request", "apply", "checkout", "review", "inspect",
    "validate", "verify", "approve", "accept", "authorize", "confirm",
    "reject", "deny", "decline", "cancel", "void", "abort", "pay", "payment",
    "charge", "purchase", "transfer", "withdraw", "deposit", "payout", "refund",
    "reimburse", "chargeback", "redeem", "claim", "consume", "use", "complete",
    "finish", "close", "finalize", "settle", "update", "edit", "patch", "modify",
    "change", "delete", "remove", "destroy",
}


def _tokens(endpoint: str) -> list[str]:
    try:
        path = urllib.parse.urlsplit(endpoint if "://" in endpoint else f"https://placeholder.invalid/{endpoint.lstrip('/')}").path
    except ValueError:
        path = endpoint
    return [
        token.lower()
        for token in re.split(r"[^A-Za-z0-9]+", path)
        if token
    ]


def _looks_identifier(token: str) -> bool:
    token = str(token or "").lower()
    if token in {"id", "uuid", "pk"}:
        return True
    if token.isdigit():
        return True
    if re.fullmatch(r"[0-9a-f]{8,}", token, re.I):
        return True
    if token.startswith("uuid") and len(token) > 4:
        return True
    if token.endswith("id") and len(token) > 4:
        return True
    return False


def _action(endpoint: str, method: str) -> str:
    tokens = set(_tokens(endpoint))
    for action, markers in ACTION_PATTERNS:
        if any(marker in tokens for marker in markers):
            return action
    method = str(method or "UNKNOWN").upper()
    if method == "POST":
        return "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "DELETE":
        return "delete"
    return "access"


def _resource_key(endpoint: str) -> str:
    tokens = []
    for token in _tokens(endpoint):
        if token in RESOURCE_STOPWORDS or _looks_identifier(token):
            continue
        if re.fullmatch(r"v\d+", token):
            continue
        tokens.append(token)
    if not tokens:
        return "generic"
    return "/".join(tokens[-3:])


def _insert_workflow_finding(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str,
    kind: str,
    confidence: int,
    severity: str,
    summary: str,
    evidence: Mapping[str, Any],
) -> None:
    finding_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"recon-monitor:{analysis_id}:{target}:workflow:{endpoint}:{kind}",
        )
    )
    payload = dict(evidence)
    payload.update(
        {
            "workflow_state_engine_version": WORKFLOW_STATE_ENGINE_VERSION,
            "rule_version": WORKFLOW_STATE_RULE_VERSION,
            "context_only": True,
            "non_decisive": True,
            "route_semantics_are_not_behavioral_proof": True,
            "active_request_performed": False,
        }
    )
    db.execute(
        """INSERT OR REPLACE INTO protocol_findings(
        finding_id,analysis_id,target,protocol,entity,kind,confidence,severity,summary,evidence_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            finding_id,
            analysis_id,
            target,
            "workflow",
            endpoint,
            kind,
            max(0, min(100, int(confidence))),
            severity,
            summary,
            json_dumps(payload),
            utc_now(),
        ),
    )


def _contract_rows(db: Database, analysis_id: str, target: str) -> list[dict[str, Any]]:
    try:
        return [
            dict(row)
            for row in db.all(
                "SELECT endpoint,method,auth_boundary,confidence,input_fields_json,output_fields_json "
                "FROM endpoint_contracts WHERE analysis_id=? AND target=? ORDER BY endpoint,method",
                (analysis_id, target),
            )
        ]
    except Exception:
        return []


def generate_workflow_state_intelligence(
    db: Database,
    analysis_id: str,
    targets: Iterable[str],
) -> dict[str, Any]:
    counts = Counter()
    per_target: dict[str, Any] = {}

    for target in sorted(set(str(value) for value in targets if str(value))):
        rows = _contract_rows(db, analysis_id, target)
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        target_counts = Counter()

        for row in rows:
            endpoint = str(row.get("endpoint") or "")
            method = str(row.get("method") or "UNKNOWN").upper()
            action = _action(endpoint, method)
            resource = _resource_key(endpoint)
            enriched = dict(row)
            enriched.update({"action": action, "resource": resource})
            grouped[resource].append(enriched)

            if method in STATE_CHANGING_METHODS and action in SINGLE_USE_OR_FINANCIAL:
                confidence = min(90, 58 + parse_int(row.get("confidence"), 50) // 4 + (8 if action in {"refund", "transfer", "redeem"} else 0))
                _insert_workflow_finding(
                    db,
                    analysis_id=analysis_id,
                    target=target,
                    endpoint=endpoint,
                    kind="single_use_or_financial_workflow_surface",
                    confidence=confidence,
                    severity="medium",
                    summary=f"Stored endpoint contract exposes a state-changing {action} workflow surface.",
                    evidence={
                        "resource": resource,
                        "action": action,
                        "method": method,
                        "auth_boundary": str(row.get("auth_boundary") or ""),
                    },
                )
                counts["single_use_or_financial"] += 1
                target_counts["single_use_or_financial"] += 1

            if method in STATE_CHANGING_METHODS and action in PRIVILEGED_ACTIONS:
                _insert_workflow_finding(
                    db,
                    analysis_id=analysis_id,
                    target=target,
                    endpoint=endpoint,
                    kind="privileged_workflow_surface",
                    confidence=min(88, 56 + parse_int(row.get("confidence"), 50) // 4),
                    severity="medium",
                    summary=f"Stored endpoint contract exposes a potentially privileged {action} transition.",
                    evidence={
                        "resource": resource,
                        "action": action,
                        "method": method,
                        "auth_boundary": str(row.get("auth_boundary") or ""),
                    },
                )
                counts["privileged"] += 1
                target_counts["privileged"] += 1

        for resource, members in grouped.items():
            actions = sorted(
                {str(item.get("action") or "access") for item in members},
                key=lambda value: (ACTION_ORDER.get(value, 999), value),
            )
            if len(actions) < 2:
                continue
            transitions = [
                {"from": before, "to": after}
                for before, after in zip(actions, actions[1:])
                if before != after
            ]
            methods = sorted({str(item.get("method") or "UNKNOWN") for item in members})
            endpoints = sorted({str(item.get("endpoint") or "") for item in members if str(item.get("endpoint") or "")})
            protected = sorted({
                str(item.get("auth_boundary") or "")
                for item in members
                if str(item.get("auth_boundary") or "")
            })
            has_sensitive_sequence = bool(set(actions) & {"approve", "refund", "transfer", "redeem", "pay"})
            confidence = min(
                94,
                52
                + len(actions) * 7
                + min(12, len(methods) * 3)
                + (10 if has_sensitive_sequence else 0),
            )
            evidence = {
                "resource": resource,
                "actions": actions,
                "transitions": transitions,
                "methods": methods,
                "endpoints": endpoints,
                "auth_boundaries": protected,
                "member_count": len(members),
            }
            for endpoint in endpoints:
                _insert_workflow_finding(
                    db,
                    analysis_id=analysis_id,
                    target=target,
                    endpoint=endpoint,
                    kind="workflow_state_machine_surface",
                    confidence=confidence,
                    severity="medium" if has_sensitive_sequence else "low",
                    summary=f"Stored endpoint contracts form a {len(actions)}-stage workflow for resource {resource}.",
                    evidence=evidence,
                )
            counts["state_machines"] += 1
            counts["workflow_transition_edges"] += len(transitions)
            target_counts["state_machines"] += 1
            target_counts["workflow_transition_edges"] += len(transitions)

        per_target[target] = {
            "endpoint_contracts": len(rows),
            "resource_groups": len(grouped),
            **dict(target_counts),
        }

    return {
        "version": WORKFLOW_STATE_ENGINE_VERSION,
        "rule_version": WORKFLOW_STATE_RULE_VERSION,
        "counts": dict(counts),
        "targets": per_target,
        "safety": {
            "stored_contracts_only": True,
            "network_requests": False,
            "context_only": True,
            "can_confirm_business_logic": False,
            "route_names_do_not_prove_state_machine_failure": True,
        },
    }


__all__ = [
    "WORKFLOW_STATE_ENGINE_VERSION",
    "WORKFLOW_STATE_RULE_VERSION",
    "generate_workflow_state_intelligence",
]
