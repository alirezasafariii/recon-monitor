from __future__ import annotations

"""Cross-surface correlation and investigation queue for Recon Monitor.

Correlation Engine V2 intentionally consumes only data already collected by the
recon/analysis pipeline.  It does not contact targets and it does not create
target evidence.  Its family scores are advisory priors for Meta Ranker.
"""

import json
import re
from collections import defaultdict
from typing import Any, Iterable, Mapping

from core import Database, sha256_text

CORRELATION_ENGINE_VERSION = "2.0.0"
CORRELATION_RULE_VERSION = "2026.08.10.1"

_OBJECT_STOPWORDS = {
    "api", "v1", "v2", "v3", "v4", "get", "post", "put", "patch", "delete",
    "create", "update", "list", "detail", "details", "data", "item", "items",
    "resource", "resources", "object", "objects", "id",
}
_IDENTITY_TOKENS = {"user", "owner", "member", "customer", "account", "tenant", "org", "organization", "profile"}
_PRIVILEGE_TOKENS = {"admin", "role", "permission", "privilege", "staff", "backoffice"}
_SENSITIVE_TOKENS = {
    "email", "phone", "address", "token", "secret", "password", "ssn", "card",
    "balance", "invoice", "customer", "user", "tenant", "session",
}


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def normalize_endpoint(value: str) -> str:
    """Normalize dynamic identifiers while preserving resource structure."""
    text = str(value or "").strip().lower()
    text = text.split("#", 1)[0]
    text = re.sub(r"([?&][^=&#]+)=([^&#]*)", r"\1={value}", text)
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "{uuid}", text, flags=re.I)
    text = re.sub(r"(?<![a-z0-9])\d{2,}(?![a-z0-9])", "{n}", text)
    text = re.sub(r"/+", "/", text)
    return text


def canonical_object_token(value: Any) -> str:
    token = _normalize(value)
    if not token:
        return ""
    token = token.replace("_ids", "").replace("_id", "")
    if token.endswith("ids") and len(token) > 4:
        token = token[:-3]
    elif token.endswith("id") and len(token) > 3:
        token = token[:-2].rstrip("_")
    aliases = {
        "userid": "user", "user_id": "user", "owner": "user", "ownerid": "user",
        "tenantid": "tenant", "organization": "org", "organizationid": "org",
        "orgid": "org", "accountid": "account", "customerid": "customer",
        "profileid": "profile", "orderid": "order", "invoiceid": "invoice",
    }
    token = aliases.get(token, token)
    return token if token and token not in _OBJECT_STOPWORDS else ""


def _endpoint_resource_tokens(endpoint: str) -> set[str]:
    path = normalize_endpoint(endpoint).split("?", 1)[0]
    result: set[str] = set()
    for raw in re.split(r"[/._{}:-]+", path):
        token = canonical_object_token(raw)
        if token and token not in {"https", "http", "com"}:
            result.add(token)
    return result


def _flatten_inputs(raw: Any) -> list[str]:
    data = _loads(raw, {})
    result: list[str] = []
    for value in data.values():
        if isinstance(value, list):
            result.extend(str(item) for item in value if str(item).strip())
    return result


def _surface_object_tokens(contract: Mapping[str, Any], relationships: Iterable[Mapping[str, Any]], shape: Mapping[str, Any] | None) -> set[str]:
    values: list[str] = []
    values.extend(_flatten_inputs(contract.get("input_fields_json")))
    values.extend(str(item) for item in _loads(contract.get("output_fields_json"), []) if str(item).strip())
    values.extend(_endpoint_resource_tokens(str(contract.get("endpoint") or "")))
    for relation in relationships:
        values.append(str(relation.get("parent_parameter") or ""))
        values.append(str(relation.get("child_parameter") or ""))
    if shape:
        values.extend(str(item) for item in _loads(shape.get("keys_json"), []) if str(item).strip())
    tokens = {canonical_object_token(value.split(".")[-1].replace("[]", "")) for value in values}
    return {token for token in tokens if token}


def _relation_signatures(rows: Iterable[Mapping[str, Any]]) -> set[str]:
    signatures: set[str] = set()
    for row in rows:
        parent = canonical_object_token(row.get("parent_parameter"))
        child = canonical_object_token(row.get("child_parameter"))
        relation = _normalize(row.get("relation"))
        if parent and child:
            signatures.add(f"{parent}:{relation or 'related'}:{child}")
    return signatures


def _safe_all(db: Database, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in db.all(query, params)]
    except Exception:
        return []


def _cluster_id(target: str, endpoints: Iterable[str], objects: Iterable[str]) -> str:
    basis = "|".join([
        str(target),
        ",".join(sorted(normalize_endpoint(value) for value in endpoints if value)),
        ",".join(sorted(set(objects))),
    ])
    return sha256_text("correlation-v2|" + basis)[:24]


def build_correlation_context(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "",
    alert_id: int | None = None,
    source_ref: str = "",
    max_related: int = 12,
) -> dict[str, Any]:
    """Build an explainable cross-endpoint object/auth cluster.

    All scores in this object are non-evidentiary correlation priors.  They can
    prioritize investigation but must never satisfy an admission gate.
    """
    contracts = _safe_all(
        db,
        "SELECT * FROM endpoint_contracts WHERE analysis_id=? AND target=? ORDER BY confidence DESC",
        (analysis_id, target),
    )
    relationships = _safe_all(
        db,
        "SELECT * FROM parameter_relationships WHERE analysis_id=? AND target=?",
        (analysis_id, target),
    )
    boundaries = _safe_all(
        db,
        "SELECT * FROM authentication_boundaries WHERE analysis_id=? AND target=?",
        (analysis_id, target),
    )
    shapes = _safe_all(
        db,
        "SELECT * FROM response_shape_fingerprints WHERE analysis_id=? AND target=?",
        (analysis_id, target),
    )
    candidates = _safe_all(
        db,
        "SELECT candidate_id,bug_family,endpoint,alert_id,source_ref,investigation_value,candidate_state "
        "FROM bug_candidates WHERE analysis_id=? AND target=?",
        (analysis_id, target),
    )

    relations_by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in relationships:
        relations_by_endpoint[normalize_endpoint(str(row.get("endpoint") or ""))].append(row)
    boundary_by_endpoint = {
        normalize_endpoint(str(row.get("endpoint") or "")): row for row in boundaries
    }
    shape_by_endpoint = {
        normalize_endpoint(str(row.get("endpoint") or "")): row for row in shapes
    }
    candidates_by_endpoint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidates:
        candidates_by_endpoint[normalize_endpoint(str(row.get("endpoint") or ""))].append(row)

    surfaces: list[dict[str, Any]] = []
    for contract in contracts:
        raw_endpoint = str(contract.get("endpoint") or "")
        normalized = normalize_endpoint(raw_endpoint)
        rels = relations_by_endpoint.get(normalized, [])
        boundary = boundary_by_endpoint.get(normalized, {})
        shape = shape_by_endpoint.get(normalized, {})
        objects = _surface_object_tokens(contract, rels, shape)
        resources = _endpoint_resource_tokens(raw_endpoint)
        relation_signatures = _relation_signatures(rels)
        sensitive = {
            canonical_object_token(str(value).split(".")[-1].replace("[]", ""))
            for value in _loads(shape.get("sensitive_keys_json"), [])
        } if shape else set()
        sensitive = {value for value in sensitive if value}
        surfaces.append({
            "endpoint": raw_endpoint,
            "normalized_endpoint": normalized,
            "alert_id": contract.get("alert_id"),
            "method": str(contract.get("method") or "UNKNOWN"),
            "objects": sorted(objects),
            "resources": sorted(resources),
            "relations": sorted(relation_signatures),
            "auth_boundary": str(boundary.get("boundary") or contract.get("auth_boundary") or "unknown"),
            "boundary_confidence": int(boundary.get("confidence") or 0),
            "contract_confidence": int(contract.get("confidence") or 0),
            "sensitive_tokens": sorted(sensitive),
            "candidates": candidates_by_endpoint.get(normalized, []),
        })

    seed_norm = normalize_endpoint(endpoint)
    seed_candidates = [
        row for row in candidates
        if (alert_id is not None and row.get("alert_id") == alert_id)
        or (source_ref and str(row.get("source_ref") or "") == source_ref)
        or (seed_norm and normalize_endpoint(str(row.get("endpoint") or "")) == seed_norm)
    ]
    seed = next(
        (
            surface for surface in surfaces
            if (seed_norm and surface["normalized_endpoint"] == seed_norm)
            or (alert_id is not None and surface.get("alert_id") == alert_id)
        ),
        None,
    )
    if seed is None:
        seed = {
            "endpoint": endpoint or source_ref,
            "normalized_endpoint": seed_norm or normalize_endpoint(source_ref),
            "alert_id": alert_id,
            "method": "UNKNOWN",
            "objects": sorted(_endpoint_resource_tokens(endpoint or source_ref)),
            "resources": sorted(_endpoint_resource_tokens(endpoint or source_ref)),
            "relations": [],
            "auth_boundary": "unknown",
            "boundary_confidence": 0,
            "contract_confidence": 0,
            "sensitive_tokens": [],
            "candidates": seed_candidates,
        }

    seed_objects = set(seed["objects"])
    seed_resources = set(seed["resources"])
    seed_relations = set(seed["relations"])
    edges: list[dict[str, Any]] = []
    related: list[dict[str, Any]] = []

    for surface in surfaces:
        score = 0
        reasons: list[str] = []
        objects = set(surface["objects"])
        resources = set(surface["resources"])
        relations = set(surface["relations"])
        shared_objects = sorted(seed_objects & objects)
        shared_resources = sorted(seed_resources & resources)
        shared_relations = sorted(seed_relations & relations)

        if surface["normalized_endpoint"] == seed["normalized_endpoint"] and seed["normalized_endpoint"]:
            score = 100
            reasons.append("same normalized endpoint")
        else:
            if alert_id is not None and surface.get("alert_id") == alert_id:
                score += 45
                reasons.append("same alert")
            if shared_objects:
                score += min(48, len(shared_objects) * 18)
                reasons.append("shared object model: " + ", ".join(shared_objects[:6]))
            if shared_resources:
                score += min(24, len(shared_resources) * 8)
                reasons.append("shared resource vocabulary: " + ", ".join(shared_resources[:6]))
            if shared_relations:
                score += min(24, len(shared_relations) * 12)
                reasons.append("shared parameter relation: " + ", ".join(shared_relations[:4]))
            if seed["auth_boundary"] != "unknown" and surface["auth_boundary"] == seed["auth_boundary"]:
                score += 8
                reasons.append("same authentication boundary")
            elif (
                seed["auth_boundary"] != "unknown"
                and surface["auth_boundary"] != "unknown"
                and surface["auth_boundary"] != seed["auth_boundary"]
                and (shared_objects or shared_resources)
            ):
                score += 12
                reasons.append(
                    f"auth-boundary differential: {seed['auth_boundary']} -> {surface['auth_boundary']}"
                )
            if source_ref and any(str(c.get("source_ref") or "") == source_ref for c in surface["candidates"]):
                score += 15
                reasons.append("same semantic/source reference")

        score = _clamp(score)
        if score < 28:
            continue
        node = dict(surface)
        node["correlation_score"] = score
        node["correlation_reasons"] = reasons
        related.append(node)
        if surface["normalized_endpoint"] != seed["normalized_endpoint"]:
            edges.append({
                "from": seed["endpoint"],
                "to": surface["endpoint"],
                "score": score,
                "reasons": reasons,
            })

    if not related:
        related = [{**seed, "correlation_score": 100, "correlation_reasons": ["seed surface"]}]
    related.sort(key=lambda item: (int(item["correlation_score"]), int(item.get("contract_confidence") or 0)), reverse=True)
    related = related[: max(1, max_related)]

    cluster_objects = sorted({obj for item in related for obj in item.get("objects", [])})
    cluster_resources = sorted({obj for item in related for obj in item.get("resources", [])})
    cluster_boundaries = sorted({str(item.get("auth_boundary") or "unknown") for item in related})
    cluster_sensitive = sorted({obj for item in related for obj in item.get("sensitive_tokens", [])})
    endpoints = [str(item.get("endpoint") or "") for item in related if str(item.get("endpoint") or "").strip()]
    cluster_id = _cluster_id(target, endpoints, cluster_objects)

    family_scores: dict[str, int] = {}
    family_reasons: dict[str, list[str]] = defaultdict(list)

    # Existing promoted candidates on related surfaces provide the strongest
    # correlation prior, still explicitly non-evidentiary.
    for item in related:
        similarity = int(item.get("correlation_score") or 0)
        for candidate in item.get("candidates", []):
            family = str(candidate.get("bug_family") or "").strip()
            if not family:
                continue
            investigation = _clamp(float(candidate.get("investigation_value") or 0))
            contribution = _clamp(similarity * 0.55 + investigation * 0.30, 0, 88)
            family_scores[family] = max(family_scores.get(family, 0), contribution)
            family_reasons[family].append(
                f"related candidate on {item.get('endpoint')}: similarity={similarity}, investigation={investigation}"
            )

    multi_surface = len({normalize_endpoint(value) for value in endpoints if value}) >= 2
    identity_objects = sorted(set(cluster_objects) & _IDENTITY_TOKENS)
    privilege_objects = sorted((set(cluster_objects) | set(cluster_resources)) & _PRIVILEGE_TOKENS)
    boundary_differential = len({value for value in cluster_boundaries if value != "unknown"}) >= 2
    sensitive_cluster = bool(cluster_sensitive) or bool((set(cluster_objects) | set(cluster_resources)) & _SENSITIVE_TOKENS)

    def heuristic(family: str, score: int, reason: str) -> None:
        family_scores[family] = max(family_scores.get(family, 0), score)
        family_reasons[family].append(reason)

    if multi_surface and identity_objects:
        heuristic(
            "broken_object_authorization",
            min(72, 48 + len(identity_objects) * 6 + (10 if boundary_differential else 0)),
            "multiple related endpoints share identity/object vocabulary"
            + (" with different auth boundaries" if boundary_differential else ""),
        )
    if multi_surface and privilege_objects:
        heuristic(
            "broken_function_authorization",
            min(70, 46 + len(privilege_objects) * 7 + (8 if boundary_differential else 0)),
            "privileged resources/functions appear across a related endpoint cluster",
        )
    if sensitive_cluster and multi_surface:
        heuristic(
            "information_disclosure",
            min(62, 38 + min(18, len(cluster_sensitive) * 4)),
            "related surfaces expose sensitive-looking response/object vocabulary",
        )
    if any("graphql" in normalize_endpoint(value) for value in endpoints):
        heuristic(
            "graphql_authorization",
            46 + (10 if identity_objects else 0),
            "GraphQL surface is connected to identity/object resources",
        )

    family_scores = {family: _clamp(score, 0, 88) for family, score in family_scores.items()}
    cluster_strength = _clamp(
        max((int(item.get("correlation_score") or 0) for item in related), default=0) * 0.45
        + min(35, max(0, len(related) - 1) * 9)
        + min(20, len(cluster_objects) * 4),
        0,
        95,
    )

    return {
        "engine_version": CORRELATION_ENGINE_VERSION,
        "rule_version": CORRELATION_RULE_VERSION,
        "role": "non_evidentiary_cross_surface_prior",
        "cluster_id": cluster_id,
        "cluster_strength": cluster_strength,
        "seed": {
            "endpoint": seed["endpoint"],
            "normalized_endpoint": seed["normalized_endpoint"],
            "objects": list(seed["objects"]),
            "auth_boundary": seed["auth_boundary"],
        },
        "related_surfaces": related,
        "edges": edges,
        "object_tokens": cluster_objects,
        "resource_tokens": cluster_resources,
        "auth_boundaries": cluster_boundaries,
        "sensitive_tokens": cluster_sensitive,
        "family_scores": family_scores,
        "family_reasons": {key: value[:8] for key, value in family_reasons.items()},
        "safety": {
            "correlation_is_not_target_evidence": True,
            "cannot_satisfy_admission": True,
            "cannot_confirm_vulnerability": True,
        },
    }


def correlation_family_scores(
    db: Database,
    *,
    analysis_id: str,
    target: str,
    endpoint: str = "",
    alert_id: int | None = None,
    source_ref: str = "",
) -> dict[str, int]:
    return dict(
        build_correlation_context(
            db,
            analysis_id=analysis_id,
            target=target,
            endpoint=endpoint,
            alert_id=alert_id,
            source_ref=source_ref,
        ).get("family_scores", {})
    )


def investigation_queue(
    db: Database,
    analysis_id: str,
    *,
    target: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Return cluster-deduplicated investigation work, highest value first."""
    where = "WHERE analysis_id=?"
    params: list[Any] = [analysis_id]
    if target:
        where += " AND target=?"
        params.append(target)
    hypotheses = _safe_all(
        db,
        f"SELECT hypothesis_id,target,asset,endpoint,source_ref,alert_id,bug_family,state,summary,admission_json "
        f"FROM analysis_hypotheses {where}",
        tuple(params),
    )
    grouped: dict[str, dict[str, Any]] = {}

    for row in hypotheses:
        admission = _loads(row.get("admission_json"), {})
        knowledge = admission.get("knowledge_context", {}) if isinstance(admission, Mapping) else {}
        meta = knowledge.get("meta_ranker", {}) if isinstance(knowledge, Mapping) else {}
        primary = meta.get("primary") if isinstance(meta, Mapping) else None
        if not isinstance(primary, Mapping):
            continue
        context = build_correlation_context(
            db,
            analysis_id=analysis_id,
            target=str(row.get("target") or ""),
            endpoint=str(row.get("endpoint") or ""),
            alert_id=row.get("alert_id"),
            source_ref=str(row.get("source_ref") or ""),
        )
        cluster_id = str(context.get("cluster_id") or row.get("hypothesis_id"))
        proximity = _clamp(float(primary.get("bug_proximity_score") or 0))
        evidence = _clamp(float(primary.get("target_evidence_confidence") or 0))
        cluster_strength = _clamp(float(context.get("cluster_strength") or 0))
        priority_bonus = {"HIGH": 90, "MEDIUM": 60, "LOW": 35, "NOISE": 10}.get(
            str(primary.get("hunt_priority") or "NOISE").upper(), 10
        )
        queue_score = _clamp(
            proximity * 0.42 + evidence * 0.28 + cluster_strength * 0.18 + priority_bonus * 0.12
        )
        item = grouped.setdefault(
            cluster_id,
            {
                "cluster_id": cluster_id,
                "target": str(row.get("target") or ""),
                "queue_score": 0,
                "primary_bug": str(primary.get("label") or primary.get("family") or row.get("bug_family") or ""),
                "primary_family": str(primary.get("family") or row.get("bug_family") or ""),
                "bug_proximity_score": proximity,
                "target_evidence_confidence": evidence,
                "hunt_priority": str(primary.get("hunt_priority") or "NOISE"),
                "cluster_strength": cluster_strength,
                "endpoints": [],
                "hypothesis_ids": [],
                "families": {},
                "object_tokens": list(context.get("object_tokens", [])),
                "auth_boundaries": list(context.get("auth_boundaries", [])),
                "why": list(primary.get("why", [])),
                "status": "investigation_queue_not_confirmed",
            },
        )
        item["queue_score"] = max(int(item["queue_score"]), queue_score)
        item["bug_proximity_score"] = max(int(item["bug_proximity_score"]), proximity)
        item["target_evidence_confidence"] = max(int(item["target_evidence_confidence"]), evidence)
        item["cluster_strength"] = max(int(item["cluster_strength"]), cluster_strength)
        endpoint_value = str(row.get("endpoint") or "")
        if endpoint_value and endpoint_value not in item["endpoints"]:
            item["endpoints"].append(endpoint_value)
        hypothesis_id = str(row.get("hypothesis_id") or "")
        if hypothesis_id and hypothesis_id not in item["hypothesis_ids"]:
            item["hypothesis_ids"].append(hypothesis_id)
        for ranking in meta.get("rankings", []) if isinstance(meta, Mapping) else []:
            if not isinstance(ranking, Mapping):
                continue
            family = str(ranking.get("family") or "")
            if family:
                item["families"][family] = max(
                    int(item["families"].get(family, 0)),
                    _clamp(float(ranking.get("bug_proximity_score") or 0)),
                )

    queue = list(grouped.values())
    for item in queue:
        item["families"] = [
            {"family": family, "score": score}
            for family, score in sorted(
                item["families"].items(), key=lambda pair: pair[1], reverse=True
            )[:3]
        ]
        item["endpoints"] = item["endpoints"][:12]
        item["hypothesis_ids"] = item["hypothesis_ids"][:50]
    queue.sort(
        key=lambda item: (
            int(item["queue_score"]),
            int(item["bug_proximity_score"]),
            int(item["target_evidence_confidence"]),
        ),
        reverse=True,
    )
    return queue[: max(1, int(limit))]
