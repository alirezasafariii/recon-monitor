from __future__ import annotations

"""Dashboard compatibility surface for vulnerability-intelligence UI extensions.

The established dashboard implementation is retained verbatim in ``dashboard_core``.
This module preserves the public ``dashboard`` import contract and layers the
Investigation Queue / Meta Ranker / Correlation Engine onto the existing Analysis
and Potential Findings workspaces without changing the primary navigation.
"""

import urllib.parse
from collections import defaultdict
from typing import Any, Callable

import dashboard_core as _base
from correlation_engine import CORRELATION_ENGINE_VERSION, investigation_queue
from meta_ranker import META_RANKER_VERSION


DASHBOARD_INTELLIGENCE_INTEGRATION_VERSION = "1.0.0"

# Re-export the complete legacy dashboard contract, including private helpers that
# are intentionally imported by the regression suite.  Keep module identity fields
# local so tracebacks and runtime metadata continue to point at this compatibility
# surface rather than at dashboard_core.
for _name, _value in vars(_base).items():
    if _name not in {
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__file__",
        "__cached__",
        "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_ANALYSIS_ENGINE = _base.DashboardHandler.analysis_engine
_ORIGINAL_BUG_CANDIDATES = _base.DashboardHandler.bug_candidates


def _capture_html(self: Any, renderer: Callable[[Any], None]) -> tuple[str, str, int]:
    """Capture one existing page render so an additive panel can be inserted safely."""
    captured: dict[str, Any] = {}
    had_instance_send = "send_html" in getattr(self, "__dict__", {})
    previous_instance_send = getattr(self, "__dict__", {}).get("send_html")

    def capture(title: str, body: str, status: int = 200) -> None:
        captured.update(title=title, body=body, status=status)

    self.send_html = capture
    try:
        renderer(self)
    finally:
        if had_instance_send:
            self.send_html = previous_instance_send
        else:
            self.__dict__.pop("send_html", None)

    if not captured:
        raise RuntimeError("Dashboard renderer completed without producing HTML")
    return (
        str(captured.get("title") or "Recon Monitor"),
        str(captured.get("body") or ""),
        int(captured.get("status") or 200),
    )


def _latest_analysis_queue(self: Any, *, target: str = "", limit: int = 50) -> tuple[str, list[dict[str, Any]]]:
    db = self.db()
    try:
        latest = db.one(
            "SELECT id FROM analysis_runs WHERE status='success' "
            "ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1"
        )
        analysis_id = str(latest["id"]) if latest else ""
        queue = (
            investigation_queue(db, analysis_id, target=target or None, limit=limit)
            if analysis_id
            else []
        )
    finally:
        db.close()
    return analysis_id, queue


def _insert_before(body: str, needle: str, fragment: str) -> str:
    index = body.find(needle)
    if index < 0:
        return body + fragment
    return body[:index] + fragment + body[index:]


def _family_summary(queue: list[dict[str, Any]], limit: int = 5) -> list[tuple[str, int, int]]:
    scores: dict[str, int] = defaultdict(int)
    counts: dict[str, int] = defaultdict(int)
    for item in queue:
        seen: set[str] = set()
        rankings = item.get("families") if isinstance(item.get("families"), list) else []
        for ranking in rankings:
            if not isinstance(ranking, dict):
                continue
            family = str(ranking.get("family") or "").strip()
            if not family:
                continue
            scores[family] = max(scores[family], _base.parse_int(ranking.get("score"), 0, 0, 100))
            if family not in seen:
                counts[family] += 1
                seen.add(family)
        primary = str(item.get("primary_family") or "").strip()
        if primary and primary not in seen:
            scores[primary] = max(scores[primary], _base.parse_int(item.get("bug_proximity_score"), 0, 0, 100))
            counts[primary] += 1
    ordered = sorted(scores, key=lambda family: (scores[family], counts[family], family), reverse=True)
    return [(family, scores[family], counts[family]) for family in ordered[: max(1, limit)]]


def _analysis_intelligence_panel(analysis_id: str, queue: list[dict[str, Any]]) -> str:
    if not analysis_id:
        return (
            "<section class='panel' id='vulnerability-intelligence' style='margin-top:16px'>"
            "<div class='panel-head'><h3>Vulnerability Intelligence</h3>"
            + _base._pill("not run", "neutral")
            + "</div><div class='panel-body'>"
            + _base._empty(
                "No vulnerability-intelligence context yet",
                "A completed analysis run is required before Meta Ranker and cross-surface correlation can be summarized.",
            )
            + "</div></section>"
        )

    count = len(queue)
    avg_proximity = round(
        sum(_base.parse_int(item.get("bug_proximity_score"), 0, 0, 100) for item in queue) / count
    ) if count else 0
    avg_evidence = round(
        sum(_base.parse_int(item.get("target_evidence_confidence"), 0, 0, 100) for item in queue) / count
    ) if count else 0
    strong_clusters = sum(1 for item in queue if _base.parse_int(item.get("cluster_strength"), 0, 0, 100) >= 60)
    high_priority = sum(1 for item in queue if str(item.get("hunt_priority") or "").upper() == "HIGH")
    families = _family_summary(queue)
    family_rows = "".join(
        f"<tr><td>{_base._esc(family.replace('_',' '))}</td><td><strong>{score}</strong></td><td>{clusters}</td></tr>"
        for family, score, clusters in families
    )
    family_table = (
        "<div class='table-wrap' style='border:0;border-radius:0'><table>"
        "<thead><tr><th>Leading family</th><th>Proximity</th><th>Clusters</th></tr></thead>"
        f"<tbody>{family_rows or '<tr><td colspan=3>No ranked family context is available yet.</td></tr>'}</tbody>"
        "</table></div>"
    )
    metrics = "<div class='metrics-grid'>" + "".join(
        [
            _base._metric_card("Investigation clusters", count, "Cross-surface hypotheses deduplicated by cluster", "blue", "/potential-findings#investigation-queue"),
            _base._metric_card("Average bug proximity", f"{avg_proximity}%", "Meta Ranker proximity — not vulnerability confidence", "purple"),
            _base._metric_card("Average target evidence", f"{avg_evidence}%", "Uses target observations only", "success" if avg_evidence >= 60 else "amber"),
            _base._metric_card("Strong correlations", strong_clusters, "Clusters with cross-surface strength ≥60", "orange"),
            _base._metric_card("High hunt priority", high_priority, "Prioritized for analyst attention, not confirmation", "danger" if high_priority else "neutral"),
        ]
    ) + "</div>"
    return (
        "<section class='panel' id='vulnerability-intelligence' style='margin-top:16px'>"
        "<div class='panel-head'><div><h3>Vulnerability Intelligence</h3>"
        f"<span class='muted small'>Meta Ranker { _base._esc(META_RANKER_VERSION) } · Correlation Engine { _base._esc(CORRELATION_ENGINE_VERSION) }</span></div>"
        + _base._pill("advisory context", "info")
        + "</div><div class='panel-body'>"
        + metrics
        + "<div class='callout' style='margin-top:14px'><strong>Evidence boundary preserved</strong>"
        "<span>Bug proximity and cross-surface correlation rank where to investigate. They cannot satisfy admission, create an independent evidence root, raise target-evidence confidence, or confirm a vulnerability.</span></div>"
        + "<div style='margin-top:14px'>"
        + family_table
        + "</div></div></section>"
    )


def _queue_item_card(item: dict[str, Any]) -> str:
    queue_score = _base.parse_int(item.get("queue_score"), 0, 0, 100)
    proximity = _base.parse_int(item.get("bug_proximity_score"), 0, 0, 100)
    evidence = _base.parse_int(item.get("target_evidence_confidence"), 0, 0, 100)
    cluster = _base.parse_int(item.get("cluster_strength"), 0, 0, 100)
    target = str(item.get("target") or "")
    family = str(item.get("primary_family") or "")
    label = str(item.get("primary_bug") or family or "Investigation cluster")
    priority = str(item.get("hunt_priority") or "NOISE").upper()
    endpoints = [str(value) for value in item.get("endpoints", []) if str(value).strip()]
    families = [value for value in item.get("families", []) if isinstance(value, dict)]
    why = [str(value) for value in item.get("why", []) if str(value).strip()]
    object_tokens = [str(value) for value in item.get("object_tokens", []) if str(value).strip()]
    boundaries = [str(value) for value in item.get("auth_boundaries", []) if str(value).strip()]

    endpoint_preview = "".join(f"<code>{_base._esc(value)}</code> " for value in endpoints[:4]) or "<span class='muted'>No endpoint recorded</span>"
    family_preview = " ".join(
        _base._pill(f"{str(row.get('family') or '').replace('_',' ')} { _base.parse_int(row.get('score'),0,0,100) }")
        for row in families[:3]
        if str(row.get("family") or "").strip()
    )
    why_html = "".join(f"<li>{_base._esc(reason)}</li>" for reason in why[:4]) or "<li>No additional ranking explanation recorded.</li>"
    context_parts = []
    if object_tokens:
        context_parts.append("objects: " + ", ".join(object_tokens[:6]))
    if boundaries:
        context_parts.append("auth: " + ", ".join(boundaries[:4]))
    context = " · ".join(context_parts) or "Cross-surface context is limited for this cluster."
    filter_href = _base._query_link("/potential-findings", target=target, family=family)

    return (
        f"<article class='candidate-card investigation-queue-card' data-cluster-id='{_base._esc(item.get('cluster_id') or '')}'>"
        f"<div class='candidate-accent tone-{_base._tone(priority)}'></div><div class='candidate-main'>"
        "<div class='candidate-heading'><div>"
        f"<div class='candidate-kicker'>{_base._pill(priority)}{_base._pill('not confirmed','neutral')}<span>{_base._esc(target)}</span></div>"
        f"<h3>{_base._esc(label)}</h3><div class='muted small'>{endpoint_preview}</div></div>"
        f"<div class='investigation-score'><span>Queue</span><strong>{queue_score}</strong></div></div>"
        "<div class='score-triad'>"
        f"<div><span>Bug proximity</span><strong class='tone-purple'>{proximity}</strong></div>"
        f"<div><span>Target evidence</span><strong class='tone-info'>{evidence}</strong></div>"
        f"<div><span>Cluster strength</span><strong class='tone-orange'>{cluster}</strong></div>"
        f"<div><span>Surfaces</span><strong class='tone-success'>{len(endpoints)}</strong></div>"
        "</div>"
        f"<div class='candidate-reasoning'><div><strong>Top families</strong><p>{family_preview or 'No ranked alternatives recorded.'}</p></div>"
        f"<div><strong>Why it deserves review</strong><ul>{why_html}</ul></div>"
        f"<div><strong>Correlation context</strong><p>{_base._esc(context)}</p></div></div>"
        "<div class='next-step'><span>Interpretation</span><p>This cluster is an investigation priority only. Review the underlying Potential Findings and target evidence before any vulnerability claim.</p></div>"
        f"</div><a class='candidate-open' href='{_base._esc(filter_href)}'>Open findings →</a></article>"
    )


def _investigation_queue_panel(analysis_id: str, queue: list[dict[str, Any]]) -> str:
    high = sum(1 for item in queue if str(item.get("hunt_priority") or "").upper() == "HIGH")
    strong = sum(1 for item in queue if _base.parse_int(item.get("cluster_strength"), 0, 0, 100) >= 60)
    content = "".join(_queue_item_card(item) for item in queue[:8])
    if not content:
        content = _base._empty(
            "No investigation clusters match this view",
            "Potential Findings remain available below. A cluster appears here only when a persisted Meta Ranker result can be correlated across the selected analysis context.",
        )
    return (
        "<section class='panel' id='investigation-queue' style='margin-top:16px'>"
        "<div class='panel-head'><div><h3>Investigation Queue</h3>"
        "<span class='muted small'>Cluster-deduplicated priorities inside Potential Findings · not a confirmation queue</span></div>"
        + _base._pill("investigation only", "info")
        + "</div><div class='panel-body'>"
        "<div class='attention-grid'>"
        f"<div class='attention-card'><span>Clusters</span><strong>{len(queue)}</strong><small>deduplicated work items</small></div>"
        f"<div class='attention-card'><span>High priority</span><strong>{high}</strong><small>hunt priority HIGH</small></div>"
        f"<div class='attention-card'><span>Strong correlation</span><strong>{strong}</strong><small>cluster strength ≥60</small></div>"
        f"<div class='attention-card'><span>Analysis</span><strong>{_base._esc(analysis_id[:8] if analysis_id else '—')}</strong><small>latest completed analysis</small></div>"
        "</div>"
        "<div class='callout' style='margin-top:14px'><strong>What this queue changes</strong>"
        "<span>Related hypotheses are collapsed into analyst-sized clusters and ranked by proximity, target evidence, cluster strength and hunt priority. The complete Potential Findings inventory remains below and unchanged.</span></div>"
        f"<div class='stack' style='margin-top:16px'>{content}</div>"
        "</div></section>"
    )


def _analysis_engine_with_intelligence(self: Any) -> None:
    title, body, status = _capture_html(self, _ORIGINAL_ANALYSIS_ENGINE)
    analysis_id, queue = _latest_analysis_queue(self, limit=100)
    panel = _analysis_intelligence_panel(analysis_id, queue)
    body = _insert_before(body, "<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Invisible Security Intelligence Core</h3>", panel)
    self.send_html(title, body, status)


def _bug_candidates_with_queue(self: Any) -> None:
    title, body, status = _capture_html(self, _ORIGINAL_BUG_CANDIDATES)
    params = self.query()
    target = str((params.get("target") or [""])[0]).strip()
    family = str((params.get("family") or [""])[0]).strip()
    analysis_id, queue = _latest_analysis_queue(self, target=target, limit=100)
    if family:
        queue = [
            item
            for item in queue
            if str(item.get("primary_family") or "") == family
            or any(
                isinstance(row, dict) and str(row.get("family") or "") == family
                for row in (item.get("families") or [])
            )
        ]
    panel = _investigation_queue_panel(analysis_id, queue)
    body = _insert_before(body, "<section class='filter-panel'>", panel)
    self.send_html(title, body, status)


# Patch only the two owning workspace pages.  NAV_SECTIONS, routes, aliases and all
# other dashboard behavior remain the established implementation's responsibility.
_base.DashboardHandler.analysis_engine = _analysis_engine_with_intelligence
_base.DashboardHandler.bug_candidates = _bug_candidates_with_queue
DashboardHandler = _base.DashboardHandler
