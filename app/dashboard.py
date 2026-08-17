from __future__ import annotations

"""Additive vulnerability-intelligence UI for the existing dashboard.

The primary dashboard information architecture remains owned by ``dashboard_core``.
This compatibility surface adds vulnerability intelligence and the cluster-to-case
investigation workflow inside the existing Analysis and Potential Findings pages.
"""

import json
import urllib.parse
from collections import defaultdict
from typing import Any, Callable, Mapping

import dashboard_core as _base
from correlation_engine import CORRELATION_ENGINE_VERSION, build_correlation_context, investigation_queue
from investigation_workflow import (
    INVESTIGATION_WORKFLOW_VERSION,
    cluster_workflow_snapshot,
    ensure_cluster_case,
    record_cluster_decision,
    refresh_case_workflow,
)
from meta_ranker import META_RANKER_VERSION


DASHBOARD_INTELLIGENCE_INTEGRATION_VERSION = "1.2.1"

# Preserve the complete established dashboard import contract, including private
# rendering helpers used by regression tests and local integrations.
for _name, _value in vars(_base).items():
    if _name not in {
        "__name__", "__loader__", "__package__", "__spec__", "__file__",
        "__cached__", "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_ANALYSIS_ENGINE = _base.DashboardHandler.analysis_engine
_ORIGINAL_BUG_CANDIDATES = _base.DashboardHandler.bug_candidates
_ORIGINAL_DO_POST = _base.DashboardHandler.do_POST


def _capture_html(self: Any, renderer: Callable[[Any], None]) -> tuple[str, str, int]:
    captured: dict[str, Any] = {}
    had_send = "send_html" in getattr(self, "__dict__", {})
    prior_send = getattr(self, "__dict__", {}).get("send_html")
    self.send_html = lambda title, body, status=200: captured.update(title=title, body=body, status=status)
    try:
        renderer(self)
    finally:
        if had_send:
            self.send_html = prior_send
        else:
            self.__dict__.pop("send_html", None)
    if not captured:
        raise RuntimeError("Dashboard renderer completed without producing HTML")
    return str(captured.get("title") or "Recon Monitor"), str(captured.get("body") or ""), int(captured.get("status") or 200)


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _latest_analysis_queue(self: Any, *, target: str = "", limit: int = 50) -> tuple[str, list[dict[str, Any]]]:
    db = self.db()
    try:
        latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
        analysis_id = str(latest["id"]) if latest else ""
        queue = investigation_queue(db, analysis_id, target=target or None, limit=limit) if analysis_id else []
        return analysis_id, queue
    finally:
        db.close()


def _insert_before(body: str, needle: str, fragment: str) -> str:
    index = body.find(needle)
    return body + fragment if index < 0 else body[:index] + fragment + body[index:]


def _family_summary(queue: list[dict[str, Any]], limit: int = 5) -> list[tuple[str, int, int]]:
    scores: dict[str, int] = defaultdict(int)
    counts: dict[str, int] = defaultdict(int)
    for item in queue:
        seen: set[str] = set()
        rankings = item.get("families") if isinstance(item.get("families"), list) else []
        for ranking in rankings:
            if not isinstance(ranking, Mapping):
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
    return [(family, scores[family], counts[family]) for family in ordered[:max(1, limit)]]


def _analysis_intelligence_panel(analysis_id: str, queue: list[dict[str, Any]]) -> str:
    if not analysis_id:
        return (
            "<section class='panel' id='vulnerability-intelligence'><div class='panel-head'><h3>Vulnerability Intelligence</h3>"
            + _base._pill("not run", "neutral")
            + "</div><div class='panel-body'>"
            + _base._empty("No vulnerability-intelligence context yet", "A completed analysis run is required before Meta Ranker and cross-surface correlation can be summarized.")
            + "</div></section>"
        )
    count = len(queue)
    avg_proximity = round(sum(_base.parse_int(x.get("bug_proximity_score"), 0, 0, 100) for x in queue) / count) if count else 0
    avg_evidence = round(sum(_base.parse_int(x.get("target_evidence_confidence"), 0, 0, 100) for x in queue) / count) if count else 0
    strong = sum(_base.parse_int(x.get("cluster_strength"), 0, 0, 100) >= 60 for x in queue)
    high = sum(str(x.get("hunt_priority") or "").upper() == "HIGH" for x in queue)
    rows = "".join(
        f"<tr><td>{_base._esc(family.replace('_',' '))}</td><td><strong>{score}</strong></td><td>{clusters}</td></tr>"
        for family, score, clusters in _family_summary(queue)
    )
    metrics = "<div class='metrics-grid'>" + "".join([
        _base._metric_card("Investigation clusters", count, "Cross-surface hypotheses deduplicated by cluster", "blue", "/potential-findings#investigation-queue"),
        _base._metric_card("Average bug proximity", f"{avg_proximity}%", "Meta Ranker proximity — not vulnerability confidence", "purple"),
        _base._metric_card("Average target evidence", f"{avg_evidence}%", "Uses target observations only", "success" if avg_evidence >= 60 else "amber"),
        _base._metric_card("Strong correlations", strong, "Clusters with cross-surface strength ≥60", "orange"),
        _base._metric_card("High hunt priority", high, "Prioritized for analyst attention, not confirmation", "danger" if high else "neutral"),
    ]) + "</div>"
    return (
        "<section class='panel' id='vulnerability-intelligence' style='margin-top:16px'>"
        "<div class='panel-head'><div><h3>Vulnerability Intelligence</h3>"
        f"<span class='muted small'>Meta Ranker {_base._esc(META_RANKER_VERSION)} · Correlation Engine {_base._esc(CORRELATION_ENGINE_VERSION)}</span></div>"
        + _base._pill("advisory context", "info")
        + "</div><div class='panel-body'>" + metrics
        + "<div class='callout' style='margin-top:14px'><strong>Evidence boundary preserved</strong><span>Bug proximity and cross-surface correlation rank where to investigate. They cannot satisfy admission, create an independent evidence root, raise target-evidence confidence, or confirm a vulnerability.</span></div>"
        + "<div class='table-wrap' style='margin-top:14px'><table><thead><tr><th>Leading family</th><th>Proximity</th><th>Clusters</th></tr></thead><tbody>"
        + (rows or "<tr><td colspan='3'>No ranked family context is available yet.</td></tr>")
        + "</tbody></table></div></div></section>"
    )


def _cluster_href(item: Mapping[str, Any]) -> str:
    params = {"cluster": str(item.get("cluster_id") or "")}
    if str(item.get("target") or "").strip():
        params["target"] = str(item.get("target"))
    if str(item.get("primary_family") or "").strip():
        params["family"] = str(item.get("primary_family"))
    return "/potential-findings?" + urllib.parse.urlencode(params) + "#investigation-cluster-detail"


def _queue_item_card(item: dict[str, Any]) -> str:
    queue_score = _base.parse_int(item.get("queue_score"), 0, 0, 100)
    proximity = _base.parse_int(item.get("bug_proximity_score"), 0, 0, 100)
    evidence = _base.parse_int(item.get("target_evidence_confidence"), 0, 0, 100)
    cluster = _base.parse_int(item.get("cluster_strength"), 0, 0, 100)
    priority = str(item.get("hunt_priority") or "NOISE").upper()
    endpoints = [str(v) for v in item.get("endpoints", []) if str(v).strip()]
    why = "".join(f"<li>{_base._esc(v)}</li>" for v in item.get("why", [])[:4]) or "<li>No additional ranking explanation recorded.</li>"
    families = " ".join(
        _base._pill(f"{str(row.get('family') or '').replace('_',' ')} {_base.parse_int(row.get('score'),0,0,100)}")
        for row in item.get("families", [])[:3] if isinstance(row, Mapping)
    )
    context: list[str] = []
    if item.get("object_tokens"):
        context.append("objects: " + ", ".join(str(v) for v in item.get("object_tokens", [])[:6]))
    if item.get("auth_boundaries"):
        context.append("auth: " + ", ".join(str(v) for v in item.get("auth_boundaries", [])[:4]))
    return (
        f"<article class='candidate-card investigation-queue-card' data-cluster-id='{_base._esc(item.get('cluster_id') or '')}'>"
        f"<div class='candidate-accent tone-{_base._tone(priority)}'></div><div class='candidate-main'>"
        f"<div class='candidate-heading'><div><div class='candidate-kicker'>{_base._pill(priority)}{_base._pill('not confirmed','neutral')}<span>{_base._esc(item.get('target') or '')}</span></div>"
        f"<h3>{_base._esc(item.get('primary_bug') or item.get('primary_family') or 'Investigation cluster')}</h3>"
        f"<div class='muted small'>{''.join(f'<code>{_base._esc(v)}</code> ' for v in endpoints[:4])}</div></div>"
        f"<div class='investigation-score'><span>Queue</span><strong>{queue_score}</strong></div></div>"
        f"<div class='score-triad'><div><span>Bug proximity</span><strong class='tone-purple'>{proximity}</strong></div><div><span>Target evidence</span><strong class='tone-info'>{evidence}</strong></div><div><span>Cluster strength</span><strong class='tone-orange'>{cluster}</strong></div><div><span>Surfaces</span><strong class='tone-success'>{len(endpoints)}</strong></div></div>"
        f"<div class='candidate-reasoning'><div><strong>Top families</strong><p>{families or 'No ranked alternatives recorded.'}</p></div><div><strong>Why it deserves review</strong><ul>{why}</ul></div><div><strong>Correlation context</strong><p>{_base._esc(' · '.join(context) or 'Cross-surface context is limited for this cluster.')}</p></div></div>"
        "<div class='next-step'><span>Interpretation</span><p>This cluster is an investigation priority only. Review the underlying Potential Findings and target evidence before any vulnerability claim.</p></div>"
        f"</div><a class='candidate-open' href='{_base._esc(_cluster_href(item))}'>Open cluster →</a></article>"
    )


def _investigation_queue_panel(analysis_id: str, queue: list[dict[str, Any]]) -> str:
    high = sum(str(x.get("hunt_priority") or "").upper() == "HIGH" for x in queue)
    strong = sum(_base.parse_int(x.get("cluster_strength"), 0, 0, 100) >= 60 for x in queue)
    content = "".join(_queue_item_card(item) for item in queue[:8]) or _base._empty(
        "No investigation clusters match this view",
        "Potential Findings remain available below. A cluster appears here only when a persisted Meta Ranker result can be correlated across the selected analysis context.",
    )
    return (
        "<section class='panel' id='investigation-queue' style='margin-top:16px'><div class='panel-head'><div><h3>Investigation Queue</h3><span class='muted small'>Cluster-deduplicated priorities inside Potential Findings · not a confirmation queue</span></div>"
        + _base._pill("investigation only", "info")
        + "</div><div class='panel-body'><div class='attention-grid'>"
        f"<div class='attention-card'><span>Clusters</span><strong>{len(queue)}</strong><small>deduplicated work items</small></div>"
        f"<div class='attention-card'><span>High priority</span><strong>{high}</strong><small>hunt priority HIGH</small></div>"
        f"<div class='attention-card'><span>Strong correlation</span><strong>{strong}</strong><small>cluster strength ≥60</small></div>"
        f"<div class='attention-card'><span>Analysis</span><strong>{_base._esc(analysis_id[:8] if analysis_id else '—')}</strong><small>latest completed analysis</small></div>"
        "</div><div class='callout' style='margin-top:14px'><strong>What this queue changes</strong><span>Related hypotheses are collapsed into analyst-sized clusters and ranked by proximity, target evidence, cluster strength and hunt priority. The complete Potential Findings inventory remains below and unchanged.</span></div>"
        f"<div class='stack' style='margin-top:16px'>{content}</div></div></section>"
    )


def _cluster_detail_context(db: Any, analysis_id: str, item: Mapping[str, Any]) -> dict[str, Any]:
    hyp_ids = [str(v) for v in item.get("hypothesis_ids", []) if str(v).strip()]
    hypotheses: list[dict[str, Any]] = []
    if hyp_ids:
        placeholders = ",".join("?" for _ in hyp_ids)
        hypotheses = [dict(row) for row in db.all(
            "SELECT hypothesis_id,target,asset,endpoint,source_ref,alert_id,bug_family,bug_variant,state,summary,supporting_evidence_json,contradicting_evidence_json,missing_evidence_json,decisive_signals_json,admission_json,promoted_candidate_id,last_seen_at "
            f"FROM analysis_hypotheses WHERE analysis_id=? AND hypothesis_id IN ({placeholders}) ORDER BY state='promoted' DESC,last_seen_at DESC",
            (analysis_id, *hyp_ids),
        )]
    endpoints = [str(v) for v in item.get("endpoints", []) if str(v).strip()]
    candidates: list[dict[str, Any]] = []
    if endpoints:
        placeholders = ",".join("?" for _ in endpoints)
        candidates = [dict(row) for row in db.all(
            "SELECT candidate_id,bug_family,bug_variant,candidate_state,analyst_decision,priority_score,likelihood_score,evidence_strength,impact_potential,investigation_value,endpoint,summary,safe_next_action,updated_at FROM bug_candidates "
            f"WHERE analysis_id=? AND target=? AND endpoint IN ({placeholders}) ORDER BY investigation_value DESC,priority_score DESC",
            (analysis_id, str(item.get("target") or ""), *endpoints),
        )]
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    missing: list[str] = []
    decisive: list[str] = []
    primary_meta: dict[str, Any] = {}
    correlation: dict[str, Any] = {}
    for row in hypotheses:
        support.extend(value for value in _loads(row.get("supporting_evidence_json"), []) if isinstance(value, dict))
        contradict.extend(value for value in _loads(row.get("contradicting_evidence_json"), []) if isinstance(value, dict))
        missing.extend(str(value) for value in _loads(row.get("missing_evidence_json"), []) if str(value).strip())
        decisive.extend(str(value) for value in _loads(row.get("decisive_signals_json"), []) if str(value).strip())
        admission = _loads(row.get("admission_json"), {})
        stored = admission.get("correlation_context") if isinstance(admission, dict) else None
        if isinstance(stored, dict) and str(stored.get("cluster_id") or "") == str(item.get("cluster_id") or ""):
            correlation = stored
        knowledge = admission.get("knowledge_context") if isinstance(admission, dict) else None
        meta = knowledge.get("meta_ranker") if isinstance(knowledge, dict) else None
        primary = meta.get("primary") if isinstance(meta, dict) else None
        if isinstance(primary, dict):
            if _base.parse_int(primary.get("bug_proximity_score"), 0, 0, 100) >= _base.parse_int(primary_meta.get("bug_proximity_score"), 0, 0, 100):
                primary_meta = dict(primary)
            missing.extend(str(value) for value in primary.get("evidence_gaps", []) if str(value).strip())
    if not correlation and hypotheses:
        seed = hypotheses[0]
        correlation = build_correlation_context(
            db,
            analysis_id=analysis_id,
            target=str(seed.get("target") or item.get("target") or ""),
            endpoint=str(seed.get("endpoint") or ""),
            alert_id=seed.get("alert_id"),
            source_ref=str(seed.get("source_ref") or ""),
        )
    workflow: dict[str, Any] = {"status": "unavailable"}
    if hasattr(db, "one"):
        workflow = cluster_workflow_snapshot(db, analysis_id=analysis_id, item=item)
    return {
        "item": dict(item), "hypotheses": hypotheses, "candidates": candidates,
        "support": _dedupe_dicts(support), "contradict": _dedupe_dicts(contradict),
        "missing": list(dict.fromkeys(missing)), "decisive": list(dict.fromkeys(decisive)),
        "primary_meta": primary_meta, "correlation": correlation, "workflow": workflow,
    }


def _evidence_rows(items: list[dict[str, Any]], kind: str) -> str:
    return "".join(
        "<tr>"
        f"<td>{_base._pill(kind, 'success' if kind == 'support' else 'danger')}</td>"
        f"<td><code>{_base._esc(item.get('type') or 'signal')}</code></td>"
        f"<td>{_base._esc(item.get('source_group') or item.get('source') or 'unknown')}</td>"
        f"<td>{_base._esc(item.get('text') or item.get('detail') or item.get('value') or 'Stored evidence item')}</td>"
        f"<td>{_base._esc('' if item.get('weight') in (None,'') else item.get('weight'))}</td></tr>"
        for item in items[:20]
    )


def _workflow_panel(analysis_id: str, item: Mapping[str, Any], workflow: Mapping[str, Any]) -> str:
    return_href = _cluster_href(item)
    status = str(workflow.get("status") or "not_started")
    if status == "unavailable":
        return ""
    if status != "started":
        return (
            "<section class='panel' id='investigation-workflow' style='margin-top:18px'>"
            "<div class='panel-head'><div><h4>Investigation Workflow</h4>"
            f"<span class='muted small'>Case bridge {INVESTIGATION_WORKFLOW_VERSION}</span></div>"
            + _base._pill("not started", "neutral")
            + "</div><div class='panel-body'>"
            "<div class='callout'><strong>Turn this dossier into analyst work</strong><span>Start Investigation links this cluster to the existing Security Case, Evidence Gap, Case Autopilot and Safe Validation engines. It does not confirm the vulnerability and does not run validation.</span></div>"
            "<form method='post' action='/investigation/start' style='margin-top:14px'>"
            f"<input type='hidden' name='analysis_id' value='{_base._esc(analysis_id)}'>"
            f"<input type='hidden' name='cluster_id' value='{_base._esc(item.get('cluster_id') or '')}'>"
            f"<input type='hidden' name='target' value='{_base._esc(item.get('target') or '')}'>"
            f"<input type='hidden' name='return' value='{_base._esc(return_href)}'>"
            "<button type='submit'>Start Investigation</button></form>"
            "<p class='muted small' style='margin-top:10px'>A proximity-only cluster with no promoted primary-family Potential Finding cannot be marked Confirmed.</p>"
            "</div></section>"
        )

    case = workflow.get("case") if isinstance(workflow.get("case"), Mapping) else {}
    gap = workflow.get("evidence") if isinstance(workflow.get("evidence"), Mapping) else {}
    autopilot = workflow.get("autopilot") if isinstance(workflow.get("autopilot"), Mapping) else {}
    validation = workflow.get("validation") if isinstance(workflow.get("validation"), Mapping) else {}
    case_id = str(workflow.get("case_id") or case.get("case_id") or "")
    coverage = _base.parse_int(gap.get("coverage"), 0, 0, 100)
    missing_count = _base.parse_int(gap.get("missing_count"), 0, 0, 999)
    autopilot_score = _base.parse_int(autopilot.get("autopilot_score"), 0, 0, 100)
    level = str(validation.get("recommended_level") or "offline")
    executable = bool(validation.get("executable_in_this_release"))
    primary_candidate_count = _base.parse_int(workflow.get("primary_candidate_count"), 0, 0, 999)

    requirement_rows = "".join(
        f"<tr><td>{_base._esc(row.get('label') or row.get('key') or '')}</td><td>{_base._pill(row.get('status') or 'missing','success' if row.get('status') == 'present' else 'amber')}</td><td>{_base._esc(row.get('why') or '')}</td></tr>"
        for row in gap.get("requirements", []) if isinstance(row, Mapping)
    ) or "<tr><td colspan='3' class='muted'>No evidence requirements are available.</td></tr>"
    tasks = [row for row in autopilot.get("tasks", []) if isinstance(row, Mapping)]
    task_rows = "".join(
        f"<li><strong>#{_base._esc(row.get('rank') or '')}</strong> {_base._esc(row.get('title') or '')}</li>"
        for row in tasks[:8]
    ) or "<li>No additional evidence task is currently required; review the dossier and record a decision.</li>"
    reasons = "".join(f"<li>{_base._esc(value)}</li>" for value in validation.get("reasons", [])[:6]) or "<li>No additional validation eligibility reason recorded.</li>"

    validation_action = (
        "<form method='post' action='/validation/plan'>"
        f"<input type='hidden' name='case_id' value='{_base._esc(case_id)}'>"
        f"<input type='hidden' name='level' value='{_base._esc(level)}'>"
        f"<input type='hidden' name='return' value='{_base._esc(return_href)}'>"
        f"<button type='submit'>Create {_base._esc(level.replace('_',' '))} Validation Plan</button></form>"
        if executable
        else "<p class='muted small'>This family remains controlled/manual-only in this release. No automatic live validation action is exposed here.</p>"
    )
    confirmed_option = "<option value='confirmed_by_analyst'>Confirmed by analyst</option>" if primary_candidate_count else ""

    return (
        "<section class='panel' id='investigation-workflow' style='margin-top:18px'>"
        "<div class='panel-head'><div><h4>Investigation Workflow</h4>"
        f"<span class='muted small'>Case <code>{_base._esc(case_id)}</code> · workflow {INVESTIGATION_WORKFLOW_VERSION}</span></div>"
        + _base._pill(case.get("state") or "reviewing")
        + "</div><div class='panel-body'>"
        "<div class='attention-grid'>"
        f"<div class='attention-card'><span>Evidence readiness</span><strong>{coverage}%</strong><small>case evidence requirements present</small></div>"
        f"<div class='attention-card'><span>Missing evidence</span><strong>{missing_count}</strong><small>requirements still open</small></div>"
        f"<div class='attention-card'><span>Autopilot readiness</span><strong>{autopilot_score}%</strong><small>workflow readiness, not vulnerability confidence</small></div>"
        f"<div class='attention-card'><span>Validation</span><strong>{_base._esc(level.replace('_',' '))}</strong><small>{'plan may be created; execution stays gated' if executable else 'manual or controlled only'}</small></div>"
        "</div>"
        "<div class='grid two' style='margin-top:16px'>"
        f"<section><h4>Next Best Actions</h4><ol>{task_rows}</ol>"
        "<form method='post' action='/investigation/refresh' style='margin-top:12px'>"
        f"<input type='hidden' name='case_id' value='{_base._esc(case_id)}'><input type='hidden' name='return' value='{_base._esc(return_href)}'>"
        "<button type='submit' class='secondary'>Refresh Evidence Plan</button></form></section>"
        f"<section><h4>Safe Validation Eligibility</h4><p>{_base._pill(level)}</p><ul>{reasons}</ul>{validation_action}</section>"
        "</div>"
        "<section style='margin-top:18px'><h4>Evidence Readiness</h4><div class='table-wrap'><table><thead><tr><th>Requirement</th><th>Status</th><th>Why it matters</th></tr></thead><tbody>"
        + requirement_rows + "</tbody></table></div></section>"
        "<section style='margin-top:18px'><h4>Analyst Decision</h4>"
        "<div class='callout'><strong>Feedback loop</strong><span>Decisions are applied only to promoted Potential Findings in the cluster's primary family. Those reviewed outcomes feed the historical prior on subsequent Meta Ranker runs; hidden proximity-only hypotheses are never promoted by this action.</span></div>"
        "<form method='post' action='/investigation/decision' class='filters' style='margin-top:12px'>"
        f"<input type='hidden' name='case_id' value='{_base._esc(case_id)}'><input type='hidden' name='return' value='{_base._esc(return_href)}'>"
        "<label>Decision<select name='decision'><option value='needs_more_evidence'>Needs more evidence</option>"
        + confirmed_option
        + "<option value='rejected'>Rejected</option><option value='duplicate'>Duplicate</option></select></label>"
        "<label>Analyst note<input name='note' maxlength='1000' placeholder='Reason, observed boundary, or evidence still needed'></label>"
        "<button type='submit'>Record Decision</button></form>"
        + ("<p class='muted small'>Confirmed is unavailable because this cluster has no promoted Potential Finding for the primary family.</p>" if not primary_candidate_count else "")
        + f"<p style='margin-top:12px'><a class='button secondary' href='/case?id={urllib.parse.quote(case_id)}'>Open full Security Case →</a></p>"
        "</section></div></section>"
    )


def _investigation_cluster_detail_panel(analysis_id: str, detail: Mapping[str, Any]) -> str:
    item = detail.get("item") if isinstance(detail.get("item"), Mapping) else {}
    target = str(item.get("target") or "")
    family = str(item.get("primary_family") or "")
    priority = str(item.get("hunt_priority") or "NOISE").upper()
    hypotheses = [row for row in detail.get("hypotheses", []) if isinstance(row, Mapping)]
    candidates = [row for row in detail.get("candidates", []) if isinstance(row, Mapping)]
    correlation = detail.get("correlation") if isinstance(detail.get("correlation"), Mapping) else {}
    primary = detail.get("primary_meta") if isinstance(detail.get("primary_meta"), Mapping) else {}
    workflow = detail.get("workflow") if isinstance(detail.get("workflow"), Mapping) else {"status": "not_started"}

    cand_rows = "".join(
        f"<tr><td><code>{_base._esc(str(row.get('candidate_id') or '')[:12])}</code></td><td>{_base._esc(str(row.get('bug_family') or '').replace('_',' '))}</td><td><code>{_base._esc(row.get('endpoint') or '')}</code></td><td>{_base._pill(str(row.get('candidate_state') or 'unknown'))}</td><td>{_base._pill(str(row.get('analyst_decision') or 'unreviewed'))}</td><td>{_base.parse_int(row.get('investigation_value'),0,0,100)}</td><td>{_base._esc(row.get('summary') or '')}</td></tr>"
        for row in candidates[:20]
    ) or "<tr><td colspan='7' class='muted'>No promoted Potential Finding currently belongs to these correlated surfaces.</td></tr>"
    hyp_rows = "".join(
        f"<tr><td><code>{_base._esc(str(row.get('hypothesis_id') or '')[:12])}</code></td><td>{_base._esc(str(row.get('bug_family') or '').replace('_',' '))}</td><td><code>{_base._esc(row.get('endpoint') or '')}</code></td><td>{_base._pill(str(row.get('state') or 'unknown'))}</td><td>{_base._esc(row.get('summary') or '')}</td></tr>"
        for row in hypotheses[:30]
    ) or "<tr><td colspan='5' class='muted'>No member hypotheses are available.</td></tr>"
    evidence_rows = _evidence_rows([row for row in detail.get("support", []) if isinstance(row, dict)], "support") + _evidence_rows([row for row in detail.get("contradict", []) if isinstance(row, dict)], "contradict")
    evidence_rows = evidence_rows or "<tr><td colspan='5' class='muted'>No stored evidence items are available for this cluster.</td></tr>"
    missing = "".join(f"<li>{_base._esc(value)}</li>" for value in detail.get("missing", [])[:20]) or "<li>No explicit evidence gap is currently recorded.</li>"
    decisive = " ".join(_base._pill(str(value), "info") for value in detail.get("decisive", [])[:12]) or "<span class='muted'>No decisive signals recorded.</span>"
    why = "".join(f"<li>{_base._esc(value)}</li>" for value in primary.get("why", [])[:12]) or "".join(f"<li>{_base._esc(value)}</li>" for value in item.get("why", [])[:12]) or "<li>No ranking rationale is stored.</li>"
    family_tags = " ".join(
        _base._pill(f"{str(row.get('family') or '').replace('_',' ')} {_base.parse_int(row.get('score'),0,0,100)}")
        for row in item.get("families", [])[:3] if isinstance(row, Mapping)
    ) or "<span class='muted'>No alternative family ranking recorded.</span>"

    differential_values: list[str] = []
    for edge in correlation.get("edges", []) if isinstance(correlation.get("edges"), list) else []:
        if not isinstance(edge, Mapping):
            continue
        for reason in edge.get("reasons", []) if isinstance(edge.get("reasons"), list) else []:
            text = str(reason)
            if text.startswith("auth-boundary differential:"):
                differential_values.append(f"{edge.get('from')} → {edge.get('to')}: {text.split(':',1)[1].strip()}")
    differentials = "".join(f"<li>{_base._esc(value)}</li>" for value in dict.fromkeys(differential_values)) or "<li>No auth-boundary differential is recorded inside this cluster.</li>"
    surface_rows = "".join(
        f"<tr><td><code>{_base._esc(row.get('endpoint') or '')}</code></td><td>{_base._esc(row.get('method') or '')}</td><td>{_base._esc(row.get('auth_boundary') or 'unknown')}</td><td>{_base.parse_int(row.get('correlation_score'),0,0,100)}</td><td>{_base._esc('; '.join(str(value) for value in row.get('correlation_reasons', [])[:4]))}</td></tr>"
        for row in correlation.get("related_surfaces", [])[:20] if isinstance(row, Mapping)
    ) or "<tr><td colspan='5' class='muted'>No correlated surface detail is available.</td></tr>"
    components = primary.get("components") if isinstance(primary.get("components"), Mapping) else {}
    labels = {
        "target_evidence": "Target evidence", "profile_compatibility": "Profile compatibility",
        "writeup_similarity": "Writeup similarity", "historical_feedback": "Historical feedback",
        "correlation": "Cross-surface correlation", "llm_advisory": "LLM advisory",
    }
    component_rows = "".join(
        f"<tr><td>{_base._esc(labels[key])}</td><td><strong>{_base.parse_int(components[key],0,0,100)}</strong></td><td>{_base._pill('target evidence' if key == 'target_evidence' else 'non-evidentiary','success' if key == 'target_evidence' else 'neutral')}</td></tr>"
        for key in labels if components.get(key) is not None
    ) or "<tr><td colspan='3' class='muted'>No Meta Ranker component breakdown is stored.</td></tr>"

    return (
        "<section class='panel' id='investigation-cluster-detail' style='margin-top:16px'><div class='panel-head'><div>"
        f"<div class='muted small'><a href='{_base._esc(_base._query_link('/potential-findings', target=target, family=family))}'>← Investigation Queue</a> · cluster <code>{_base._esc(item.get('cluster_id') or '')}</code></div>"
        f"<h3>{_base._esc(item.get('primary_bug') or family or 'Investigation cluster')}</h3><span class='muted small'>{_base._esc(target)} · {_base._esc(family.replace('_',' '))}</span></div>"
        + _base._pill(priority) + _base._pill("not confirmed", "neutral")
        + "</div><div class='panel-body'>"
        f"<div class='score-triad'><div><span>Queue score</span><strong>{_base.parse_int(item.get('queue_score'),0,0,100)}</strong></div><div><span>Bug proximity</span><strong class='tone-purple'>{_base.parse_int(item.get('bug_proximity_score'),0,0,100)}</strong></div><div><span>Target evidence</span><strong class='tone-info'>{_base.parse_int(item.get('target_evidence_confidence'),0,0,100)}</strong></div><div><span>Cluster strength</span><strong class='tone-orange'>{_base.parse_int(item.get('cluster_strength'),0,0,100)}</strong></div></div>"
        "<div class='callout' style='margin-top:14px'><strong>Investigation dossier — not a vulnerability verdict</strong><span>This view collects stored evidence, correlated surfaces and ranking context in one place. Only target observations can support admission or analyst confirmation; knowledge, history, correlation and LLM advice remain advisory.</span></div>"
        + _workflow_panel(analysis_id, item, workflow)
        + f"<div class='grid two' style='margin-top:16px'><section><h4>Closest bug families</h4><p>{family_tags}</p><h4>Why the ranker cares</h4><ul>{why}</ul></section><section><h4>Missing evidence</h4><ul>{missing}</ul><h4>Decisive target signals</h4><p>{decisive}</p></section></div>"
        + "<section style='margin-top:18px'><h4>Related Potential Findings</h4><div class='table-wrap'><table><thead><tr><th>ID</th><th>Family</th><th>Endpoint</th><th>State</th><th>Analyst</th><th>Investigation</th><th>Summary</th></tr></thead><tbody>" + cand_rows + "</tbody></table></div></section>"
        + "<section style='margin-top:18px'><h4>Member hypotheses</h4><div class='table-wrap'><table><thead><tr><th>ID</th><th>Family</th><th>Endpoint</th><th>State</th><th>Summary</th></tr></thead><tbody>" + hyp_rows + "</tbody></table></div></section>"
        + "<section style='margin-top:18px'><h4>Evidence dossier</h4><div class='table-wrap'><table><thead><tr><th>Role</th><th>Type</th><th>Source</th><th>Observation</th><th>Weight</th></tr></thead><tbody>" + evidence_rows + "</tbody></table></div></section>"
        + f"<div class='grid two' style='margin-top:18px'><section><h4>Auth-boundary differentials</h4><ul>{differentials}</ul></section><section><h4>Meta Ranker components</h4><div class='table-wrap'><table><thead><tr><th>Component</th><th>Score</th><th>Role</th></tr></thead><tbody>{component_rows}</tbody></table></div></section></div>"
        + "<section style='margin-top:18px'><h4>Correlated surfaces</h4><div class='table-wrap'><table><thead><tr><th>Endpoint</th><th>Method</th><th>Auth boundary</th><th>Correlation</th><th>Reason</th></tr></thead><tbody>" + surface_rows + "</tbody></table></div></section>"
        + "</div></section>"
    )


def _analysis_engine_with_intelligence(self: Any) -> None:
    # The Analysis workspace must remain an instant summary surface. Deep
    # investigation correlation belongs to Potential Findings and is loaded only
    # when the operator explicitly opens that workspace. This prevents a large
    # completed/stopped run from blocking /analysis page delivery.
    title, body, status = _capture_html(self, _ORIGINAL_ANALYSIS_ENGINE)
    deferred = (
        "<section class='panel' id='vulnerability-intelligence' style='margin-top:16px'>"
        "<div class='panel-head'><div><h3>Vulnerability Intelligence</h3>"
        f"<span class='muted small'>Integration {_base._esc(DASHBOARD_INTELLIGENCE_INTEGRATION_VERSION)} · on-demand deep correlation</span></div>"
        + _base._pill("on demand", "info")
        + "</div><div class='panel-body'>"
        "<div class='callout'><strong>Fast Analysis summary</strong>"
        "<span>Deep Meta Ranker and cross-surface Investigation Queue correlation is intentionally not computed while opening this page. "
        "Open Potential Findings when you want the full investigation context.</span></div>"
        "<p style='margin-top:12px'><a class='button secondary' href='/potential-findings#investigation-queue'>Open Investigation Queue →</a></p>"
        "</div></section>"
    )
    body = _insert_before(
        body,
        "<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Invisible Security Intelligence Core</h3>",
        deferred,
    )
    self.send_html(title, body, status)


def _bug_candidates_with_queue(self: Any) -> None:
    title, body, status = _capture_html(self, _ORIGINAL_BUG_CANDIDATES)
    params = self.query()
    target = str((params.get("target") or [""])[0]).strip()
    family = str((params.get("family") or [""])[0]).strip()
    selected_cluster = str((params.get("cluster") or [""])[0]).strip()
    analysis_id, queue = _latest_analysis_queue(self, target=target, limit=100)
    if family:
        queue = [
            item for item in queue
            if str(item.get("primary_family") or "") == family
            or any(isinstance(row, Mapping) and str(row.get("family") or "") == family for row in item.get("families", []))
        ]
    fragments: list[str] = []
    if selected_cluster:
        selected = next((item for item in queue if str(item.get("cluster_id") or "") == selected_cluster), None)
        if selected:
            db = self.db()
            try:
                detail = _cluster_detail_context(db, analysis_id, selected)
            finally:
                db.close()
            fragments.append(_investigation_cluster_detail_panel(analysis_id, detail))
        else:
            fragments.append(
                "<section class='panel' id='investigation-cluster-detail'><div class='panel-head'><h3>Investigation cluster</h3>"
                + _base._pill("not found", "neutral")
                + "</div><div class='panel-body'>"
                + _base._empty("Cluster not available in this view", "The selected cluster may belong to a different target/family filter or a different completed analysis.")
                + "</div></section>"
            )
    fragments.append(_investigation_queue_panel(analysis_id, queue))
    body = _insert_before(body, "<section class='filter-panel'>", "".join(fragments))
    self.send_html(title, body, status)


def _safe_return(value: str, fallback: str = "/potential-findings") -> str:
    text = str(value or "").strip()
    return text if text.startswith("/") and not text.startswith("//") else fallback


def _do_post_with_investigation(self: Any) -> None:
    path = urllib.parse.urlsplit(self.path).path
    if path not in {"/investigation/start", "/investigation/refresh", "/investigation/decision"}:
        _ORIGINAL_DO_POST(self)
        return

    data = self.form_data()
    if not self._require_auth("analyst"):
        return
    if not self._same_origin_post() or not self._require_csrf(data):
        self.send_html(
            "Forbidden",
            "<h1>Investigation action rejected</h1><p>The request failed the dashboard same-origin or CSRF check. Reload the page before retrying.</p>",
            403,
        )
        return

    actor = getattr(self.session, "username", "dashboard") if self.session else "dashboard"
    return_href = _safe_return(str((data.get("return") or ["/potential-findings"])[0]))
    db = self.db()
    try:
        if path == "/investigation/start":
            analysis_id = str((data.get("analysis_id") or [""])[0]).strip()
            if not analysis_id:
                latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
                analysis_id = str(latest["id"]) if latest else ""
            ensure_cluster_case(
                db,
                analysis_id=analysis_id,
                cluster_id=str((data.get("cluster_id") or [""])[0]),
                target=str((data.get("target") or [""])[0]),
                actor=actor,
            )
        elif path == "/investigation/refresh":
            refresh_case_workflow(db, str((data.get("case_id") or [""])[0]), actor=actor)
        else:
            record_cluster_decision(
                db,
                str((data.get("case_id") or [""])[0]),
                str((data.get("decision") or ["needs_more_evidence"])[0]),
                note=str((data.get("note") or [""])[0])[:1000],
                actor=actor,
            )
    except _base.ReconError as exc:
        self.send_html(
            "Investigation action rejected",
            f"<h1>Investigation action rejected</h1><p>{_base._esc(exc)}</p><p><a class='button' href='{_base._esc(return_href)}'>Return to cluster</a></p>",
            400,
        )
        return
    finally:
        db.close()
    self.redirect(return_href)


# Patch only the owning existing surfaces. NAV_SECTIONS and all top-level workspace
# segmentation remain entirely owned by dashboard_core and therefore unchanged.
_base.DashboardHandler.analysis_engine = _analysis_engine_with_intelligence
_base.DashboardHandler.bug_candidates = _bug_candidates_with_queue
_base.DashboardHandler.do_POST = _do_post_with_investigation
DashboardHandler = _base.DashboardHandler
