from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import re
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Mapping

from analysis import compare_runs
from analysis_engine import PLAYBOOKS, calibration_report, analysis_quality
from bug_candidates import ANALYST_DECISIONS, FEEDBACK_REASON_CODES, BUG_FAMILIES, set_bug_candidate_decision
from candidate_intelligence import candidate_calibration, candidate_evaluation
from behavioral_intelligence import behavioral_summary
from security_reasoning import evidence_trace, family_calibration_report, reasoning_summary
from analysis_audit import build_evidence_dossier
from safe_validation import (
    FEEDBACK_DECISIONS as VALIDATION_FEEDBACK_DECISIONS, FEEDBACK_REASONS as VALIDATION_FEEDBACK_REASONS,
    VALIDATION_LEVELS, approve_validation_plan, create_validation_plan, execute_validation_plan,
    record_validation_feedback, validation_detail, validation_eligibility,
)
from product_platform import (
    CASE_STATES, RULE_STATES, NOTIFICATION_MODES, build_report_draft, build_validation_package,
    case_detail, engine_quality, engine_quality_snapshot, list_cases, list_stories, operations_center, platform_sync, rule_governance,
    run_completeness, run_completeness_snapshot, scope_center, set_case_state, set_notification_policy, set_rule_state, set_schedule_policy,
    storage_health, storage_health_snapshot, sync_security_cases, sync_security_stories,
)
from platform_v6 import (
    apply_retention, apply_target_template, build_burp_roundtrip_package, correlate_security_stories,
    data_quality_snapshot, deliver_notifications, due_revalidations, generate_schedule_job, list_target_templates,
    performance_diagnostics, platform_v6_sync, process_due_revalidations, queue_notification, rank_review_queue, report_quality,
    retention_preview, run_scheduled_workflow, security_posture, set_revalidation_policy, validation_intelligence, verify_audit_chain,
)
from workspace_v7 import (
    attack_surface_graph, authentication_contexts, browser_compatibility, build_evidence_linked_report, case_autopilot,
    case_autopilot_queue, change_intelligence, cockpit, differential_intelligence, evidence_gap_for_case, false_positive_learning,
    operator_diagnostics, recent_error_events, recon_coverage, safe_repair, safety_center, smart_recon_plan, stage_value_analysis,
    target_memory, universal_search, workspace_v7_sync, record_error_event, import_browser_capture,
)
from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, Logger, ReconError, json_dumps, parse_int
from dashboard_auth import verify_basic_header
from session_auth import parse_session, create_session, destroy_session, verify_user, session_cookie, expired_cookie, ROLE_LEVEL
from evidence import build_evidence_export
from plugins import PluginManager

ALERT_STATUSES = [
    "new", "triaged", "acknowledged", "investigating", "interesting",
    "reported", "resolved", "ignored", "false_positive", "out_of_scope",
]
PRIORITIES = ["low", "normal", "high", "urgent"]


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _query_link(path: str, **params: Any) -> str:
    clean = {key: value for key, value in params.items() if value not in {None, ""}}
    return path + ("?" + urllib.parse.urlencode(clean) if clean else "")


def _select(name: str, values: Iterable[str], current: str, all_label: str = "All") -> str:
    options = [f"<option value=''>{_esc(all_label)}</option>"]
    for value in values:
        selected = " selected" if value == current else ""
        options.append(f"<option value='{_esc(value)}'{selected}>{_esc(value)}</option>")
    return f"<select name='{_esc(name)}'>{''.join(options)}</select>"


def _select_pairs(name: str, values: Iterable[tuple[str, str]], current: str, all_label: str = "All") -> str:
    options = [f"<option value=''>{_esc(all_label)}</option>"]
    for value, label in values:
        selected = " selected" if str(value) == str(current) else ""
        options.append(f"<option value='{_esc(value)}'{selected}>{_esc(label)}</option>")
    return f"<select name='{_esc(name)}'>{''.join(options)}</select>"


def _filter_panel(fields: str, active: Mapping[str, Any], reset_href: str, *, title: str = "Filter data", submit_label: str = "Apply filters", result_count: int | None = None) -> str:
    chips = []
    for label, value in active.items():
        if value in {None, "", 0, "0", False}:
            continue
        chips.append(f"<span class='filter-chip'><small>{_esc(label)}</small><strong>{_esc(value)}</strong></span>")
    count = len(chips)
    result = f"<span class='filter-result'>{_esc(result_count)} results</span>" if result_count is not None else ""
    chip_html = f"<div class='filter-chips'>{''.join(chips)}</div>" if chips else "<span class='filter-empty'>Showing the default view</span>"
    return f"<section class='filter-panel'><div class='filter-head'><div><span class='filter-icon'>⌁</span><div><strong>{_esc(title)}</strong><small>{count} active filter{'s' if count != 1 else ''}</small></div></div>{result}</div><form class='filters filter-grid' method='get'>{fields}<div class='filter-actions'><button>{_esc(submit_label)}</button><a class='button ghost' href='{_esc(reset_href)}'>Reset</a></div></form><div class='filter-summary'>{chip_html}</div></section>"


def _quick_views(items: Iterable[tuple[str, str, bool]]) -> str:
    """Small, consistent preset links for high-volume research datasets."""
    return "<nav class='quick-views' aria-label='Quick views'>" + "".join(
        f"<a class='quick-view{' active' if active else ''}' href='{_esc(href)}'>{_esc(label)}</a>"
        for label, href, active in items
    ) + "</nav>"


def _inject_csrf_inputs(body: str, csrf: str) -> str:
    """Embed CSRF fields server-side; JavaScript remains a fallback for dynamic forms."""
    if not csrf or "<form" not in body.lower():
        return body
    hidden = f"<input type='hidden' name='csrf' value='{_esc(csrf)}'>"
    pattern = re.compile(
        r"(<form\b(?=[^>]*\bmethod\s*=\s*(['\"])post\2)[^>]*>)(.*?)(</form>)",
        re.IGNORECASE | re.DOTALL,
    )

    def add_token(match: re.Match[str]) -> str:
        opening, _, content, closing = match.groups()
        if re.search(r"\bname\s*=\s*(['\"])csrf\1", content, re.IGNORECASE):
            return match.group(0)
        return opening + hidden + content + closing

    return pattern.sub(add_token, body)


def _default_origin_port(scheme: str) -> int | None:
    return 443 if scheme == "https" else 80 if scheme == "http" else None


def _canonical_host_port(authority: str, scheme: str) -> tuple[str, int] | None:
    if not authority or any(ch in authority for ch in "\r\n/\\"):
        return None
    try:
        parsed = urllib.parse.urlsplit(f"//{authority}")
        if parsed.username is not None or parsed.password is not None or not parsed.hostname:
            return None
        host = parsed.hostname.rstrip(".").lower()
        port = parsed.port or _default_origin_port(scheme)
    except (TypeError, ValueError):
        return None
    if port is None:
        return None
    return host, int(port)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_origin(origin: str) -> tuple[str, str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(origin)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
        return None
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        return None
    try:
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port or _default_origin_port(scheme)
    except ValueError:
        return None
    if not host or port is None:
        return None
    return scheme, host, int(port)


def _origin_matches_request(origin: str, host_header: str, request_scheme: str = "http") -> bool:
    parsed_origin = _parse_origin(origin)
    request = _canonical_host_port(host_header, request_scheme)
    if parsed_origin is None or request is None:
        return False
    scheme, origin_host, origin_port = parsed_origin
    if scheme != request_scheme:
        return False
    request_host, request_port = request
    same_host = origin_host == request_host or (_is_loopback_host(origin_host) and _is_loopback_host(request_host))
    return bool(same_host and origin_port == request_port)


def _origin_matches_loopback_server(origin: str, server_address: Any, request_scheme: str = "http") -> bool:
    """Validate against the actual listening socket when a browser/proxy rewrites Host.

    This fallback is intentionally narrow: the server itself must be bound to a loopback
    address, the Origin must also be loopback, and its port must equal the real listening
    port. External origins, remote binds and port changes remain rejected.
    """
    parsed_origin = _parse_origin(origin)
    if parsed_origin is None or not isinstance(server_address, (tuple, list)) or len(server_address) < 2:
        return False
    scheme, origin_host, origin_port = parsed_origin
    try:
        server_host = str(server_address[0]).rstrip(".").lower()
        server_port = int(server_address[1])
    except (TypeError, ValueError, IndexError):
        return False
    if scheme != request_scheme:
        return False
    return bool(_is_loopback_host(server_host) and _is_loopback_host(origin_host) and origin_port == server_port)




def _loopback_socket_context(server_address: Any, client_address: Any) -> bool:
    """Return true only when both the dashboard socket and caller are loopback."""
    if not isinstance(server_address, (tuple, list)) or len(server_address) < 2:
        return False
    if not isinstance(client_address, (tuple, list)) or not client_address:
        return False
    try:
        server_host = str(server_address[0]).rstrip(".").lower()
        client_host = str(client_address[0]).rstrip(".").lower()
        int(server_address[1])
    except (TypeError, ValueError, IndexError):
        return False
    return bool(_is_loopback_host(server_host) and _is_loopback_host(client_host))


def _origin_from_referer(referer: str) -> str:
    """Extract only scheme and authority from a Referer value."""
    if not referer or any(ch in referer for ch in "\r\n"):
        return ""
    try:
        parsed = urllib.parse.urlsplit(referer)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc}"

def _allowed_origin(origin: str, configured: str) -> bool:
    if not origin or not configured:
        return False
    try:
        candidate = urllib.parse.urlsplit(origin)
        c_scheme = candidate.scheme.lower()
        c_host = (candidate.hostname or "").rstrip(".").lower()
        c_port = candidate.port or _default_origin_port(c_scheme)
    except ValueError:
        return False
    if c_scheme not in {"http", "https"} or not c_host or c_port is None:
        return False
    for raw in configured.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            allowed = urllib.parse.urlsplit(raw)
            a_scheme = allowed.scheme.lower()
            a_host = (allowed.hostname or "").rstrip(".").lower()
            a_port = allowed.port or _default_origin_port(a_scheme)
        except ValueError:
            continue
        if (c_scheme, c_host, int(c_port)) == (a_scheme, a_host, int(a_port or 0)):
            return True
    return False


def _json(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return fallback


def _badges(tags: Iterable[str]) -> str:
    return " ".join(f"<span class='tag'>{_esc(tag)}</span>" for tag in tags)


def _tone(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "critical": "danger", "urgent": "danger", "failed": "danger", "error": "danger",
        "high": "orange", "warning": "orange", "warn": "orange",
        "medium": "amber", "triaged": "amber", "interesting": "purple",
        "low": "success", "success": "success", "healthy": "success", "active": "success", "resolved": "success",
        "info": "info", "running": "info", "investigating": "info", "acknowledged": "info",
        "new": "blue", "reported": "purple", "reappeared": "purple", "strong-candidate": "danger", "strong_candidate": "danger", "plausible": "orange", "possible": "amber", "weak-signal": "neutral", "weak_signal": "neutral", "confirmed-by-analyst": "success", "confirmed_by_analyst": "success", "rejected": "neutral", "needs-more-evidence": "info", "needs_more_evidence": "info",
        "ignored": "neutral", "false-positive": "neutral", "false_positive": "neutral", "out-of-scope": "neutral", "out_of_scope": "neutral",
        "inactive": "neutral", "retired": "neutral", "skipped": "neutral",
    }
    return aliases.get(text, "neutral")


def _pill(label: Any, tone: str = "") -> str:
    value = str(label or "—")
    return f"<span class='pill pill-{_esc(tone or _tone(value))}'><span class='pill-dot'></span>{_esc(value.replace('_',' '))}</span>"


def _metric_card(label: str, value: Any, detail: str = "", tone: str = "blue", href: str = "") -> str:
    inner = f"<div class='metric-top'><span>{_esc(label)}</span><span class='metric-spark tone-{_esc(tone)}'></span></div><div class='metric-value'>{_esc(value)}</div>"
    if detail:
        inner += f"<div class='metric-detail'>{_esc(detail)}</div>"
    if href:
        return f"<a class='metric-card' href='{_esc(href)}'>{inner}<span class='metric-arrow'>↗</span></a>"
    return f"<div class='metric-card'>{inner}</div>"


def _score_triad(likelihood: Any, evidence: Any, impact: Any, observation: Any | None = None, exploitability: Any | None = None) -> str:
    items = [
        ("Likelihood", parse_int(likelihood, 0), "purple"),
        ("Evidence", parse_int(evidence, 0), "info"),
        ("Impact", parse_int(impact, 0), "orange"),
    ]
    if exploitability is not None:
        items.append(("Exploitability", parse_int(exploitability, 0), "amber"))
    if observation is not None:
        items.append(("Observation", parse_int(observation, 0), "success"))
    return "<div class='score-triad'>" + "".join(
        f"<div><span>{_esc(label)}</span><strong class='tone-{tone}'>{max(0,min(100,value))}</strong></div>"
        for label,value,tone in items
    ) + "</div>"


def _breadcrumb(*items: tuple[str, str] | str) -> str:
    parts=[]
    for item in items:
        if isinstance(item, tuple):
            label,href=item; parts.append(f"<a href='{_esc(href)}'>{_esc(label)}</a>")
        else:
            parts.append(f"<span>{_esc(item)}</span>")
    return "<nav class='breadcrumbs' aria-label='Breadcrumb'>" + "<i>›</i>".join(parts) + "</nav>"


def _candidate_card(candidate: Mapping[str, Any], compact: bool = False) -> str:
    row=dict(candidate)
    candidate_id=str(row.get('candidate_id') or '')
    link=f"/bug-candidate?id={urllib.parse.quote(candidate_id)}"
    supporting=_json(row.get('supporting_evidence_json'),[])
    opposing=_json(row.get('contradicting_evidence_json'),[])
    missing=_json(row.get('missing_evidence_json'),[])
    source=str(row.get('endpoint') or row.get('source_ref') or row.get('asset') or 'No source reference')
    why=''.join(f"<li>{_esc((e.get('text') if isinstance(e,Mapping) else e))}</li>" for e in supporting[:2])
    if not why:
        why=f"<li>{_esc(row.get('summary') or 'Candidate generated from correlated evidence.')}</li>"
    caveat=''.join(f"<li>{_esc((e.get('text') if isinstance(e,Mapping) else e))}</li>" for e in opposing[:1])
    missing_text=''.join(f"<li>{_esc((e.get('text') if isinstance(e,Mapping) else e))}</li>" for e in missing[:1])
    details='' if compact else f"<div class='candidate-reasoning'><div><strong>Why it matters</strong><ul>{why}</ul></div><div><strong>Why it may be wrong</strong><ul>{caveat or '<li>No contradicting evidence recorded.</li>'}</ul></div><div><strong>What is missing</strong><ul>{missing_text or '<li>No missing evidence recorded.</li>'}</ul></div></div>"
    next_action=str(row.get('safe_next_action') or 'Review the evidence and confirm the expected security boundary.')
    return f"<article class='candidate-card'><div class='candidate-accent tone-{_tone(row.get('candidate_state'))}'></div><div class='candidate-main'><div class='candidate-heading'><div><div class='candidate-kicker'>{_pill(row.get('candidate_state'))}{_pill(row.get('analyst_decision'))}<span>{_esc(row.get('target'))}</span></div><h3><a href='{link}'>{_esc(row.get('title'))}</a></h3><code>{_esc(source)}</code></div><div class='investigation-score'><span>Investigation</span><strong>{parse_int(row.get('investigation_value',row.get('priority_score')),0)}</strong></div></div>{_score_triad(row.get('calibrated_likelihood',row.get('likelihood_score')),row.get('evidence_strength'),row.get('impact_potential'),row.get('observation_quality'),row.get('exploitability_confidence'))}{details}<div class='next-step'><span>Next best action</span><p>{_esc(next_action)}</p></div></div><a class='candidate-open' href='{link}'>Review →</a></article>"


def _audit_evidence_item(item: Mapping[str, Any], polarity: str) -> str:
    snapshot = item.get("snapshot") if isinstance(item.get("snapshot"), Mapping) else {}
    documents = snapshot.get("documents") if isinstance(snapshot, Mapping) and isinstance(snapshot.get("documents"), Mapping) else {}
    doc_html = []
    for name, wrapped in documents.items():
        wrapped = wrapped if isinstance(wrapped, Mapping) else {}
        digest = str(wrapped.get("sha256") or "")
        data = wrapped.get("data", {})
        doc_html.append(
            f"<details class='audit-document'><summary>{_esc(str(name).replace('_',' ').title())}<span class='faint'>sha256 { _esc(digest[:12]) }</span></summary>"
            f"<pre>{_esc(json_dumps(data,pretty=True))}</pre></details>"
        )
    verified = bool(item.get("snapshot_verified"))
    icon = "+" if polarity == "support" else "−"
    tone = "success" if polarity == "support" else "danger"
    meta = " · ".join(x for x in [
        str(item.get("source_kind") or "unknown source"),
        str(item.get("source_tool") or ""),
        f"trust {parse_int(item.get('trust_score'),0)}",
        str(item.get("directness") or ""),
    ] if x)
    lineage = f"{item.get('source_run_id','')} → {item.get('source_group','')} → {item.get('root_fingerprint','')}"
    document_body = ''.join(doc_html)
    if not document_body:
        document_body = '<p class="muted small">No structured source document snapshot was available for this evidence record.</p>'
    return (
        f"<article class='evidence-item'><div class='evidence-icon tone-{tone}'>{icon}</div><div style='min-width:0;flex:1'>"
        f"<div class='split'><strong>{_esc(item.get('evidence_type') or 'evidence')}</strong>{_pill('snapshot verified' if verified else 'snapshot unavailable','success' if verified else 'amber')}</div>"
        f"<div>{_esc(item.get('summary') or '')}</div><small class='faint'>{_esc(meta)}</small>"
        f"<details style='margin-top:8px'><summary>Source, lineage & raw snapshot</summary><div class='kv' style='margin-top:10px'>"
        f"<strong>Evidence ID</strong><code>{_esc(item.get('evidence_id'))}</code><strong>Root</strong><code>{_esc(item.get('root_fingerprint'))}</code>"
        f"<strong>Run lineage</strong><code>{_esc(lineage)}</code><strong>Integrity</strong><code>{_esc(item.get('integrity_hash'))}</code>"
        f"<strong>Raw reference</strong><code>{_esc(item.get('raw_reference'))}</code></div>{document_body}</details>"
        f"</div></article>"
    )


def _audit_exclusion_item(item: Mapping[str, Any]) -> str:
    signal = item.get("signal") if isinstance(item.get("signal"), Mapping) else {}
    return (
        "<article class='evidence-item'><div class='evidence-icon tone-amber'>×</div><div style='min-width:0;flex:1'>"
        f"<strong>{_esc(item.get('reason_code','excluded').replace('_',' '))}</strong><div>{_esc(item.get('reason') or '')}</div>"
        f"<small class='faint'>root {_esc(item.get('root_fingerprint'))} · {_esc(item.get('polarity'))}</small>"
        f"<details style='margin-top:8px'><summary>Excluded signal</summary><pre>{_esc(json_dumps(signal,pretty=True))}</pre></details></div></article>"
    )


def _attention_item(label: str, value: Any, detail: str, href: str, tone: str = 'info') -> str:
    return f"<a class='attention-item' href='{_esc(href)}'><span class='attention-icon tone-{_esc(tone)}'>●</span><div><strong>{_esc(label)}</strong><small>{_esc(detail)}</small></div><b>{_esc(value)}</b><i>→</i></a>"


def _command_decision_item(item: Mapping[str, Any], rank: int) -> str:
    tone = str(item.get('tone') or _tone(item.get('priority')))
    score = max(0, min(100, parse_int(item.get('score'), 0)))
    meta = str(item.get('meta') or '')
    return (
        f"<a class='command-decision' href='{_esc(item.get('href') or '/')}' data-decision-kind='{_esc(item.get('kind') or 'item')}'>"
        f"<span class='decision-rank'>{rank:02d}</span>"
        f"<span class='decision-copy'><small>{_esc(item.get('eyebrow') or 'Review')}</small><strong>{_esc(item.get('title') or 'Review item')}</strong>"
        f"<span>{_esc(item.get('detail') or '')}</span>{f'<em>{_esc(meta)}</em>' if meta else ''}</span>"
        f"<span class='decision-score tone-{_esc(tone)}'><b>{score}</b><small>priority</small></span><i>→</i></a>"
    )


def _command_center_snapshot(db: Database, target: str = "") -> dict[str, Any]:
    data = cockpit(db, target=target)
    latest_run = db.one("SELECT id,status,started_at,finished_at,error,target_count FROM runs ORDER BY started_at DESC LIMIT 1")
    latest_analysis = db.one("SELECT id,status,target,started_at,finished_at FROM analysis_runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
    analysis_id = str(latest_analysis['id']) if latest_analysis else ''
    candidate_args: list[Any] = [analysis_id]
    candidate_where = ["analysis_id=?", "analyst_decision='unreviewed'", "candidate_state IN ('strong_candidate','plausible')"]
    if target:
        candidate_where.append("target=?"); candidate_args.append(target)
    candidates = [dict(r) for r in db.all(
        f"SELECT candidate_id,target,title,bug_family,candidate_state,investigation_value,calibrated_likelihood,evidence_strength,impact_potential,endpoint,safe_next_action FROM bug_candidates WHERE {' AND '.join(candidate_where)} ORDER BY investigation_value DESC,calibrated_likelihood DESC LIMIT 8",
        tuple(candidate_args),
    )] if analysis_id else []
    case_args: list[Any] = []
    case_where = ["state NOT IN ('reported','closed','rejected')"]
    if target:
        case_where.append("target=?"); case_args.append(target)
    cases = [dict(r) for r in db.all(
        f"SELECT case_id,target,title,state,priority_score,evidence_gap_score,autopilot_score,updated_at FROM security_cases WHERE {' AND '.join(case_where)} ORDER BY priority_score DESC,updated_at DESC LIMIT 8",
        tuple(case_args),
    )]
    changes = _change_alert_events(db, target)
    recent_runs = [dict(r) for r in db.all(
        "SELECT id,status,started_at,finished_at,error,target_count FROM runs ORDER BY started_at DESC LIMIT 5"
    )]
    decisions: list[dict[str, Any]] = []
    if latest_run and str(latest_run['status']) == 'failed':
        decisions.append({
            'kind':'run','eyebrow':'Run failure','title':'Repair the latest recon run','detail':str(latest_run['error'] or 'The latest recon did not complete successfully.'),
            'href':'/runs','score':98,'tone':'danger','meta':str(latest_run['id']),
        })
    for row in candidates:
        score=parse_int(row.get('investigation_value'),0)
        decisions.append({
            'kind':'candidate','eyebrow':'Potential finding','title':str(row.get('title') or 'Review potential finding'),
            'detail':str(row.get('safe_next_action') or 'Review evidence and decide whether more bounded validation is justified.'),
            'href':f"/bug-candidate?id={urllib.parse.quote(str(row.get('candidate_id') or ''))}",
            'score':score,'tone':'danger' if score>=85 else 'orange',
            'meta':f"{row.get('target','')} · {str(row.get('bug_family') or '').replace('_',' ')} · likelihood {parse_int(row.get('calibrated_likelihood'),0)}%",
        })
    for row in cases:
        state=str(row.get('state') or '')
        base=parse_int(row.get('priority_score'),0)
        if state=='needs_evidence':
            eyebrow='Evidence gap'; detail=f"Evidence gap {parse_int(row.get('evidence_gap_score'),0)}% · collect the missing observation before stronger claims."; score=max(base,76); tone='amber'
        elif state=='ready_for_validation':
            eyebrow='Validation ready'; detail='Review the bounded validation plan before any approved execution.'; score=max(base,82); tone='purple'
        else:
            eyebrow='Open investigation'; detail=f"Case state: {state.replace('_',' ')} · continue the highest-value investigation step."; score=base; tone='info'
        decisions.append({
            'kind':'case','eyebrow':eyebrow,'title':str(row.get('title') or 'Continue investigation'),'detail':detail,
            'href':f"/case?id={urllib.parse.quote(str(row.get('case_id') or ''))}",'score':score,'tone':tone,
            'meta':f"{row.get('target','')} · {row.get('case_id','')}",
        })
    for event in changes[:12]:
        if str(event.get('priority')) not in {'high','medium'}:
            continue
        score=parse_int(event.get('score'),0)
        decisions.append({
            'kind':'change','eyebrow':f"{str(event.get('priority') or 'medium').title()}-interest change",
            'title':f"{str(event.get('kind') or 'surface').replace('_',' ').title()} {str(event.get('change') or 'changed')}",
            'detail':str(event.get('details') or event.get('value') or ''),
            'href':_query_link('/alerts',target=str(event.get('target') or target)),
            'score':score,'tone':'danger' if str(event.get('priority'))=='high' else 'amber',
            'meta':f"{event.get('target','')} · {event.get('value','')}",
        })
    kind_order={'run':0,'candidate':1,'case':2,'change':3}
    decisions.sort(key=lambda x:(-parse_int(x.get('score'),0),kind_order.get(str(x.get('kind')),9),str(x.get('title') or '')) )
    high_changes=sum(1 for e in changes if str(e.get('priority'))=='high')
    medium_changes=sum(1 for e in changes if str(e.get('priority'))=='medium')
    if decisions:
        next_action={**decisions[0]}
    elif not latest_run:
        next_action={'kind':'recon','eyebrow':'Start here','title':'Run the first authorized recon','detail':'Create the initial baseline before analysis or change detection.','href':'/runs','score':0,'tone':'info','meta':''}
    elif data.get('needs_evidence'):
        next_action={'kind':'evidence','eyebrow':'Next best action','title':'Close the highest-value evidence gap','detail':'Improve evidence coverage before attempting stronger conclusions.','href':'/evidence-gaps','score':0,'tone':'amber','meta':''}
    else:
        next_action={'kind':'refresh','eyebrow':'Next best action','title':'Refresh workspace intelligence','detail':'Recalculate target memory, change intelligence, coverage and investigation guidance.','href':'/smart-recon','score':0,'tone':'success','meta':''}
    return {
        'cockpit':data,'latest_run':dict(latest_run) if latest_run else None,'latest_analysis':dict(latest_analysis) if latest_analysis else None,
        'candidates':candidates,'cases':cases,'changes':changes,'recent_runs':recent_runs,'decisions':decisions[:8],'next_action':next_action,
        'high_changes':high_changes,'medium_changes':medium_changes,
    }


def _page_header(title: str, subtitle: str = "", actions: str = "", eyebrow: str = "") -> str:
    copy = f"<div>{f'<div class=eyebrow>{_esc(eyebrow)}</div>' if eyebrow else ''}<h1>{_esc(title)}</h1>{f'<p class=page-subtitle>{_esc(subtitle)}</p>' if subtitle else ''}</div>"
    return f"<div class='page-header'>{copy}{f'<div class=page-actions>{actions}</div>' if actions else ''}</div>"


def _empty(title: str, detail: str = "") -> str:
    return f"<div class='empty-state'><div class='empty-icon'>◇</div><strong>{_esc(title)}</strong>{f'<span>{_esc(detail)}</span>' if detail else ''}</div>"


def _risk_meter(score: Any) -> str:
    value = max(0, min(100, parse_int(score, 0)))
    tone = "danger" if value >= 90 else "orange" if value >= 70 else "amber" if value >= 40 else "success"
    return f"<div class='risk-meter'><div class='risk-score tone-{tone}'>{value}</div><div class='risk-track'><span class='tone-{tone}' style='width:{value}%'></span></div><div class='risk-scale'><span>0</span><span>Risk score</span><span>100</span></div></div>"


def _confidence(value: Any) -> str:
    number = max(0, min(100, parse_int(value, 0)))
    tone = "success" if number >= 80 else "info" if number >= 55 else "amber" if number >= 30 else "neutral"
    return f"<div class='confidence'><span>{number}%</span><div><i class='tone-{tone}' style='width:{number}%'></i></div></div>"


def _candidate_confidence_story(candidate: Mapping[str, Any]) -> str:
    row = dict(candidate)
    likelihood = max(0, min(100, parse_int(row.get("calibrated_likelihood", row.get("likelihood_score")), 0)))
    supporting = len(_json(row.get("supporting_evidence_json"), []))
    opposing = len(_json(row.get("contradicting_evidence_json"), []))
    missing = len(_json(row.get("missing_evidence_json"), []))
    tone = "danger" if likelihood >= 85 else "orange" if likelihood >= 70 else "amber" if likelihood >= 50 else "neutral"
    factors = [
        ("Calibrated likelihood", likelihood, tone, "How strongly this bug family fits after calibration."),
        ("Evidence strength", parse_int(row.get("evidence_strength"), 0), "info", "Strength and independence of linked observations."),
        ("Evidence coverage", parse_int(row.get("evidence_coverage"), 0), "purple", "Coverage of required, supporting and falsifying evidence."),
        ("Observation quality", parse_int(row.get("observation_quality"), 0), "success", "Reliability and completeness of the underlying observations."),
        ("Exploitability", parse_int(row.get("exploitability_confidence"), 0), "amber", "Whether the observed pattern appears reachable and practically relevant."),
    ]
    bars = "".join(
        f"<div class='confidence-factor'><div><strong>{_esc(label)}</strong><span>{max(0,min(100,value))}%</span></div><div class='factor-track'><i class='tone-{factor_tone}' style='width:{max(0,min(100,value))}%'></i></div><small>{_esc(detail)}</small></div>"
        for label, value, factor_tone, detail in factors
    )
    verdict = "High-confidence review candidate" if likelihood >= 80 else "Moderate-confidence review candidate" if likelihood >= 55 else "Low-confidence signal — gather more evidence first"
    return f"<section class='panel confidence-story'><div class='panel-head'><div><h3>Why this confidence?</h3><span class='muted small'>Explainable review signals, not a claim of a confirmed vulnerability.</span></div>{_pill(str(likelihood)+'%', tone)}</div><div class='panel-body'><div class='confidence-verdict'><strong>{_esc(verdict)}</strong><span>{supporting} supporting · {opposing} contradicting · {missing} missing evidence item(s)</span></div><div class='confidence-factors'>{bars}</div><p class='muted small'>These factors are not an additive formula. Calibrated likelihood is the model output; the remaining signals explain evidence quality and practical review context.</p></div></section>"


def _workflow_steps(current: str) -> str:
    steps = ["new", "triaged", "investigating", "interesting", "reported", "resolved"]
    rank = {name: index for index, name in enumerate(steps)}
    current_index = rank.get(str(current), -1)
    items = []
    for index, step in enumerate(steps):
        state = "done" if current_index > index else "current" if current_index == index else "future"
        items.append(f"<div class='flow-step {state}'><span>{index+1}</span><small>{_esc(step)}</small></div>")
    return "<div class='workflow-steps'>" + "".join(items) + "</div>"


def _suggested_action(alert: Mapping[str, Any]) -> tuple[str, str]:
    status = str(alert.get("status") or "new")
    score = parse_int(alert.get("risk_score"), 0)
    if status == "new":
        return "Triage evidence", "Review the risk reasons, confirm scope, and classify the signal before active validation."
    if status in {"triaged", "acknowledged"}:
        return "Build a hypothesis", "Connect the alert to related assets, endpoints, JavaScript changes, and historical observations."
    if status == "investigating":
        return "Record reproducible evidence", "Capture the minimum safe verification steps and mark contradictory evidence explicitly."
    if status == "interesting" or score >= 85:
        return "Prepare report package", "Export evidence, verify timestamps and hashes, then document impact without overstating certainty."
    if status == "reported":
        return "Track response", "Keep the report reference and update the workflow when the program responds."
    return "Review lifecycle", "Confirm whether the alert is resolved, ignored, out of scope, or needs another observation."


def _diff_html(text: str) -> str:
    lines = []
    for line in str(text or "").splitlines():
        cls = "diff-add" if line.startswith("+") and not line.startswith("+++") else "diff-del" if line.startswith("-") and not line.startswith("---") else "diff-hunk" if line.startswith("@@") else "diff-meta" if line.startswith(("+++", "---")) else ""
        lines.append(f"<span class='{cls}'>{_esc(line)}</span>")
    return "\n".join(lines)


def _change_priority(kind: str, change: str, value: str = "") -> tuple[str, int]:
    text = (value or "").lower()
    kind = (kind or "").lower()
    if kind in {"authentication", "authentication_boundary", "sensitive_response", "response_shape"}:
        return "high", 90
    if kind == "port" and any(token in text for token in (":22", ":2375", ":3389", ":5432", ":6379", ":9200")):
        return "high", 88
    if any(token in text for token in ("admin", "internal", "auth", "oauth", "login", "upload", "export", "graphql", "debug")):
        return "high", 84
    if kind in {"endpoint", "url", "javascript", "port"} and change == "added":
        return "medium", 68
    if kind in {"subdomain", "technology"} and change == "added":
        return "medium", 56
    if change == "changed":
        return "medium", 62
    return "low", 35


def _latest_successful_runs(db: Database, target: str = "") -> list[dict[str, str]]:
    params: list[Any] = []
    where = ""
    if target:
        where = " AND rt.target=?"
        params.append(target)
    rows = db.all(
        "SELECT rt.target,r.id,r.started_at,COALESCE(r.finished_at,r.started_at) finished_at "
        "FROM runs r JOIN run_targets rt ON rt.run_id=r.id WHERE r.status='success'" + where +
        " AND COALESCE(r.finished_at,r.started_at)=(SELECT MAX(COALESCE(r2.finished_at,r2.started_at)) FROM runs r2 JOIN run_targets rt2 ON rt2.run_id=r2.id WHERE r2.status='success' AND rt2.target=rt.target) "
        "ORDER BY COALESCE(r.finished_at,r.started_at) DESC,rt.target",
        tuple(params),
    )
    out=[]
    for row in rows:
        prev=db.one(
            "SELECT r.id,COALESCE(r.finished_at,r.started_at) ts FROM runs r JOIN run_targets rt ON rt.run_id=r.id "
            "WHERE r.status='success' AND rt.target=? AND COALESCE(r.finished_at,r.started_at)<? ORDER BY COALESCE(r.finished_at,r.started_at) DESC LIMIT 1",
            (row['target'], row['finished_at']),
        )
        out.append({"target":str(row['target']),"run_id":str(row['id']),"started_at":str(row['started_at'] or ''),"finished_at":str(row['finished_at'] or ''),"previous_run":str(prev['id']) if prev else ""})
    return out


def _change_alert_events(db: Database, target: str = "") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for run in _latest_successful_runs(db, target):
        # The first successful run is the baseline. Alerts begin on re-checks.
        if not run['previous_run']:
            continue
        t=run['target']; rid=run['run_id']; started=run['started_at'] or run['finished_at']
        specs = [
            ("subdomain", "assets", "host", "host", "first_seen"),
            ("url", "urls", "url", "url", "first_seen"),
            ("javascript", "js_files", "url", "url", "first_seen"),
            ("endpoint", "endpoint_intelligence", "endpoint", "endpoint", "first_seen"),
            ("technology", "technology_observations", "technology", "technology", "first_seen"),
        ]
        for kind, table, value_col, label_col, first_col in specs:
            rows=db.all(f"SELECT {value_col} value,{first_col} first_seen,last_seen FROM {table} WHERE target=? AND last_run_id=? AND {first_col}>=? ORDER BY {first_col} DESC LIMIT 300",(t,rid,started))
            for row in rows:
                value=str(row['value'] or '')
                priority,score=_change_priority(kind,'added',value)
                events.append({"target":t,"run_id":rid,"previous_run":run['previous_run'],"kind":kind,"change":"added","value":value,"priority":priority,"score":score,"detected":str(row['first_seen'] or run['finished_at']),"details":"Newly observed during the latest successful recon."})
        for row in db.all("SELECT host,ip,port,protocol,first_seen FROM ports WHERE target=? AND last_run_id=? AND first_seen>=? ORDER BY first_seen DESC LIMIT 300",(t,rid,started)):
            value=f"{row['host']}:{row['port']}/{row['protocol']}"
            priority,score=_change_priority('port','added',value)
            events.append({"target":t,"run_id":rid,"previous_run":run['previous_run'],"kind":"port","change":"added","value":value,"priority":priority,"score":score,"detected":str(row['first_seen'] or run['finished_at']),"details":f"New service exposure{(' · '+str(row['ip'])) if row['ip'] else ''}."})
        for row in db.all("SELECT url,status_code,title,webserver,last_changed FROM fingerprints WHERE target=? AND last_run_id=? AND COALESCE(last_changed,'')>=? ORDER BY last_changed DESC LIMIT 300",(t,rid,started)):
            value=str(row['url'] or '')
            priority,score=_change_priority('response','changed',value)
            details=f"HTTP response fingerprint changed · status {row['status_code'] or 'unknown'}"
            if row['title']: details+=f" · {row['title']}"
            events.append({"target":t,"run_id":rid,"previous_run":run['previous_run'],"kind":"response","change":"changed","value":value,"priority":priority,"score":score,"detected":str(row['last_changed'] or run['finished_at']),"details":details})
        analysis=db.one("SELECT id FROM analysis_runs WHERE status='success' AND target IN (?, '*') AND started_at>=? ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1",(t,started))
        if analysis:
            aid=str(analysis['id'])
            for row in db.all("SELECT endpoint,transition,confidence,severity,created_at FROM authentication_boundary_diffs WHERE analysis_id=? AND target=? ORDER BY confidence DESC LIMIT 100",(aid,t)):
                value=str(row['endpoint'] or '')
                priority,score=_change_priority('authentication_boundary','changed',value)
                score=max(score,parse_int(row['confidence'],0))
                events.append({"target":t,"run_id":rid,"previous_run":run['previous_run'],"kind":"authentication","change":"changed","value":value,"priority":priority,"score":score,"detected":str(row['created_at'] or run['finished_at']),"details":f"Authentication boundary changed: {row['transition']} · confidence {row['confidence']}%"})
            for row in db.all("SELECT endpoint,transition,confidence,severity,sensitive_added_json,created_at FROM response_shape_diffs WHERE analysis_id=? AND target=? ORDER BY confidence DESC LIMIT 100",(aid,t)):
                sensitive=_json(row['sensitive_added_json'],[])
                if not sensitive and parse_int(row['confidence'],0)<70:
                    continue
                value=str(row['endpoint'] or '')
                priority,score=_change_priority('sensitive_response' if sensitive else 'response_shape','changed',value)
                score=max(score,parse_int(row['confidence'],0))
                suffix=f" · sensitive keys: {', '.join(str(x) for x in sensitive[:4])}" if sensitive else ""
                events.append({"target":t,"run_id":rid,"previous_run":run['previous_run'],"kind":"response_shape","change":"changed","value":value,"priority":priority,"score":score,"detected":str(row['created_at'] or run['finished_at']),"details":f"Response structure changed: {row['transition']}{suffix}"})
    # Stable deterministic ordering and event IDs for UI use.
    events.sort(key=lambda x:(x.get('detected',''),x.get('score',0)),reverse=True)
    for index,event in enumerate(events,1):
        event['event_id']=f"CHG-{index:04d}"
    return events


RECON_CATEGORY_ORDER = [
    "hosts", "apis", "authentication", "admin_internal", "file_upload",
    "data_object", "client_side", "infrastructure", "other",
]
RECON_CATEGORY_META = {
    "hosts": ("Hosts & Subdomains", "Hosts, subdomains and discovered network names", "HS"),
    "apis": ("APIs", "REST, GraphQL, WebSocket and API-like routes", "API"),
    "authentication": ("Authentication", "Login, session, token, recovery, OAuth and identity surfaces", "AU"),
    "admin_internal": ("Admin / Internal", "Administrative, internal, debug and management surfaces", "AI"),
    "file_upload": ("File & Upload", "Upload, download, import, export and file-handling surfaces", "FU"),
    "data_object": ("Data / Object", "Object identifiers and business-data access surfaces", "DO"),
    "client_side": ("Client-side / JavaScript", "JavaScript, source maps and client-discovered routes", "JS"),
    "infrastructure": ("Infrastructure", "Ports, services, HTTP/TLS fingerprints and technologies", "IF"),
    "other": ("Other", "Observed surface not yet classified into a stronger security context", "OT"),
}
RECON_RAW_META = {
    "host": ("Hosts", "Hosts and subdomains"), "url": ("URLs", "Observed web locations"),
    "endpoint": ("Endpoints", "Normalized route intelligence"), "port": ("Ports", "Network services"),
    "javascript": ("JavaScript", "Client-side resources"), "fingerprint": ("Fingerprints", "HTTP, TLS and technology observations"),
}


def _recon_security_categories(kind: str, value: str, detail: str = "", existing: Iterable[str] = ()) -> list[str]:
    text = " ".join([kind, value, detail, *[str(x) for x in existing]]).lower()
    labels: set[str] = set()
    if kind == "host": labels.add("hosts")
    if kind == "endpoint" or re.search(r"(?:^|/)(?:api|graphql|graphiql|ws|websocket)(?:/|$)", text) or re.search(r"/v[0-9]+(?:/|$)", text): labels.add("apis")
    if any(x in text for x in ("login","logout","signin","sign-in","signup","sign-up","register","auth","oauth","oidc","sso","session","token","password","passwd","reset","recover","recovery","mfa","2fa")): labels.add("authentication")
    if any(x in text for x in ("admin","internal","debug","management","manage/","backoffice","back-office","staff","console","actuator")): labels.add("admin_internal")
    if any(x in text for x in ("upload","download","attachment","attachments","import","export","file/","files/","document","media/","multipart","source-map","sourcemap")): labels.add("file_upload")
    if any(x in text for x in ("/user","/account","/profile","/order","/invoice","/project","/tenant","/customer","/record","/item","/object","/document","{id}",":id","uuid","object_id","user_id","account_id","tenant_id")): labels.add("data_object")
    if kind == "javascript" or ".js" in value.lower() or "source map" in text or "sourcemap" in text: labels.add("client_side")
    if kind in {"port","fingerprint"}: labels.add("infrastructure")
    if not labels: labels.add("other")
    return [key for key in RECON_CATEGORY_ORDER if key in labels]


def _recon_interest_score(kind: str, categories: Iterable[str], confidence: int = 0, change_state: str = "stable", source_count: int = 1) -> int:
    score = {"host":16,"url":22,"endpoint":34,"port":24,"javascript":20,"fingerprint":18}.get(kind,15)
    weights = {"apis":10,"authentication":20,"admin_internal":24,"file_upload":15,"data_object":15,"client_side":5,"infrastructure":5,"hosts":2}
    for category in set(categories): score += weights.get(category,0)
    score += min(10, max(0,int(confidence))//10)
    if change_state == "new": score += 15
    elif change_state in {"changed","reappeared"}: score += 12
    elif change_state == "disappeared": score += 5
    score += min(8, max(0,source_count-1)*2)
    return max(0,min(100,score))


def _recon_surface_items(db: Database, target: str = "") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    clause = " WHERE target=?" if target else ""
    args: tuple[Any,...] = (target,) if target else ()
    changes = _change_alert_events(db, target)
    change_map: dict[tuple[str,str,str],dict[str,Any]] = {}
    kind_alias = {"subdomain":"host","endpoint":"endpoint","url":"url","port":"port","javascript":"javascript","fingerprint":"fingerprint"}
    for event in changes:
        kind = kind_alias.get(str(event.get("kind") or ""))
        if not kind: continue
        key=(str(event.get("target") or ""),kind,str(event.get("value") or ""))
        current=change_map.get(key)
        if current is None or parse_int(event.get("score"),0)>parse_int(current.get("score"),0): change_map[key]=event
    items: list[dict[str,Any]]=[]
    def add(kind: str, row: Mapping[str,Any], value: str, detail: str, confidence: int, sources: Iterable[str], existing: Iterable[str] = ()) -> None:
        row=dict(row)
        src=[str(x) for x in sources if str(x).strip()]
        if not src: src=["stored recon observation"]
        event=change_map.get((str(row.get("target") or ""),kind,value))
        change_state=str(event.get("change") if event else "stable")
        cats=_recon_security_categories(kind,value,detail,existing)
        items.append({
            "kind":kind,"target":str(row.get("target") or ""),"value":value,"detail":detail,
            "confidence":max(0,min(100,int(confidence or 0))),"categories":cats,
            "interest":_recon_interest_score(kind,cats,int(confidence or 0),change_state,len(src)),
            "change_state":change_state,"sources":src,"first_seen":str(row.get("first_seen") or ""),
            "last_seen":str(row.get("last_seen") or ""),"last_run_id":str(row.get("last_run_id") or ""),
        })
    for r in db.all("SELECT target,host,sources_json,confidence,first_seen,last_seen,last_run_id FROM assets"+clause+" ORDER BY last_seen DESC LIMIT 1500",args):
        add("host",r,str(r["host"]),"Discovered host",parse_int(r["confidence"],0),_json(r["sources_json"],[]))
    for r in db.all("SELECT target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id FROM endpoint_intelligence"+clause+" ORDER BY confidence DESC,last_seen DESC LIMIT 2000",args):
        cats=_json(r["categories_json"],[]); reasons=_json(r["reasons_json"],[])
        detail=" · ".join([str(r["primary_category"] or "endpoint")]+[str(x) for x in reasons[:2]])
        add("endpoint",r,str(r["endpoint"]),detail,parse_int(r["confidence"],0),_json(r["sources_json"],[]),cats)
    for r in db.all("SELECT target,url,kind,source,first_seen,last_seen,last_run_id FROM urls"+clause+" ORDER BY last_seen DESC LIMIT 2000",args):
        add("url",r,str(r["url"]),str(r["kind"] or "URL"),0,[str(r["source"] or "")])
    for r in db.all("SELECT target,host,ip,port,protocol,first_seen,last_seen,last_run_id,is_current FROM ports"+clause+" ORDER BY last_seen DESC LIMIT 1500",args):
        value=f"{r['host']}:{r['port']}/{r['protocol']}"; detail=f"{r['ip'] or 'IP not recorded'} · {'current' if r['is_current'] else 'not current'}"
        add("port",r,value,detail,0,["stored port observation"])
    for r in db.all("SELECT target,url,source_map_url,first_seen,last_seen,last_changed,last_run_id FROM js_files"+clause+" ORDER BY last_seen DESC LIMIT 1500",args):
        detail="Source map observed" if r["source_map_url"] else "JavaScript resource"
        add("javascript",r,str(r["url"]),detail,0,["stored JavaScript observation"],["client-side"])
    for r in db.all("SELECT target,url,status_code,title,webserver,technologies_json,content_type,ip,cdn,first_seen,last_seen,last_changed,last_run_id FROM fingerprints"+clause+" ORDER BY last_seen DESC LIMIT 1500",args):
        tech=[str(x) for x in _json(r["technologies_json"],[])[:4]]
        detail=" · ".join(x for x in [str(r["status_code"] or ""),str(r["webserver"] or ""),", ".join(tech),str(r["cdn"] or "")] if x)
        add("fingerprint",r,str(r["url"]),detail,0,["stored HTTP/TLS observation"],tech)
    items.sort(key=lambda x:(parse_int(x.get("interest"),0),str(x.get("last_seen") or "")),reverse=True)
    targets=[str(r[0]) for r in db.all("SELECT target FROM (SELECT DISTINCT target FROM assets UNION SELECT DISTINCT target FROM urls UNION SELECT DISTINCT target FROM endpoint_intelligence UNION SELECT DISTINCT target FROM run_targets) ORDER BY target")]
    coverage_rows=[]
    for tgt in ([target] if target else targets[:25]):
        if not tgt: continue
        try: coverage_rows.append(recon_coverage(db,target=tgt,persist=False))
        except Exception: continue
    coverage_overall=round(sum(parse_int(x.get("overall"),0) for x in coverage_rows)/len(coverage_rows)) if coverage_rows else 0
    blind=[]
    for row in coverage_rows:
        for spot in row.get("blind_spots",[]):
            label=f"{row.get('target')}: {spot}" if not target else str(spot)
            if label not in blind: blind.append(label)
    return items,{"targets":targets,"coverage_overall":coverage_overall,"blind_spots":blind[:8],"changes":changes}


NAV_SECTIONS = [
    ("recon", "01 · Recon", "01", "Discover and map", [
        ("/recon", "Recon workspace", "RC"), ("/assets", "Assets", "AS"), ("/asset", "Asset", "AS"),
        ("/endpoints", "Endpoints", "EP"), ("/urls", "URLs", "URL"), ("/javascript", "JavaScript", "JS"),
        ("/js-diff", "JavaScript diff", "JD"), ("/fingerprints", "HTTP / TLS", "HT"), ("/runs", "Run history", "RN"),
        ("/attack-surface", "Attack surface", "AG"), ("/graph", "Asset graph", "GR"),
        ("/recon-coverage", "Recon coverage", "CV"), ("/target-memory", "Target memory", "TM"),
        ("/smart-recon", "Smart recon planner", "SP"), ("/browser-capture", "Browser capture", "BC"),
        ("/lifecycle", "Lifecycle", "LC"),
    ]),
    ("analysis", "02 · Analysis", "02", "Understand what the evidence means", [
        ("/analysis", "Analysis", "AN"),
    ]),
    ("findings", "03 · Potential Findings", "03", "Review probable bugs", [
        ("/potential-findings", "Potential findings", "PF"), ("/bug-candidates", "Potential findings", "PF"),
        ("/bug-candidate", "Finding detail", "PF"), ("/cases", "Reviewed cases", "CS"), ("/case", "Case detail", "CS"),
        ("/safe-validation", "Validation", "SV"), ("/case-autopilot", "Case autopilot", "AP"),
        ("/report-builder", "Reports", "RP"), ("/candidate-quality", "Candidate quality", "CQ"),
        ("/candidate-bundles", "Candidate bundles", "CB"), ("/workbench", "Review queue", "RQ"),
        ("/validation-intelligence", "Validation intelligence", "VI"), ("/review-priority", "Review priority", "PR"),
        ("/report-quality", "Report quality", "RQ"), ("/learning", "False-positive learning", "FL"),
    ]),
    ("alerts", "04 · Alerts", "04", "See what changed", [
        ("/alerts", "Change alerts", "AL"), ("/signal-alerts", "Signal workflow", "SG"), ("/alert", "Alert detail", "AL"),
        ("/change-intelligence", "Change intelligence", "CH"), ("/compare", "Compare runs", "CR"),
        ("/daily", "Recent changes", "RC"), ("/incidents", "Incidents", "IN"),
    ]),
]

# Only cross-cutting system functions belong here. Research pages live exclusively
# inside their owning workspace above so the sidebar never exposes duplicate paths.
ADVANCED_NAV_SECTIONS = [
    ("Operations", [
        ("/operations-center", "Operations center", "OC"), ("/storage-health", "Storage health", "SH"),
        ("/automation", "Automation", "AU"), ("/performance", "Performance", "PF"),
        ("/retention", "Retention", "RT"), ("/views", "Saved views", "VW"),
    ]),
    ("Safety & governance", [
        ("/scope-center", "Scope center", "SC"), ("/targets", "Targets", "TG"),
        ("/safety-center", "Safety center", "SF"), ("/platform-security", "Platform security", "PS"),
        ("/diagnostics", "Diagnostics", "DX"), ("/rules", "Rule governance", "RG"),
        ("/audit", "Audit trail", "AT"),
    ]),
    ("System quality & configuration", [
        ("/engine-quality", "Engine quality", "EQ"), ("/data-quality", "Data quality", "DQ"),
        ("/templates", "Target templates", "TP"), ("/plugins", "Plugins", "PL"),
    ]),
]


def _layout(title: str, body: str, csrf: str = "", username: str = "", role: str = "", current_path: str = "") -> str:
    body = _inject_csrf_inputs(body, csrf)
    csrf_json = json.dumps(csrf)
    path_only = urllib.parse.urlsplit(current_path or "/").path
    active_path = {'/alert':'/potential-findings','/asset':'/recon','/js-diff':'/recon','/bug-candidate':'/potential-findings','/bug-candidates':'/potential-findings','/case':'/potential-findings','/signal-alerts':'/alerts','/behavioral-intelligence':'/analysis','/differential-intelligence':'/analysis','/evidence-gaps':'/analysis','/security-reasoning':'/analysis','/semantic-intelligence':'/analysis','/auth-contexts':'/analysis','/hypotheses':'/analysis','/clusters':'/analysis','/dataflows':'/analysis','/analysis-quality':'/analysis','/security-stories':'/analysis'}.get(path_only, path_only)
    login_mode = path_only == '/login'
    nav = []
    command_active = active_path == "/"
    nav.append(
        f"<a class='nav-item{' active' if command_active else ''}' href='/' data-command-center='1'>"
        f"<span class='nav-icon'>CC</span><span class='nav-group-copy'><strong>Command Center</strong><small>Overview and decision inbox</small></span><b>→</b></a>"
    )
    primary_hrefs={"recon":"/recon","analysis":"/analysis","findings":"/potential-findings","alerts":"/alerts"}
    for section_id, section, group_icon, hint, links in NAV_SECTIONS:
        href=primary_hrefs[section_id]
        group_active=any(active_path == item_href or (item_href != "/" and active_path.startswith(item_href)) for item_href,_,_ in links)
        nav.append(
            f"<a class='nav-item{' active' if group_active else ''}' href='{href}' data-nav-group='{_esc(section_id)}' data-primary-workspace='1'>"
            f"<span class='nav-icon'>{_esc(group_icon)}</span><span class='nav-group-copy'><strong>{_esc(section)}</strong><small>{_esc(hint)}</small></span><b>→</b></a>"
        )
    advanced_links=[link for _,links in ADVANCED_NAV_SECTIONS for link in links]
    advanced_active=any(active_path == href or active_path.startswith(href) for href,_,_ in advanced_links)
    advanced_groups=[]
    for group_label,links in ADVANCED_NAV_SECTIONS:
        items=[]
        for href,label,icon in links:
            active=active_path == href or active_path.startswith(href)
            items.append(f"<a class='nav-item{' active' if active else ''}' href='{href}'><span class='nav-icon'>{_esc(icon)}</span><span class='nav-text'>{_esc(label)}</span></a>")
        advanced_groups.append(f"<div class='advanced-group'><div class='advanced-label'>{_esc(group_label)}</div>{''.join(items)}</div>")
    advanced_nav=f"<details class='advanced-nav' data-nav-group='advanced' data-active='{'1' if advanced_active else '0'}'{' open' if advanced_active else ''}><summary><span class='nav-group-icon'>••</span><span class='nav-group-copy'><strong>System</strong><small>Operations, safety and settings</small></span><b>⌄</b></summary><div class='nav-items'>{''.join(advanced_groups)}</div></details>"
    legacy_nav_contract="<div hidden aria-hidden='true'><details data-nav-group='workspace'><summary>Decide, validate, report</summary></details><details data-nav-group='analysis'><summary>Candidates and reasoning</summary></details><details data-nav-group='quality'></details><details data-nav-group='operations'><summary>Scope, runs and platform health</summary></details><details data-nav-group='inventory'></details></div>"
    user = _esc(username or "local")
    user_role = _esc(role or "viewer")
    parsed_path=urllib.parse.urlsplit(current_path or '/')
    focus_target=str((urllib.parse.parse_qs(parsed_path.query).get('target') or [''])[0])
    focus_chip=f"<span class='focus-chip'><small>Focus</small><strong>{_esc(focus_target)}</strong></span>" if focus_target else ""
    section_name='Command Center' if active_path == '/' else 'Workspace'
    for _,section,_,_,links in NAV_SECTIONS:
        if any(active_path == href or (href != '/' and active_path.startswith(href)) for href,_,_ in links):
            section_name=section; break
    if advanced_active: section_name='System'
    return f"""<!doctype html>
<html lang='en' data-theme='dark'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{_esc(title)} — Recon Monitor</title>
<style>
:root{{--bg:#050b14;--bg-2:#07111f;--surface:#0a1422;--surface-2:#0e1a2b;--surface-3:#13233a;--surface-raised:#101d31;--text:#f4f7ff;--muted:#9aa8c2;--faint:#677791;--border:#1d3048;--border-strong:#31506f;--brand:#758bff;--brand-2:#46c7ff;--brand-soft:rgba(70,199,255,.09);--success:#50d890;--info:#59b9ff;--amber:#f2c45f;--orange:#ff9c63;--danger:#ff6b82;--purple:#b692ff;--shadow:0 24px 70px rgba(0,0,0,.38);--shadow-soft:0 12px 34px rgba(0,0,0,.20);--ring:0 0 0 3px rgba(70,199,255,.12);--sidebar:276px}}
html[data-theme='light']{{--bg:#f3f6fb;--bg-2:#edf3fa;--surface:#fff;--surface-2:#f7f9fd;--surface-3:#edf2fa;--surface-raised:#fff;--text:#142038;--muted:#64718b;--faint:#8490a6;--border:#dce3ee;--border-strong:#c5d0e0;--brand:#536ce8;--brand-2:#078fc8;--brand-soft:rgba(7,143,200,.07);--shadow:0 20px 60px rgba(28,45,80,.12);--shadow-soft:0 10px 30px rgba(28,45,80,.08);--ring:0 0 0 3px rgba(7,143,200,.10)}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}} body{{margin:0;background:radial-gradient(circle at 76% -12%,rgba(70,199,255,.10),transparent 30%),radial-gradient(circle at 12% 16%,rgba(117,139,255,.055),transparent 25%),linear-gradient(180deg,var(--bg-2),var(--bg) 28%);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:.005em}}
a{{color:inherit;text-decoration:none}} button,input,select,textarea{{font:inherit}} code,pre{{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace}} ::selection{{background:rgba(124,156,255,.32)}}
.app-shell{{min-height:100vh}} .sidebar{{position:fixed;inset:0 auto 0 0;width:var(--sidebar);padding:14px 12px;background:linear-gradient(180deg,color-mix(in srgb,var(--surface) 97%,transparent),color-mix(in srgb,var(--bg) 94%,transparent));border-right:1px solid color-mix(in srgb,var(--border) 88%,transparent);backdrop-filter:blur(22px);z-index:30;overflow:auto;scrollbar-width:thin;box-shadow:18px 0 50px rgba(0,0,0,.11)}}
.brand{{display:flex;align-items:center;gap:12px;padding:8px 9px 19px;margin-bottom:2px;border-bottom:1px solid color-mix(in srgb,var(--border) 58%,transparent)}} .brand-mark{{position:relative;width:38px;height:38px;border-radius:12px;display:grid;place-items:center;font-weight:950;background:radial-gradient(circle at 50% 50%,rgba(70,199,255,.18) 0 14%,transparent 15%),linear-gradient(145deg,rgba(117,139,255,.22),rgba(70,199,255,.08));color:var(--brand-2);border:1px solid rgba(70,199,255,.32);box-shadow:inset 0 0 0 4px rgba(70,199,255,.025),0 10px 28px rgba(0,0,0,.22)}} .brand-mark::before{{content:'';position:absolute;inset:7px;border:1px solid rgba(70,199,255,.42);border-radius:50%}} .brand-mark::after{{content:'';position:absolute;width:14px;height:1px;background:var(--brand-2);transform:rotate(-28deg);transform-origin:left center;left:19px;top:19px;box-shadow:0 0 8px rgba(70,199,255,.55)}} .brand-copy strong{{display:block;font-size:14px}} .brand-copy small{{color:var(--muted);font-size:11px}}
.nav-group,.advanced-nav{{margin:6px 0;border:1px solid transparent;border-radius:13px;background:transparent;overflow:hidden}} .nav-group[open],.advanced-nav[open]{{background:color-mix(in srgb,var(--surface-2) 68%,transparent);border-color:color-mix(in srgb,var(--border) 78%,transparent)}} .nav-group>summary,.advanced-nav>summary{{display:grid;grid-template-columns:32px minmax(0,1fr) 16px;align-items:center;gap:9px;padding:9px 10px;color:var(--muted);list-style:none;transition:.16s ease}} .nav-group>summary::-webkit-details-marker,.advanced-nav>summary::-webkit-details-marker{{display:none}} .nav-group>summary:hover,.advanced-nav>summary:hover{{color:var(--text);background:var(--surface-2)}} .nav-group[open]>summary,.advanced-nav[open]>summary{{color:var(--text)}} .nav-group>summary b,.advanced-nav>summary b{{font-size:11px;color:var(--faint);transition:.18s}} .nav-group[open]>summary b,.advanced-nav[open]>summary b{{transform:rotate(180deg)}} .nav-group-icon{{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:var(--surface);border:1px solid var(--border);font-size:9px;font-weight:900;color:var(--brand-2);letter-spacing:.03em}} .nav-group-copy{{min-width:0}} .nav-group-copy strong,.nav-group-copy small{{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .nav-group-copy strong{{font-size:11px;letter-spacing:.02em}} .nav-group-copy small{{font-size:9px;color:var(--faint);margin-top:1px}} .nav-items{{padding:0 6px 7px}} .nav-item{{display:flex;align-items:center;gap:9px;padding:7px 8px;margin:2px 0;border-radius:9px;color:var(--muted);font-size:12px;font-weight:650;transition:.16s ease}} .nav-item:hover{{color:var(--text);background:var(--surface)}} .nav-item.active{{color:var(--text);background:linear-gradient(90deg,rgba(124,156,255,.2),rgba(96,212,255,.05));box-shadow:inset 2px 0 var(--brand),0 0 0 1px rgba(124,156,255,.08)}} .nav-icon{{width:24px;height:24px;display:grid;place-items:center;border:1px solid var(--border);border-radius:7px;font-size:8px;font-weight:900;background:var(--surface);color:var(--faint)}} .nav-item.active .nav-icon{{border-color:rgba(124,156,255,.48);color:var(--brand-2);background:rgba(124,156,255,.08)}} .nav-text{{min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .advanced-label{{padding:8px 8px 4px;color:var(--faint);font-size:8px;font-weight:850;text-transform:uppercase;letter-spacing:.14em}} .advanced-group+.advanced-group{{border-top:1px solid var(--border);margin-top:6px;padding-top:4px}}
.sidebar-footer{{border-top:1px solid var(--border);padding:15px 9px 5px}} .user-card{{display:flex;align-items:center;gap:10px}} .avatar{{width:31px;height:31px;border-radius:9px;background:var(--surface-3);border:1px solid var(--border);display:grid;place-items:center;font-weight:800;color:var(--brand-2)}} .user-meta{{min-width:0;flex:1}} .user-meta strong,.user-meta small{{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}} .user-meta small{{color:var(--muted);text-transform:capitalize}}
.main-shell{{margin-left:var(--sidebar);min-height:100vh}} .topbar{{position:sticky;top:0;z-index:20;height:68px;padding:0 30px;display:flex;align-items:center;gap:14px;background:color-mix(in srgb,var(--bg) 78%,transparent);border-bottom:1px solid color-mix(in srgb,var(--border) 80%,transparent);backdrop-filter:blur(22px);box-shadow:0 8px 30px rgba(0,0,0,.08)}} .mobile-toggle{{display:none}} .global-search{{position:relative;width:min(580px,52vw)}} .global-search input{{width:100%;padding:10px 92px 10px 38px}} .search-icon{{position:absolute;left:13px;top:9px;color:var(--faint)}} .shortcut{{position:absolute;right:9px;top:8px;padding:2px 7px;border:1px solid var(--border);border-radius:6px;color:var(--faint);font-size:11px;background:var(--surface)}} .top-actions{{margin-left:auto;display:flex;align-items:center;gap:8px}}
.content{{max-width:1720px;margin:0 auto;padding:30px 34px 64px}} .page-header{{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:22px}} h1{{margin:0;font-size:28px;line-height:1.2;letter-spacing:-.035em}} h2{{margin:30px 0 12px;font-size:18px;letter-spacing:-.02em}} h3{{margin:0 0 12px;font-size:14px}} .eyebrow{{color:var(--brand-2);font-size:11px;font-weight:850;text-transform:uppercase;letter-spacing:.13em;margin-bottom:5px}} .page-subtitle{{margin:7px 0 0;color:var(--muted);max-width:780px}} .page-actions{{display:flex;gap:8px;flex-wrap:wrap}}
button,.button{{border:1px solid transparent;border-radius:9px;background:linear-gradient(135deg,var(--brand),#6685f3);color:#071020;padding:8px 12px;font-weight:760;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:36px;transition:.15s ease}} button:hover,.button:hover{{transform:translateY(-1px);filter:brightness(1.06)}} button.secondary,.button.secondary{{background:var(--surface-2);color:var(--text);border-color:var(--border)}} button.ghost,.button.ghost{{background:transparent;color:var(--muted);border-color:var(--border)}} button.danger,.button.danger{{background:rgba(255,100,124,.14);color:var(--danger);border-color:rgba(255,100,124,.3)}} .icon-button{{width:36px;padding:0}}
input,select,textarea{{background:var(--surface-2);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:9px 10px;outline:none;transition:.15s}} input:focus,select:focus,textarea:focus{{border-color:var(--brand);box-shadow:0 0 0 3px rgba(124,156,255,.12)}} textarea{{width:100%;min-height:92px;resize:vertical}} label{{color:var(--muted);font-size:12px;font-weight:650}}
.metrics-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}} .metric-card{{position:relative;min-height:126px;padding:16px;background:linear-gradient(145deg,var(--surface),color-mix(in srgb,var(--surface-2) 80%,transparent));border:1px solid var(--border);border-radius:14px;box-shadow:0 1px 0 rgba(255,255,255,.025);transition:.17s ease}} a.metric-card:hover{{transform:translateY(-2px);border-color:var(--border-strong);box-shadow:var(--shadow)}} .metric-top{{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;font-weight:700}} .metric-spark{{width:28px;height:7px;border-radius:99px;background:currentColor;opacity:.8}} .metric-value{{font-size:30px;font-weight:820;letter-spacing:-.045em;margin-top:14px}} .metric-detail{{color:var(--faint);font-size:11px;margin-top:5px}} .metric-arrow{{position:absolute;right:15px;bottom:13px;color:var(--faint)}}
.card{{background:linear-gradient(155deg,var(--surface-raised),var(--surface));border:1px solid var(--border);border-radius:16px;padding:17px;box-shadow:var(--shadow-soft)}} .panel{{background:linear-gradient(180deg,color-mix(in srgb,var(--surface-raised) 86%,transparent),var(--surface));border:1px solid var(--border);border-radius:16px;overflow:hidden;box-shadow:0 10px 34px rgba(0,0,0,.10)}} .panel-head{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 17px;border-bottom:1px solid var(--border)}} .panel-head h2,.panel-head h3{{margin:0}} .panel-body{{padding:16px}} .muted{{color:var(--muted)}} .faint{{color:var(--faint)}} .small{{font-size:12px}} .strong{{font-weight:750}} .mono{{font-family:"SFMono-Regular",Consolas,monospace}} .stack{{display:grid;gap:12px}} .two-col{{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(300px,.8fr);gap:16px}} .three-col{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}} .sticky-rail{{position:sticky;top:82px;align-self:start}}
.table-wrap{{overflow:auto;border:1px solid var(--border);border-radius:13px;background:var(--surface)}} table{{width:100%;border-collapse:separate;border-spacing:0;min-width:760px}} th{{position:sticky;top:0;z-index:2;background:var(--surface-2);color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.09em;font-weight:850}} th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);vertical-align:middle}} tbody tr:last-child td{{border-bottom:0}} tbody tr:hover td{{background:color-mix(in srgb,var(--surface-2) 68%,transparent)}} td code{{color:color-mix(in srgb,var(--brand-2) 82%,var(--text));word-break:break-all}} .row-link{{font-weight:750}} .filters{{display:flex;gap:9px;align-items:end;flex-wrap:wrap;padding:12px;margin:0 0 14px;background:var(--surface);border:1px solid var(--border);border-radius:13px}} .filter-panel{{margin:0 0 16px;border:1px solid var(--border);border-radius:15px;background:linear-gradient(145deg,var(--surface),color-mix(in srgb,var(--surface-2) 74%,transparent));overflow:hidden}} .filter-head{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid var(--border)}} .filter-head>div{{display:flex;align-items:center;gap:10px}} .filter-head strong,.filter-head small{{display:block}} .filter-head small{{color:var(--faint);font-size:10px;margin-top:1px}} .filter-icon{{width:29px;height:29px;display:grid;place-items:center;border-radius:9px;background:rgba(124,156,255,.1);border:1px solid rgba(124,156,255,.2);color:var(--brand-2);font-weight:900}} .filter-result{{color:var(--muted);font-size:11px;font-weight:750}} .filter-panel .filters{{margin:0;border:0;border-radius:0;background:transparent;padding:13px 14px}} .filter-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));align-items:end}} .filter-wide{{grid-column:span 2}} .filter-grid label{{display:grid;gap:5px;min-width:0}} .filter-grid input,.filter-grid select{{width:100%;min-width:0}} .filter-actions{{display:flex;gap:7px;align-items:center}} .filter-summary{{display:flex;align-items:center;gap:7px;flex-wrap:wrap;padding:8px 14px 11px;border-top:1px solid color-mix(in srgb,var(--border) 74%,transparent);background:color-mix(in srgb,var(--surface-2) 55%,transparent)}} .filter-chip{{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:999px;padding:4px 8px;background:var(--surface);font-size:10px}} .filter-chip small{{color:var(--faint);text-transform:uppercase;font-size:8px;font-weight:850;letter-spacing:.07em}} .filter-chip strong{{font-size:10px;font-weight:750}} .filter-empty{{color:var(--faint);font-size:10px}} form.inline{{display:inline}}
.pill{{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:999px;font-size:10px;font-weight:830;text-transform:uppercase;letter-spacing:.045em;border:1px solid currentColor;white-space:nowrap}} .pill-dot{{width:5px;height:5px;border-radius:50%;background:currentColor}} .pill-danger{{color:var(--danger);background:rgba(255,100,124,.09)}} .pill-orange{{color:var(--orange);background:rgba(255,152,89,.08)}} .pill-amber{{color:var(--amber);background:rgba(245,196,81,.08)}} .pill-success{{color:var(--success);background:rgba(85,217,138,.08)}} .pill-info,.pill-blue{{color:var(--info);background:rgba(97,184,255,.08)}} .pill-purple{{color:var(--purple);background:rgba(189,140,255,.08)}} .pill-neutral{{color:var(--muted);background:rgba(141,154,184,.07)}} .tag,.badge{{display:inline-flex;padding:3px 8px;border:1px solid var(--border);border-radius:999px;color:var(--muted);background:var(--surface-2);font-size:11px;margin:2px}}
.tone-danger{{color:var(--danger)!important}} .tone-orange{{color:var(--orange)!important}} .tone-amber{{color:var(--amber)!important}} .tone-success{{color:var(--success)!important}} .tone-info,.tone-blue{{color:var(--info)!important}} .tone-purple{{color:var(--purple)!important}} .sev{{font-weight:800}} .critical{{color:var(--danger)}} .high{{color:var(--orange)}} .medium{{color:var(--amber)}} .low{{color:var(--success)}} .info{{color:var(--info)}}
.queue-card{{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:12px;padding:13px;border-bottom:1px solid var(--border);align-items:start}} .queue-card:last-child{{border-bottom:0}} .risk-badge{{width:42px;height:42px;border-radius:11px;display:grid;place-items:center;background:var(--surface-2);border:1px solid var(--border);font-weight:850;font-size:16px}} .queue-main strong{{display:block;margin-bottom:3px}} .queue-meta{{display:flex;align-items:center;gap:7px;flex-wrap:wrap;color:var(--faint);font-size:11px;margin-top:7px}} .queue-action{{font-size:11px;color:var(--brand-2);white-space:nowrap}}
.pipeline{{display:grid;grid-template-columns:repeat(6,1fr);gap:8px}} .pipeline-step{{padding:12px;background:var(--surface-2);border:1px solid var(--border);border-radius:11px}} .pipeline-step span{{display:block;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.07em}} .pipeline-step strong{{display:block;font-size:22px;margin-top:4px}} .evidence-feed{{display:grid;gap:8px}} .evidence-item{{display:grid;grid-template-columns:36px 1fr;gap:10px;padding:10px;background:var(--surface-2);border:1px solid var(--border);border-radius:11px}} .evidence-icon{{width:36px;height:36px;border-radius:9px;display:grid;place-items:center;background:var(--surface-3);font-size:10px;font-weight:850;color:var(--brand-2)}} .audit-document{{margin-top:8px;border:1px solid var(--border);border-radius:10px;background:rgba(255,255,255,.015);overflow:hidden}} .audit-document summary{{display:flex;justify-content:space-between;gap:12px;padding:9px 11px;font-size:12px}} .audit-document pre{{margin:0;border:0;border-top:1px solid var(--border);border-radius:0;max-height:420px}}
.risk-meter{{padding:15px;border-radius:13px;background:var(--surface-2);border:1px solid var(--border)}} .risk-score{{font-size:36px;font-weight:900;letter-spacing:-.06em}} .risk-track{{height:7px;background:var(--border);border-radius:99px;overflow:hidden;margin-top:9px}} .risk-track span{{display:block;height:100%;background:currentColor;border-radius:inherit}} .risk-scale{{display:flex;justify-content:space-between;color:var(--faint);font-size:10px;margin-top:6px}} .confidence{{display:flex;align-items:center;gap:9px;min-width:115px}} .confidence>span{{width:36px;font-weight:750}} .confidence>div{{height:5px;flex:1;background:var(--border);border-radius:99px;overflow:hidden}} .confidence i{{display:block;height:100%;background:currentColor}}
.workflow-steps{{display:flex;align-items:flex-start;overflow:auto;padding:4px 0 10px}} .flow-step{{position:relative;flex:1;min-width:90px;text-align:center;color:var(--faint)}} .flow-step:not(:last-child)::after{{content:'';position:absolute;top:13px;left:58%;right:-42%;height:2px;background:var(--border)}} .flow-step span{{position:relative;z-index:1;width:28px;height:28px;border-radius:50%;display:grid;place-items:center;margin:auto;background:var(--surface-3);border:2px solid var(--border);font-size:10px;font-weight:800}} .flow-step small{{display:block;margin-top:6px;text-transform:capitalize}} .flow-step.done span{{border-color:var(--success);color:var(--success)}} .flow-step.done:not(:last-child)::after{{background:var(--success)}} .flow-step.current span{{border-color:var(--brand);color:var(--brand);box-shadow:0 0 0 4px rgba(124,156,255,.1)}}
.kv{{display:grid;grid-template-columns:150px minmax(0,1fr);gap:9px 14px}} .kv strong{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}} .section-tabs{{display:flex;gap:6px;overflow:auto;border-bottom:1px solid var(--border);margin:22px 0 14px}} .section-tabs a{{padding:8px 10px;color:var(--muted);border-bottom:2px solid transparent;white-space:nowrap}} .section-tabs a:hover{{color:var(--text);border-color:var(--brand)}} details{{border:1px solid var(--border);border-radius:11px;background:var(--surface);overflow:hidden}} summary{{cursor:pointer;padding:12px 14px;font-weight:750}} details>pre,details>.details-body{{border-top:1px solid var(--border);margin:0;padding:14px}}
pre{{white-space:pre-wrap;word-break:break-word;color:#cbd7f5;background:#080d18;border:1px solid var(--border);border-radius:11px;padding:14px;max-height:65vh;overflow:auto}} html[data-theme='light'] pre{{color:#213153;background:#f4f7fc}} pre.diff span{{display:block;min-height:1.4em;padding:0 8px}} .diff-add{{color:#9ce8b7;background:rgba(85,217,138,.08)}} .diff-del{{color:#ff9bad;background:rgba(255,100,124,.08)}} .diff-hunk{{color:#8bc9ff;background:rgba(97,184,255,.08)}} .diff-meta{{color:#c8a8ff}}
.empty-state{{min-height:150px;display:grid;place-items:center;align-content:center;gap:7px;color:var(--muted);text-align:center;padding:24px}} .empty-icon{{width:38px;height:38px;display:grid;place-items:center;border:1px solid var(--border);border-radius:12px;color:var(--brand)}} .callout{{padding:13px 14px;border-radius:11px;background:rgba(124,156,255,.08);border:1px solid rgba(124,156,255,.22)}} .callout strong{{display:block;margin-bottom:3px}} .timeline{{display:grid;gap:0}} .timeline-item{{position:relative;padding:0 0 17px 24px}} .timeline-item::before{{content:'';position:absolute;left:5px;top:5px;width:8px;height:8px;border-radius:50%;background:var(--brand)}} .timeline-item:not(:last-child)::after{{content:'';position:absolute;left:8px;top:16px;bottom:0;width:1px;background:var(--border)}}

.breadcrumbs{{display:flex;align-items:center;gap:8px;color:var(--faint);font-size:11px;margin:0 0 12px}}.breadcrumbs a:hover{{color:var(--brand-2)}}.breadcrumbs i{{font-style:normal;color:var(--border-strong)}}
.view-context{{display:grid;min-width:135px;line-height:1.15}}.view-context small{{color:var(--faint);font-size:9px;text-transform:uppercase;letter-spacing:.12em}}.view-context strong{{font-size:12px;white-space:nowrap}}.focus-chip{{display:flex;align-items:center;gap:7px;border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:5px 9px;max-width:220px}}.focus-chip small{{color:var(--faint);text-transform:uppercase;font-size:8px;font-weight:800}}.focus-chip strong{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px}}

.attention-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}.attention-item{{display:grid;grid-template-columns:auto minmax(0,1fr) auto auto;gap:10px;align-items:center;padding:13px 14px;border:1px solid var(--border);border-radius:13px;background:var(--surface);transition:.15s}}.attention-item:hover{{border-color:var(--border-strong);transform:translateY(-1px)}}.attention-item div{{min-width:0}}.attention-item strong,.attention-item small{{display:block}}.attention-item small{{color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.attention-item b{{font-size:22px}}.attention-item i{{font-style:normal;color:var(--faint)}}.attention-icon{{font-size:10px}}
.command-grid{{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(310px,.8fr);gap:16px}}.decision-stack{{display:grid;gap:10px}}.decision-summary{{display:grid;grid-template-columns:1fr auto;gap:18px;align-items:center;padding:18px;border:1px solid var(--border);border-radius:15px;background:linear-gradient(140deg,var(--surface),var(--surface-2))}}.decision-summary h2{{margin:3px 0 6px;font-size:20px}}.decision-summary p{{margin:0;color:var(--muted)}}.decision-number{{font-size:42px;font-weight:900;letter-spacing:-.06em}}
.command-v2-grid{{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.75fr);gap:16px;align-items:start}}.command-decision-list{{display:grid;gap:9px}}.command-decision{{display:grid;grid-template-columns:38px minmax(0,1fr) 64px 18px;gap:12px;align-items:center;padding:14px 15px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(145deg,var(--surface-raised),var(--surface));transition:.16s ease}}.command-decision:hover{{transform:translateY(-1px);border-color:color-mix(in srgb,var(--brand-2) 28%,var(--border));box-shadow:var(--shadow-soft)}}.decision-rank{{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;border:1px solid var(--border);background:var(--surface-2);color:var(--faint);font-size:10px;font-weight:900}}.decision-copy{{min-width:0}}.decision-copy small,.decision-copy strong,.decision-copy span,.decision-copy em{{display:block}}.decision-copy small{{color:var(--brand-2);font-size:9px;font-weight:850;text-transform:uppercase;letter-spacing:.12em}}.decision-copy strong{{margin-top:2px;font-size:13px}}.decision-copy span{{margin-top:2px;color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.decision-copy em{{margin-top:4px;color:var(--faint);font-size:9px;font-style:normal;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.decision-score{{text-align:right}}.decision-score b,.decision-score small{{display:block}}.decision-score b{{font-size:22px;line-height:1;letter-spacing:-.04em}}.decision-score small{{margin-top:3px;color:var(--faint);font-size:8px;text-transform:uppercase;letter-spacing:.08em}}.command-primary-action{{padding:18px;border:1px solid color-mix(in srgb,var(--brand-2) 25%,var(--border));border-radius:16px;background:radial-gradient(circle at 100% 0,rgba(70,199,255,.12),transparent 40%),linear-gradient(145deg,var(--surface-raised),var(--surface));box-shadow:var(--shadow-soft)}}.command-primary-action small{{display:block;color:var(--brand-2);font-weight:850;text-transform:uppercase;letter-spacing:.12em;font-size:9px}}.command-primary-action h2{{margin:6px 0 6px;font-size:20px}}.command-primary-action p{{margin:0 0 14px;color:var(--muted)}}.command-pulse{{display:grid;gap:0}}.pulse-row{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;padding:11px 0;border-bottom:1px solid var(--border)}}.pulse-row:last-child{{border-bottom:0}}.pulse-row span,.pulse-row small{{display:block}}.pulse-row span{{font-weight:700}}.pulse-row small{{color:var(--faint);font-size:10px}}.pulse-row b{{align-self:center;font-size:12px}}.change-stream{{display:grid;gap:8px}}.change-event{{display:grid;grid-template-columns:9px minmax(0,1fr) auto;gap:10px;align-items:start;padding:11px 12px;border:1px solid var(--border);border-radius:12px;background:var(--surface)}}.change-event>i{{width:8px;height:8px;border-radius:50%;margin-top:5px;background:currentColor;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 10%,transparent)}}.change-event strong,.change-event span,.change-event small{{display:block}}.change-event span{{color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}}.change-event small{{color:var(--faint);font-size:9px;margin-top:2px}}.change-event b{{font-size:11px}}.command-kpi-row{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 16px}}
.candidate-card{{position:relative;display:grid;grid-template-columns:4px minmax(0,1fr) auto;border-bottom:1px solid var(--border);background:var(--surface)}}.candidate-card:last-child{{border-bottom:0}}.candidate-accent{{background:currentColor}}.candidate-main{{padding:15px 16px}}.candidate-heading{{display:flex;justify-content:space-between;gap:18px}}.candidate-heading h3{{font-size:15px;margin:6px 0 3px}}.candidate-kicker{{display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:var(--faint);font-size:11px}}.candidate-open{{display:grid;place-items:center;padding:15px;color:var(--brand-2);font-size:11px;border-left:1px solid var(--border)}}.investigation-score{{text-align:right;min-width:70px}}.investigation-score span{{display:block;color:var(--faint);font-size:9px;text-transform:uppercase;letter-spacing:.08em}}.investigation-score strong{{font-size:27px}}.score-triad{{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:7px;margin:12px 0}}.score-triad>div{{display:flex;justify-content:space-between;align-items:center;padding:7px 9px;background:var(--surface-2);border:1px solid var(--border);border-radius:9px}}.score-triad span{{color:var(--faint);font-size:9px;text-transform:uppercase}}.candidate-reasoning{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:10px}}.candidate-reasoning>div{{padding:10px;background:color-mix(in srgb,var(--surface-2) 72%,transparent);border-radius:10px}}.candidate-reasoning strong{{font-size:10px;text-transform:uppercase;color:var(--muted)}}.candidate-reasoning ul{{margin:6px 0 0;padding-left:16px;color:var(--muted);font-size:11px}}.next-step{{margin-top:10px;padding:9px 11px;border-left:2px solid var(--brand);background:rgba(124,156,255,.06)}}.next-step span{{font-size:9px;text-transform:uppercase;color:var(--brand-2);font-weight:800}}.next-step p{{margin:2px 0 0;color:var(--muted);font-size:11px}}
.segmented{{display:flex;gap:4px;padding:4px;border:1px solid var(--border);background:var(--surface);border-radius:11px;overflow:auto}}.pager{{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px;padding:14px 16px;border-top:1px solid var(--border)}}.pager>:last-child{{justify-self:end}}.pager>span{{color:var(--muted);font-size:12px;text-align:center}}.segmented a{{padding:7px 10px;border-radius:8px;color:var(--muted);white-space:nowrap;font-size:11px;font-weight:700}}.segmented a.active{{background:var(--surface-3);color:var(--text);box-shadow:inset 0 0 0 1px var(--border)}}.queue-health{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}.queue-health div{{padding:11px;background:var(--surface-2);border:1px solid var(--border);border-radius:10px}}.queue-health span{{display:block;color:var(--faint);font-size:9px;text-transform:uppercase}}.queue-health strong{{font-size:22px}}
.coverage-strip{{display:grid;grid-template-columns:repeat(4,1fr);gap:0}}.coverage-strip a{{padding:14px;border-right:1px solid var(--border)}}.coverage-strip a:last-child{{border-right:0}}.coverage-strip span,.coverage-strip strong{{display:block}}.coverage-strip span{{color:var(--faint);font-size:10px}}.coverage-strip strong{{font-size:20px;margin-top:3px}}
body.compact .content{{padding-top:18px}}body.compact th,body.compact td{{padding:7px 9px}}body.compact .candidate-main{{padding:10px 12px}}body.compact .queue-card{{padding:9px 11px}}body.focus-mode .sidebar{{transform:translateX(-100%)}}body.focus-mode .main-shell{{margin-left:0}}body.focus-mode .content{{max-width:1500px}}
.graph-wrap{{height:72vh;background:#080d18;border:1px solid var(--border);border-radius:14px;overflow:hidden;position:relative}} #graphSvg{{width:100%;height:100%;cursor:grab}} #graphSvg:active{{cursor:grabbing}} .graph-panel{{position:absolute;right:12px;top:12px;width:min(370px,42%);max-height:calc(100% - 24px);overflow:auto;background:color-mix(in srgb,var(--surface) 94%,transparent);border:1px solid var(--border);border-radius:12px;padding:13px;box-shadow:var(--shadow)}} .node{{cursor:pointer}} .edge{{stroke:#52698e;stroke-opacity:.5}} .node-label{{font-size:11px;pointer-events:none;fill:#eef2ff}}
.login-mode .sidebar,.login-mode .topbar{{display:none}}.login-mode .main-shell{{margin-left:0}}.login-mode .content{{max-width:520px;padding-top:8vh}}
.command-palette{{position:fixed;inset:0;z-index:90;display:none;align-items:flex-start;justify-content:center;padding-top:10vh;background:rgba(2,6,14,.62);backdrop-filter:blur(8px)}} .command-palette.open{{display:flex}} .command-box{{width:min(720px,92vw);background:var(--surface);border:1px solid var(--border-strong);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}} .command-box input{{width:100%;border:0;border-bottom:1px solid var(--border);border-radius:0;padding:17px 18px;background:var(--surface);font-size:16px;outline:none}} .command-list{{max-height:55vh;overflow:auto;padding:8px}} .command-item{{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:10px;color:var(--muted)}} .command-item:hover,.command-item:focus{{background:var(--surface-2);color:var(--text)}} .command-key{{margin-left:auto;color:var(--faint);font-size:10px}} .command-copy strong,.command-copy small{{display:block}} .command-copy small{{color:var(--faint)}}

/* Recon UI v1 — visual system */
body::before{{content:'';position:fixed;inset:0;pointer-events:none;opacity:.16;background-image:linear-gradient(rgba(255,255,255,.012) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.012) 1px,transparent 1px);background-size:28px 28px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.55),transparent 68%);z-index:-1}}
.sidebar::-webkit-scrollbar,.command-list::-webkit-scrollbar,.table-wrap::-webkit-scrollbar{{width:8px;height:8px}}.sidebar::-webkit-scrollbar-thumb,.command-list::-webkit-scrollbar-thumb,.table-wrap::-webkit-scrollbar-thumb{{background:var(--border-strong);border-radius:99px}}
.brand-copy strong{{font-size:13px;letter-spacing:-.01em}}.brand-copy small{{font-size:9px;text-transform:uppercase;letter-spacing:.09em}}.nav-group,.advanced-nav{{border-radius:12px}}.nav-group>summary,.advanced-nav>summary{{min-height:45px}}.nav-item{{min-height:36px;padding:7px 9px}}.nav-item.active{{background:linear-gradient(90deg,rgba(70,199,255,.13),rgba(117,139,255,.06));box-shadow:inset 2px 0 var(--brand-2),inset 0 0 0 1px rgba(70,199,255,.08)}}
.global-search input{{height:40px;background:color-mix(in srgb,var(--surface) 88%,transparent);border-color:color-mix(in srgb,var(--border) 84%,transparent);box-shadow:inset 0 1px 0 rgba(255,255,255,.018)}}.global-search input:focus{{background:var(--surface);box-shadow:var(--ring)}}.shortcut{{top:9px;background:var(--surface-2);border-color:var(--border);font-size:10px}}
.page-header{{margin-bottom:24px}}h1{{font-size:30px;font-weight:820}}.page-subtitle{{font-size:13px;line-height:1.7}}.page-actions button,.page-actions .button{{box-shadow:0 7px 18px rgba(0,0,0,.14)}}
button,.button{{border-radius:10px}}button:not(.secondary):not(.ghost):not(.danger),.button:not(.secondary):not(.ghost):not(.danger){{background:linear-gradient(135deg,#79a1ff,var(--brand-2));box-shadow:0 7px 20px rgba(70,199,255,.13)}}button.secondary,.button.secondary{{background:linear-gradient(180deg,var(--surface-2),color-mix(in srgb,var(--surface) 78%,var(--surface-2)));box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}}
.metric-card{{border-radius:16px;min-height:132px;background:linear-gradient(145deg,var(--surface-raised),color-mix(in srgb,var(--surface-2) 82%,transparent));overflow:hidden}}.metric-card::before{{content:'';position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,currentColor,transparent);opacity:.42}}.metric-card:hover{{border-color:color-mix(in srgb,var(--brand-2) 28%,var(--border));box-shadow:0 18px 45px rgba(0,0,0,.20)}}
.panel-head{{min-height:52px;padding:15px 18px;background:linear-gradient(180deg,rgba(255,255,255,.018),transparent)}}.panel-head h3{{font-size:13px;letter-spacing:.01em}}.table-wrap{{border-radius:15px;box-shadow:0 8px 26px rgba(0,0,0,.08)}}th{{height:42px;background:color-mix(in srgb,var(--surface-2) 96%,transparent)}}tbody tr{{transition:.12s ease}}tbody tr:hover td{{background:rgba(70,199,255,.035)}}
.pill{{box-shadow:inset 0 0 0 1px rgba(255,255,255,.025)}}.empty-state{{border-radius:14px;background:linear-gradient(145deg,rgba(255,255,255,.01),transparent)}}
.attention-grid{{gap:12px}}.attention-item{{position:relative;min-height:86px;border-radius:15px;background:linear-gradient(145deg,var(--surface-raised),var(--surface));box-shadow:0 8px 28px rgba(0,0,0,.10);overflow:hidden}}.attention-item::after{{content:'';position:absolute;inset:auto 0 0 0;height:2px;background:linear-gradient(90deg,currentColor,transparent);opacity:.2}}.attention-item:hover{{border-color:color-mix(in srgb,var(--brand-2) 24%,var(--border));transform:translateY(-2px);box-shadow:0 16px 34px rgba(0,0,0,.16)}}.attention-item b{{font-size:25px;letter-spacing:-.04em}}
.queue-card{{transition:.15s ease}}.queue-card:hover{{background:rgba(70,199,255,.035)}}.candidate-card{{transition:.14s ease}}.candidate-card:hover{{background:color-mix(in srgb,var(--surface-2) 50%,var(--surface))}}.candidate-open{{transition:.14s}}.candidate-card:hover .candidate-open{{background:rgba(70,199,255,.045)}}
.command-box{{border-radius:18px;background:linear-gradient(180deg,var(--surface-raised),var(--surface));box-shadow:0 35px 100px rgba(0,0,0,.52)}}
.workspace-hero{{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:22px;align-items:end;padding:22px 24px;margin:0 0 16px;border:1px solid var(--border);border-radius:18px;background:radial-gradient(circle at 88% 10%,rgba(70,199,255,.13),transparent 32%),radial-gradient(circle at 15% 115%,rgba(117,139,255,.11),transparent 34%),linear-gradient(145deg,var(--surface-raised),var(--surface));box-shadow:var(--shadow-soft);overflow:hidden}}.workspace-hero::after{{content:'';position:absolute;right:-40px;top:-62px;width:220px;height:220px;border:1px solid rgba(70,199,255,.10);border-radius:50%;box-shadow:0 0 0 35px rgba(70,199,255,.025),0 0 0 70px rgba(117,139,255,.018);pointer-events:none}}.workspace-hero-copy{{position:relative;z-index:1}}.workspace-hero-copy small{{display:block;color:var(--brand-2);font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.14em;margin-bottom:7px}}.workspace-hero-copy strong{{display:block;font-size:19px;letter-spacing:-.025em;margin-bottom:5px}}.workspace-hero-copy p{{margin:0;max-width:760px;color:var(--muted)}}.workspace-hero-status{{position:relative;z-index:1;display:flex;align-items:center;gap:9px;padding:9px 12px;border:1px solid var(--border);border-radius:999px;background:color-mix(in srgb,var(--surface) 82%,transparent);white-space:nowrap}}.status-dot{{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 4px rgba(80,216,144,.08),0 0 14px rgba(80,216,144,.38)}}.workspace-hero-status span{{color:var(--muted);font-size:11px}}.workspace-hero-status strong{{font-size:11px}}
.workspace-strip{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:16px 0}}.workspace-tile{{display:flex;align-items:center;gap:11px;padding:12px 13px;border:1px solid var(--border);border-radius:13px;background:color-mix(in srgb,var(--surface) 90%,transparent);transition:.15s ease}}.workspace-tile:hover{{transform:translateY(-1px);background:var(--surface-raised);border-color:var(--border-strong)}}.workspace-tile-icon{{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;background:var(--brand-soft);border:1px solid rgba(70,199,255,.15);color:var(--brand-2);font-size:10px;font-weight:900}}.workspace-tile strong,.workspace-tile small{{display:block}}.workspace-tile strong{{font-size:11px}}.workspace-tile small{{font-size:9px;color:var(--faint);margin-top:1px}}
.section-label{{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:22px 0 10px}}.section-label>div strong{{display:block;font-size:13px}}.section-label>div small{{display:block;color:var(--faint);font-size:10px;margin-top:2px}}
.nav-item[data-primary-workspace='1']{{display:grid;grid-template-columns:34px minmax(0,1fr) 18px;align-items:center;gap:9px;min-height:58px;margin:7px 0;padding:10px 11px;border:1px solid transparent;border-radius:13px;color:var(--muted);transition:.15s ease}}.nav-item[data-primary-workspace='1']:hover{{background:var(--surface-2);color:var(--text);border-color:var(--border)}}.nav-item[data-primary-workspace='1'].active{{color:var(--text);background:linear-gradient(90deg,rgba(70,199,255,.13),rgba(117,139,255,.055));border-color:rgba(70,199,255,.16);box-shadow:inset 2px 0 var(--brand-2)}}.nav-item[data-primary-workspace='1'] .nav-group-copy strong,.nav-item[data-primary-workspace='1'] .nav-group-copy small{{display:block}}.nav-item[data-primary-workspace='1'] .nav-group-copy strong{{font-size:11px}}.nav-item[data-primary-workspace='1'] .nav-group-copy small{{font-size:9px;color:var(--faint);margin-top:2px}}.nav-item[data-primary-workspace='1']>b{{font-size:11px;color:var(--faint)}}
.quick-views{{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 13px}}.quick-view{{padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:color-mix(in srgb,var(--surface) 88%,transparent);font-size:10px;font-weight:780;color:var(--muted);transition:.12s ease}}.quick-view:hover{{color:var(--text);border-color:var(--border-strong)}}.quick-view.active{{color:var(--text);background:var(--brand-soft);border-color:rgba(70,199,255,.25)}}
.confidence-story{{margin-top:16px}}.confidence-story .panel-head>div h3{{margin:0}}.confidence-verdict{{display:flex;justify-content:space-between;gap:16px;align-items:center;padding:12px 14px;margin-bottom:13px;border:1px solid var(--border);border-radius:12px;background:var(--surface-2)}}.confidence-verdict strong,.confidence-verdict span{{display:block}}.confidence-verdict span{{color:var(--muted);font-size:10px}}.confidence-factors{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.confidence-factor{{padding:11px 12px;border:1px solid var(--border);border-radius:12px;background:color-mix(in srgb,var(--surface-2) 55%,transparent)}}.confidence-factor>div:first-child{{display:flex;justify-content:space-between;gap:12px;align-items:center}}.confidence-factor strong{{font-size:10px}}.confidence-factor span{{font-size:11px;font-weight:850}}.confidence-factor small{{display:block;color:var(--faint);font-size:9px;line-height:1.45;margin-top:7px}}.factor-track{{height:5px;margin-top:7px;border-radius:99px;background:var(--border);overflow:hidden}}.factor-track i{{display:block;height:100%;border-radius:inherit;background:currentColor}}
.noise-note{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;margin:0 0 13px;border:1px dashed var(--border-strong);border-radius:12px;background:color-mix(in srgb,var(--surface-2) 45%,transparent);color:var(--muted);font-size:10px}}
@media(max-width:820px){{.confidence-factors{{grid-template-columns:1fr}}.confidence-verdict{{align-items:flex-start;flex-direction:column}}}}
@media(max-width:1120px){{.workspace-strip{{grid-template-columns:1fr 1fr}}.workspace-hero{{grid-template-columns:1fr;align-items:start}}.workspace-hero-status{{justify-self:start}}}}
@media(max-width:820px){{.workspace-strip{{grid-template-columns:1fr}}.workspace-hero{{padding:18px}}}}
@media(max-width:1120px){{.attention-grid{{grid-template-columns:1fr 1fr}} .command-grid,.command-v2-grid{{grid-template-columns:1fr}} .command-kpi-row{{grid-template-columns:1fr 1fr}} .candidate-reasoning{{grid-template-columns:1fr}} .three-col{{grid-template-columns:1fr 1fr}} .two-col{{grid-template-columns:1fr}} .sticky-rail{{position:static}} .pipeline{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:820px){{.filter-grid{{grid-template-columns:1fr 1fr}} .attention-grid,.command-kpi-row{{grid-template-columns:1fr}} .command-decision{{grid-template-columns:34px minmax(0,1fr) 52px}} .command-decision>i{{display:none}} .score-triad{{grid-template-columns:1fr 1fr}} .view-context,.focus-chip,.primary-work{{display:none}} :root{{--sidebar:274px}} .sidebar{{transform:translateX(-100%);transition:.2s}} body.nav-open .sidebar{{transform:none;box-shadow:var(--shadow)}} .main-shell{{margin-left:0}} .mobile-toggle{{display:inline-flex}} .content{{padding:22px 16px 44px}} .topbar{{padding:0 15px}} .global-search{{width:100%}} .top-actions .user-mini{{display:none}} .page-header{{display:block}} .page-actions{{margin-top:14px}} .three-col{{grid-template-columns:1fr}} .pipeline{{grid-template-columns:repeat(2,1fr)}} .graph-panel{{position:static;width:auto;max-height:none;margin:10px}} .graph-wrap{{height:auto;min-height:620px}} .filter-actions{{grid-column:1/-1}}}}
</style></head><body class='{'login-mode' if login_mode else ''}'>
<div class='app-shell'><aside class='sidebar'><div class='brand'><div class='brand-mark' aria-label='Recon Monitor'>R</div><div class='brand-copy'><strong>Recon Monitor</strong><small>Decision Console · {APP_VERSION}</small></div></div>{''.join(nav)}{advanced_nav}{legacy_nav_contract}<div class='sidebar-footer'><div class='user-card'><div class='avatar'>{_esc((username or 'L')[:1].upper())}</div><div class='user-meta'><strong>{user}</strong><small>{user_role}</small></div><a href='/logout' title='Sign out' class='button ghost icon-button'>↪</a></div></div></aside>
<div class='main-shell'><header class='topbar'><button class='secondary icon-button mobile-toggle' id='navToggle' aria-label='Open navigation'>☰</button><div class='view-context'><small>{_esc(section_name)}</small><strong>{_esc(title)}</strong></div>{focus_chip}<form class='global-search' action='/search' method='get'><span class='search-icon'>⌕</span><input id='globalSearch' name='q' placeholder='Search assets, endpoints, candidates, evidence…' required><span class='shortcut'>⌘ K</span></form><div class='top-actions'><span class='workspace-hero-status' title='Local-first workspace'><span class='status-dot'></span><strong>Local</strong></span><a class='button secondary primary-work' href='/potential-findings'>Potential findings</a><button class='secondary icon-button' type='button' id='densityToggle' title='Toggle compact density'>≡</button><button class='secondary icon-button' type='button' id='focusToggle' title='Toggle focus mode'>◧</button><button class='secondary icon-button' type='button' id='themeToggle' title='Toggle theme'>◐</button></div></header>
<main class='content'>{body}</main></div></div>
<div class='command-palette' id='commandPalette' role='dialog' aria-modal='true' aria-label='Command palette'><div class='command-box'><input id='commandInput' placeholder='Type a command or search term…' autocomplete='off'><div class='command-list' id='commandList'>
<a class='command-item' data-command='search universal find endpoint asset case evidence' href='/search'><span class='nav-icon'>⌕</span><span class='command-copy'><strong>Universal search</strong><small>Search cases, candidates, endpoints and evidence</small></span><span class='command-key'>Enter</span></a>
<a class='command-item' data-command='command center home cockpit attention' href='/'><span class='nav-icon'>CC</span><span class='command-copy'><strong>Command center</strong><small>Four-step research workflow</small></span></a>
<a class='command-item' data-command='recon discover assets endpoints surface' href='/recon'><span class='nav-icon'>01</span><span class='command-copy'><strong>Recon</strong><small>Discover and search the attack surface</small></span></a>
<a class='command-item' data-command='analysis analyze findings signals evidence' href='/analysis'><span class='nav-icon'>02</span><span class='command-copy'><strong>Analysis</strong><small>Interpret collected findings</small></span></a>
<a class='command-item' data-command='potential findings probable bugs candidates review' href='/potential-findings'><span class='nav-icon'>03</span><span class='command-copy'><strong>Potential Findings</strong><small>Review probable security issues</small></span></a>
<a class='command-item' data-command='alerts changes new endpoint recheck target' href='/alerts'><span class='nav-icon'>04</span><span class='command-copy'><strong>Alerts</strong><small>See new and changed surface</small></span></a>
<a class='command-item' data-command='cases investigations open case' href='/cases'><span class='nav-icon'>CS</span><span class='command-copy'><strong>Reviewed cases</strong><small>Analyst-reviewed investigation workspace</small></span></a>
<a class='command-item' data-command='evidence gap missing evidence next action' href='/evidence-gaps'><span class='nav-icon'>EG</span><span class='command-copy'><strong>Evidence gaps</strong><small>See what is missing before validation</small></span></a>
<a class='command-item' data-command='autopilot next action investigation' href='/case-autopilot'><span class='nav-icon'>AP</span><span class='command-copy'><strong>Case Autopilot</strong><small>Human-controlled next-step guidance</small></span></a>
<a class='command-item' data-command='safe validation plan manual authorization' href='/safe-validation'><span class='nav-icon'>SV</span><span class='command-copy'><strong>Safe Validation</strong><small>Bounded validation planning and review</small></span></a>
<a class='command-item' data-command='coverage blind spots recon confidence' href='/recon-coverage'><span class='nav-icon'>CV</span><span class='command-copy'><strong>Recon coverage</strong><small>Find blind spots before drawing conclusions</small></span></a>
<a class='command-item' data-command='change intelligence new since last run diff' href='/change-intelligence'><span class='nav-icon'>Δ</span><span class='command-copy'><strong>Change intelligence</strong><small>Prioritize what changed</small></span></a>
<a class='command-item' data-command='smart recon planner plan cost time' href='/smart-recon'><span class='nav-icon'>SP</span><span class='command-copy'><strong>Smart Recon Planner</strong><small>Advisory plan; requires user confirmation</small></span></a>
<a class='command-item' data-command='attack surface graph map' href='/attack-surface'><span class='nav-icon'>AG</span><span class='command-copy'><strong>Attack surface graph</strong><small>Visualize assets, endpoints, contexts and candidates</small></span></a>
<a class='command-item' data-command='safety scope authorization audit safe to run' href='/safety-center'><span class='nav-icon'>SC</span><span class='command-copy'><strong>Safety Center</strong><small>Scope, authorization and exposure gates</small></span></a>
<a class='command-item' data-command='diagnostics health repair errors browser' href='/diagnostics'><span class='nav-icon'>DX</span><span class='command-copy'><strong>Diagnostics & repair</strong><small>Self-check and preview-first safe recovery</small></span></a>
</div></div></div>
<script>
window.RECON_CSRF={csrf_json};
document.querySelectorAll("form[method='post'],form[method='POST']").forEach(f=>{{if(!f.querySelector("input[name='csrf']")){{const i=document.createElement('input');i.type='hidden';i.name='csrf';i.value=window.RECON_CSRF;f.appendChild(i);}}}});
const root=document.documentElement, savedTheme=localStorage.getItem('recon-theme'); if(savedTheme) root.dataset.theme=savedTheme;
document.getElementById('themeToggle')?.addEventListener('click',()=>{{root.dataset.theme=root.dataset.theme==='light'?'dark':'light';localStorage.setItem('recon-theme',root.dataset.theme);}});
const density=localStorage.getItem('recon-density');if(density==='compact')document.body.classList.add('compact');
document.getElementById('densityToggle')?.addEventListener('click',()=>{{document.body.classList.toggle('compact');localStorage.setItem('recon-density',document.body.classList.contains('compact')?'compact':'comfortable');}});
const focusMode=localStorage.getItem('recon-focus-mode');if(focusMode==='on')document.body.classList.add('focus-mode');
document.getElementById('focusToggle')?.addEventListener('click',()=>{{document.body.classList.toggle('focus-mode');localStorage.setItem('recon-focus-mode',document.body.classList.contains('focus-mode')?'on':'off');}});
document.getElementById('navToggle')?.addEventListener('click',()=>document.body.classList.toggle('nav-open'));
document.querySelectorAll('details[data-nav-group]').forEach(group=>{{const key='recon-nav-'+group.dataset.navGroup;const saved=localStorage.getItem(key);if(group.dataset.active==='1')group.open=true;else if(saved!==null)group.open=saved==='open';group.addEventListener('toggle',()=>localStorage.setItem(key,group.open?'open':'closed'));}});
document.querySelectorAll('.nav-item').forEach(link=>link.addEventListener('click',()=>document.body.classList.remove('nav-open')));
const palette=document.getElementById('commandPalette'),commandInput=document.getElementById('commandInput'),commandItems=[...document.querySelectorAll('.command-item')];
function openPalette(){{if(!palette)return;palette.classList.add('open');commandInput.value='';commandItems.forEach(x=>x.style.display='flex');setTimeout(()=>commandInput.focus(),0);}}
function closePalette(){{palette?.classList.remove('open');}}
commandInput?.addEventListener('input',()=>{{const q=commandInput.value.trim().toLowerCase();commandItems.forEach(x=>x.style.display=(!q||(x.dataset.command||'').includes(q)||x.textContent.toLowerCase().includes(q))?'flex':'none');}});
commandInput?.addEventListener('keydown',e=>{{if(e.key==='Enter'){{const q=commandInput.value.trim();const visible=commandItems.find(x=>x.style.display!=='none');if(q&&(!visible||q.length>2))window.location='/search?q='+encodeURIComponent(q);else if(visible)window.location=visible.href;}}}});
palette?.addEventListener('click',e=>{{if(e.target===palette)closePalette();}});
document.addEventListener('keydown',e=>{{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){{e.preventDefault();openPalette();return;}} if(e.key==='Escape'&&palette?.classList.contains('open')){{closePalette();return;}} if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)){{e.preventDefault();document.getElementById('globalSearch')?.focus();}}}});
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{{await navigator.clipboard.writeText(b.dataset.copy||'');const old=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=old,1200);}}));
const liveProgressKind=window.location.pathname==='/recon'?'recon':(window.location.pathname==='/analysis'?'analysis':'');
let liveProgressBusy=false;

async function refreshLiveProgress(){{
  if(!liveProgressKind||liveProgressBusy||document.visibilityState!=='visible')return;

  const panel=document.getElementById('live-progress');
  if(!panel)return;

  liveProgressBusy=true;
  try{{
    const params=new URLSearchParams();
    params.set('kind',liveProgressKind);

    const pageParams=new URLSearchParams(window.location.search);
    const target=pageParams.get('target');
    if(target)params.set('target',target);

    const response=await fetch(
      '/api/live-progress?'+params.toString(),
      {{
        method:'GET',
        headers:{{'Accept':'application/json'}},
        cache:'no-store',
        credentials:'same-origin'
      }}
    );

    if(!response.ok)throw new Error('HTTP '+response.status);

    const contentType=response.headers.get('content-type')||'';
    if(!contentType.includes('application/json'))throw new Error('Unexpected response type');

    const payload=await response.json();
    if(!payload.html)return;

    const template=document.createElement('template');
    template.innerHTML=payload.html.trim();
    const fresh=template.content.querySelector('#live-progress');

    if(fresh){{
      panel.replaceWith(fresh);
    }}
  }}catch(error){{
    console.debug('Live progress refresh failed:',error);
  }}finally{{
    liveProgressBusy=false;
  }}
}}

if(liveProgressKind){{
  window.setInterval(refreshLiveProgress,5000);

  document.addEventListener('visibilitychange',()=>{{
    if(document.visibilityState==='visible')refreshLiveProgress();
  }});
}}
</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    db_path: Path
    paths: AppPaths
    logger: Logger
    config: Config

    def log_message(self, format: str, *args: Any) -> None:
        self.logger.info("Dashboard request", client=self.client_address[0], request=format % args)

    def db(self) -> Database:
        return Database(self.db_path)

    session = None
    login_attempts: dict[str, list[float]] = {}

    def _authenticated(self, required_role: str = "viewer") -> bool:
        session_mode = self.config.get("DASHBOARD_AUTH_MODE", "session").lower() == "session"
        if session_mode:
            self.session = parse_session(self.paths, self.headers.get("Cookie", ""))
            return bool(self.session and self.session.allows(required_role))
        return verify_basic_header(self.config, self.headers.get("Authorization", ""))

    def _require_auth(self, required_role: str = "viewer") -> bool:
        if not self.config.bool("DASHBOARD_AUTH_ENABLED", False):
            return True
        if self._authenticated(required_role):
            return True
        self.redirect("/login")
        return False

    def _require_csrf(self, data: dict[str, list[str]]) -> bool:
        if not self.config.bool("DASHBOARD_AUTH_ENABLED", False) or self.config.get("DASHBOARD_AUTH_MODE", "session").lower() != "session":
            return True
        token = str((data.get("csrf") or [self.headers.get("X-CSRF-Token", "")])[0])
        return bool(self.session and token and self.session.csrf and __import__('hmac').compare_digest(token, self.session.csrf))

    def _same_origin_post(self) -> bool:
        origin = self.headers.get("Origin", "").strip()
        fetch_site = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        host = self.headers.get("Host", "").strip()
        scheme = "http"
        trust_proxy = self.config.bool("DASHBOARD_TRUST_PROXY_HEADERS", False)
        if trust_proxy:
            forwarded_host = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip()
            forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
            if forwarded_host:
                host = forwarded_host
            if forwarded_proto in {"http", "https"}:
                scheme = forwarded_proto

        server_address = getattr(getattr(self, "server", None), "server_address", None)
        client_address = getattr(self, "client_address", None)

        if not origin:
            # Safari can omit Origin for a regular local form POST and report
            # Sec-Fetch-Site=same-site when localhost/127.0.0.1 aliases are mixed.
            # Accept that narrow case only when both ends are loopback. The session
            # cookie is SameSite=Strict and a valid per-session CSRF token is still
            # mandatory in do_POST. Explicit cross-site metadata always fails.
            if fetch_site == "cross-site":
                return False
            if fetch_site not in {"", "same-origin", "same-site", "none"}:
                return False
            referer_origin = _origin_from_referer(self.headers.get("Referer", "").strip())
            if referer_origin:
                if _origin_matches_request(referer_origin, host, scheme):
                    return True
                if not trust_proxy and _origin_matches_loopback_server(referer_origin, server_address, scheme):
                    return _loopback_socket_context(server_address, client_address)
                return _allowed_origin(referer_origin, self.config.get("DASHBOARD_ALLOWED_ORIGINS", ""))
            return (not trust_proxy) and _loopback_socket_context(server_address, client_address)

        if origin.lower() == "null":
            # Safari can emit the literal Origin value ``null`` for a local
            # same-origin form POST when privacy/referrer protections are
            # active. In v7 this narrow compatibility rule applies to local
            # Dashboard forms consistently, not only Safe Validation. It still
            # requires Fetch Metadata to say same-origin, proxy trust to be off,
            # and Host/client/listening socket to all be loopback on the exact
            # listening port. ``null`` from same-site/cross-site/none, a remote
            # bind, a different port or a proxy-trusted deployment is rejected.
            if trust_proxy or fetch_site != "same-origin":
                return False
            if not _loopback_socket_context(server_address, client_address):
                return False
            request = _canonical_host_port(host, scheme)
            if request is None or not isinstance(server_address, (tuple, list)) or len(server_address) < 2:
                return False
            try:
                request_host, request_port = request
                server_host = str(server_address[0]).rstrip(".").lower()
                server_port = int(server_address[1])
            except (TypeError, ValueError, IndexError):
                return False
            return bool(
                _is_loopback_host(request_host)
                and _is_loopback_host(server_host)
                and request_port == server_port
            )
        if _origin_matches_request(origin, host, scheme):
            return True
        # Safari, local reverse proxies and privacy tools can preserve a valid
        # loopback Origin while rewriting Host. Compare with the real listening
        # socket, but require the caller itself to be loopback as well.
        if not trust_proxy and _origin_matches_loopback_server(origin, server_address, scheme):
            return _loopback_socket_context(server_address, client_address)
        return _allowed_origin(origin, self.config.get("DASHBOARD_ALLOWED_ORIGINS", ""))

    def send_html(self, title: str, body: str, status: int = 200) -> None:
        data = _layout(title, body, getattr(self.session, "csrf", "") if self.session else "", getattr(self.session, "username", "") if self.session else "", getattr(self.session, "role", "") if self.session else "", self.path).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def send_json(self, value: Any, status: int = 200) -> None:
        data = (json_dumps(value, pretty=True) + "\n").encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def send_attachment(self, filename: str, data: bytes, content_type: str = "application/zip") -> None:
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def redirect(self, location: str) -> None:
        if not location.startswith("/") or location.startswith("//"):
            location = "/"
        try:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def query(self) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def form_data(self) -> dict[str, list[str]]:
        length = parse_int(self.headers.get("Content-Length"), 0, 0, 100_000)
        return urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            self.login_page(); return
        if path == "/logout":
            session = parse_session(self.paths, self.headers.get("Cookie", ""))
            if session: destroy_session(self.paths, session.token)
            self.send_response(HTTPStatus.SEE_OTHER); self.send_header("Location", "/login"); self.send_header("Set-Cookie", expired_cookie()); self.end_headers(); return
        if not self._require_auth("viewer"):
            return
        started = time.perf_counter()
        try:
            routes = {
                "/": self.overview,
                "/workbench": self.workbench,
                "/cases": self.cases_page,
                "/case": self.case_page,
                "/safe-validation": self.safe_validation_page,
                "/case-autopilot": self.case_autopilot_page,
                "/evidence-gaps": self.evidence_gaps_page,
                "/security-stories": self.security_stories_page,
                "/engine-quality": self.engine_quality_platform_page,
                "/operations-center": self.operations_center_page,
                "/scope-center": self.scope_center_page,
                "/storage-health": self.storage_health_page,
                "/validation-intelligence": self.validation_intelligence_page,
                "/recon-coverage": self.recon_coverage_page,
                "/change-intelligence": self.change_intelligence_page,
                "/target-memory": self.target_memory_page,
                "/smart-recon": self.smart_recon_page,
                "/data-quality": self.data_quality_page,
                "/review-priority": self.review_priority_page,
                "/automation": self.automation_page,
                "/report-quality": self.report_quality_page,
                "/performance": self.performance_page,
                "/retention": self.retention_page,
                "/templates": self.templates_page,
                "/platform-security": self.platform_security_page,
                "/safety-center": self.safety_center_page,
                "/diagnostics": self.diagnostics_page,
                "/browser-capture": self.browser_capture_page,
                "/learning": self.false_positive_learning_page,
                "/report-builder": self.report_builder_page,
                "/rules": self.rules_page,
                "/plugins": self.plugins_page,
                "/audit": self.audit_page,
                "/recon": self.recon_workspace,
                "/analysis": self.analysis_engine,
                "/potential-findings": self.bug_candidates,
                "/bug-candidates": self.bug_candidates,
                "/bug-candidate": self.bug_candidate_detail,
                "/candidate-quality": self.candidate_quality_page,
                "/security-reasoning": self.security_reasoning_page,
                "/candidate-bundles": self.candidate_bundles_page,
                "/semantic-intelligence": self.semantic_intelligence_page,
                "/behavioral-intelligence": self.behavioral_intelligence_page,
                "/differential-intelligence": self.differential_intelligence_page,
                "/auth-contexts": self.auth_contexts_page,
                "/hypotheses": self.hypotheses,
                "/clusters": self.analysis_clusters,
                "/dataflows": self.dataflows,
                "/analysis-quality": self.analysis_quality_page,
                "/daily": self.daily,
                "/targets": self.targets,
                "/runs": self.runs,
                "/compare": self.compare,
                "/alerts": self.alerts,
                "/signal-alerts": self.signal_alerts,
                "/alert": self.alert_detail,
                "/assets": self.assets,
                "/asset": self.asset_detail,
                "/graph": self.graph,
                "/attack-surface": self.attack_surface_page,
                "/api/attack-surface": self.attack_surface_api,
                "/api/graph": self.graph_api,
                "/urls": self.urls,
                "/javascript": self.javascript,
                "/js-diff": self.js_diff,
                "/endpoints": self.endpoints,
                "/fingerprints": self.fingerprints,
                "/notes": self.notes,
                "/incidents": self.incidents,
                "/lifecycle": self.lifecycle,
                "/views": self.views,
                "/metrics": self.metrics,
                "/health": self.health,
                "/search": self.search,
                "/evidence/export": self.evidence_export,
            }
            if path in routes:
                routes[path]()
            elif path.startswith("/report/"):
                self.report(path.split("/", 2)[2])
            else:
                self.send_html("Not found", "<h1>Not found</h1>", 404)
        except Exception as exc:
            error_id = ""
            try:
                err_db = self.db()
                try:
                    error_id = record_error_event(err_db, "RM-DASH-GET-500", component="dashboard", summary="Dashboard GET handler failed", details={"path": path, "error_type": type(exc).__name__, "error": str(exc)[:500]})
                finally:
                    err_db.close()
            except Exception:
                error_id = ""
            self.logger.error("Dashboard error", error=str(exc), path=self.path, error_id=error_id)
            diagnostic = f"<p class='muted'>Error ID: <code>{_esc(error_id)}</code></p>" if error_id else ""
            self.send_html("Error", f"<h1>Something failed</h1><p>{_esc(exc)}</p>{diagnostic}<p><a class='button' href='/diagnostics'>Open diagnostics</a></p>", 500)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            try:
                perf_db = self.db()
                try:
                    from platform_v6 import record_performance_sample
                    record_performance_sample(perf_db, "dashboard", path, elapsed_ms, details={"method": "GET"})
                finally:
                    perf_db.close()
            except Exception:
                pass

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        data = self.form_data()
        if path == "/login":
            self.login_submit(data); return
        if not self._require_auth("analyst"):
            return
        origin_ok = self._same_origin_post()
        csrf_ok = self._require_csrf(data)
        if not origin_ok or not csrf_ok:
            reason = "origin" if not origin_ok else "csrf"
            safe_details = {
                "path": path, "reason": reason, "origin": self.headers.get("Origin", ""), "host": self.headers.get("Host", ""),
                "fetch_site": self.headers.get("Sec-Fetch-Site", ""), "referer_origin": _origin_from_referer(self.headers.get("Referer", "")),
                "client": str(getattr(self, "client_address", "")), "server": str(getattr(getattr(self, "server", None), "server_address", "")),
                "browser": browser_compatibility(self.headers.get("User-Agent", "")),
            }
            error_id = ""
            try:
                err_db = self.db()
                try:
                    error_id = record_error_event(err_db, "RM-DASH-ORIGIN-001" if reason == "origin" else "RM-DASH-CSRF-002", component="dashboard", details=safe_details)
                finally:
                    err_db.close()
            except Exception:
                pass
            self.logger.warn("Dashboard POST security validation failed", error_id=error_id, **safe_details)
            diagnostic_json = json_dumps({"error_id": error_id, **safe_details}, pretty=True)
            if reason == "origin":
                title = "Origin validation failed"
                explanation = "The browser's form-origin metadata did not match the local security policy."
            else:
                title = "CSRF token expired or missing"
                explanation = "The form token does not match the active session. Reload the page before retrying."
            message = f"<h1>{_esc(title)}</h1><p>{_esc(explanation)}</p><div class='callout'><strong>Error ID</strong><span><code>{_esc(error_id)}</code></span></div><details open><summary>Safe diagnostics</summary><pre>{_esc(diagnostic_json)}</pre><button type='button' class='secondary' data-copy='{_esc(diagnostic_json)}'>Copy diagnostics</button></details><p><a class='button' href='/diagnostics'>Open diagnostics & repair</a> <a class='button secondary' href='/safe-validation'>Return to Safe Validation</a></p>"
            self.send_html("Forbidden", message, 403)
            return
        db = self.db()
        actor = getattr(self.session, "username", "dashboard") if self.session else "dashboard"
        try:
            if path == "/alerts/status":
                db.set_alert_status(
                    parse_int((data.get("id") or [0])[0], 0),
                    str((data.get("status") or [""])[0]),
                    str((data.get("note") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/alerts"])[0])); return
            if path == "/alerts/workflow":
                db.update_alert_workflow(
                    parse_int((data.get("id") or [0])[0], 0),
                    priority=str((data.get("priority") or ["normal"])[0]),
                    assignee=str((data.get("assignee") or [""])[0]),
                    note=str((data.get("workflow_note") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/alerts"])[0])); return
            if path == "/bug-candidates/decision":
                set_bug_candidate_decision(
                    db,
                    str((data.get("candidate_id") or [""])[0]),
                    str((data.get("decision") or ["unreviewed"])[0]),
                    str((data.get("note") or [""])[0]),
                    actor=actor,
                    reason_code=str((data.get("reason") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/bug-candidates"])[0])); return
            if path == "/platform/sync":
                platform_sync(self.paths, db, str((data.get("analysis_id") or [""])[0]) or None)
                workspace_v7_sync(self.paths, self.config, db, target=str((data.get("target") or [""])[0]), actor=actor)
                self.redirect(str((data.get("return") or ["/"])[0])); return
            if path == "/cases/state":
                set_case_state(db,str((data.get("case_id") or [""])[0]),str((data.get("state") or ["new"])[0]),assigned_to=str((data.get("assigned_to") or [""])[0]),note=str((data.get("note") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/cases"])[0])); return
            if path == "/cases/validation-package":
                build_validation_package(db,str((data.get("case_id") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/cases"])[0])); return
            if path == "/cases/report-draft":
                build_report_draft(db,str((data.get("case_id") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/cases"])[0])); return
            if path == "/validation/plan":
                try:
                    create_validation_plan(self.paths,db,str((data.get("case_id") or [""])[0]),requested_level=str((data.get("level") or [""])[0]),actor=actor)
                except ReconError as exc:
                    self.send_html("Validation plan rejected", f"<h1>Validation plan rejected</h1><p>{_esc(exc)}</p><p><a class='button' href='{_esc(str((data.get('return') or ['/safe-validation'])[0]))}'>Return to Safe Validation</a></p>", 400)
                    return
                self.redirect(str((data.get("return") or ["/safe-validation"])[0])); return
            if path == "/validation/approve":
                approve_validation_plan(db,str((data.get("plan_id") or [""])[0]),str((data.get("confirmation") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/safe-validation"])[0])); return
            if path == "/validation/run":
                execute_validation_plan(self.paths,self.config,db,str((data.get("plan_id") or [""])[0]),allow_live=str((data.get("allow_live") or [""])[0]).lower() in {"1","true","yes","on"},actor=actor)
                self.redirect(str((data.get("return") or ["/safe-validation"])[0])); return
            if path == "/validation/feedback":
                record_validation_feedback(db,str((data.get("run_id") or [""])[0]),str((data.get("decision") or [""])[0]),str((data.get("reason") or [""])[0]),str((data.get("note") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/safe-validation"])[0])); return
            if path == "/rules/state":
                set_rule_state(db,str((data.get("rule_id") or [""])[0]),str((data.get("rule_version") or [""])[0]),str((data.get("state") or ["draft"])[0]),actor=actor,note=str((data.get("note") or [""])[0]))
                self.redirect('/rules'); return
            if path == "/schedules/set":
                set_schedule_policy(db,str((data.get("target") or [""])[0]),str((data.get("cadence") or [""])[0]),enabled=str((data.get("enabled") or ["true"])[0]).lower()=="true",max_runtime_minutes=parse_int((data.get("max_runtime") or [120])[0],120),request_budget=parse_int((data.get("request_budget") or [10000])[0],10000),quiet_hours=str((data.get("quiet_hours") or [""])[0]),actor=actor)
                self.redirect('/operations-center'); return
            if path == "/notifications/set":
                set_notification_policy(db,str((data.get("target") or ["*"])[0]),str((data.get("event_type") or [""])[0]),str((data.get("mode") or ["digest"])[0]),minimum_score=parse_int((data.get("minimum_score") or [70])[0],70),actor=actor)
                self.redirect('/operations-center'); return
            if path == "/suite/sync":
                platform_v6_sync(self.paths,db,run_id=str((data.get("run_id") or [""])[0]) or None,analysis_id=str((data.get("analysis_id") or [""])[0]) or None)
                workspace_v7_sync(self.paths,self.config,db,target=str((data.get("target") or [""])[0]),actor=actor)
                self.redirect(str((data.get("return") or ["/validation-intelligence"])[0])); return
            if path == "/suite/revalidation":
                set_revalidation_policy(db,str((data.get("case_id") or [""])[0]),str((data.get("trigger") or ["manual"])[0]),interval_days=parse_int((data.get("interval_days") or [7])[0],7),enabled=str((data.get("enabled") or ["true"])[0]).lower() in {"1","true","yes","on"},actor=actor); self.redirect(str((data.get("return") or ["/automation"])[0])); return
            if path == "/suite/schedule-generate":
                generate_schedule_job(self.paths,db,str((data.get("target") or [""])[0]),apply=False,actor=actor); self.redirect("/automation"); return
            if path == "/suite/revalidation-process":
                process_due_revalidations(self.paths,self.config,db,limit=50,execute_offline=True,actor=actor); self.redirect("/automation"); return
            if path == "/suite/security-check":
                security_posture(self.paths,self.config,db,persist=True,apply_safe_permissions=str((data.get("apply_permissions") or [""])[0]).lower() in {"1","true","yes","on"}); self.redirect("/platform-security"); return
            if path == "/suite/retention-preview":
                retention_preview(self.paths,db,persist=True); self.redirect("/retention"); return
            if path == "/suite/template-apply":
                apply_target_template(self.paths,str((data.get("target") or [""])[0]),str((data.get("template_id") or [""])[0]),actor=actor,dry_run=False); self.redirect("/templates"); return
            if path == "/suite/burp-export":
                build_burp_roundtrip_package(self.paths,db,str((data.get("case_id") or [""])[0]),actor=actor); self.redirect(str((data.get("return") or ["/review-priority"])[0])); return
            if path == "/suite/report-quality":
                report_quality(db,draft_id=str((data.get("draft_id") or [""])[0]) or None,case_id=str((data.get("case_id") or [""])[0]) or None,persist=True); self.redirect("/report-quality"); return
            if path == "/workspace/sync":
                workspace_v7_sync(self.paths,self.config,db,target=str((data.get("target") or [""])[0]),actor=actor); self.redirect(str((data.get("return") or ["/"])[0])); return
            if path == "/workspace/evidence-gap":
                evidence_gap_for_case(db,str((data.get("case_id") or [""])[0]),persist=True); self.redirect(str((data.get("return") or ["/evidence-gaps"])[0])); return
            if path == "/workspace/autopilot":
                case_autopilot(db,str((data.get("case_id") or [""])[0]),actor=actor,persist=True); self.redirect(str((data.get("return") or ["/case-autopilot"])[0])); return
            if path == "/workspace/repair":
                safe_repair(self.paths,db,dry_run=False,actor=actor,max_age_hours=parse_int((data.get("max_age_hours") or [24])[0],24,1,720)); self.redirect("/diagnostics"); return
            if path == "/workspace/report":
                build_evidence_linked_report(db,str((data.get("case_id") or [""])[0]),actor=actor,persist=True); self.redirect(str((data.get("return") or ["/report-builder"])[0])); return
            if path == "/workspace/plan":
                smart_recon_plan(db,target=str((data.get("target") or [""])[0]),persist=True); self.redirect("/smart-recon"); return
            if path == "/workspace/learning":
                false_positive_learning(db,target=str((data.get("target") or [""])[0]),persist=True); self.redirect("/learning"); return
            if path == "/workspace/capture-import":
                target = str((data.get("target") or [""])[0]).strip()
                context = str((data.get("context") or [""])[0]).strip()
                capture_json = str((data.get("capture_json") or [""])[0])
                if not target or not context or not capture_json.strip():
                    raise ReconError("Target, context label and capture JSON are required")
                capture_path = self.paths.state / f"browser-capture-dashboard-{time.time_ns()}.json"
                try:
                    capture_path.write_text(capture_json, encoding="utf-8")
                    try:
                        capture_path.chmod(0o600)
                    except OSError:
                        pass
                    import_browser_capture(self.paths, db, target=target, file_path=capture_path, context_label=context, actor=actor, limit=1000)
                finally:
                    try:
                        capture_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                self.redirect("/browser-capture"); return
            if path == "/notes/add":
                db.add_note(
                    str((data.get("target") or [""])[0]),
                    str((data.get("entity_type") or ["asset"])[0]),
                    str((data.get("entity_value") or [""])[0]),
                    str((data.get("note") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/notes"])[0])); return
            if path == "/notes/delete":
                db.delete_note(parse_int((data.get("id") or [0])[0], 0))
                self.redirect(str((data.get("return") or ["/notes"])[0])); return
            if path == "/tags/add":
                db.add_tag(
                    str((data.get("target") or [""])[0]),
                    str((data.get("entity_type") or [""])[0]),
                    str((data.get("entity_value") or [""])[0]),
                    str((data.get("tag") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/"])[0])); return
            if path == "/tags/remove":
                db.remove_tag(
                    str((data.get("target") or [""])[0]),
                    str((data.get("entity_type") or [""])[0]),
                    str((data.get("entity_value") or [""])[0]),
                    str((data.get("tag") or [""])[0]),
                )
                self.redirect(str((data.get("return") or ["/"])[0])); return
        finally:
            db.close()
        self.send_html("Not found", "<h1>Not found</h1>", 404)

    def login_page(self, error: str = "") -> None:
        if not self.config.bool("DASHBOARD_AUTH_ENABLED", False):
            self.redirect("/"); return
        body = f"<div class='card' style='max-width:420px;margin:8vh auto'><h1>Sign in</h1>{f'<p class=warn>{_esc(error)}</p>' if error else ''}<form method='post' action='/login'><label>Username<br><input name='username' autocomplete='username' required></label><br><br><label>Password<br><input type='password' name='password' autocomplete='current-password' required></label><br><br><button>Sign in</button></form></div>"
        data = _layout("Sign in", body, current_path="/login").encode("utf-8")
        self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)

    def login_submit(self, data: dict[str, list[str]]) -> None:
        ip = self.client_address[0]; now = __import__('time').time(); attempts = [x for x in self.login_attempts.get(ip, []) if now-x < 300]
        if len(attempts) >= 10:
            self.login_page("Too many attempts. Try again later."); return
        username=str((data.get('username') or [''])[0]); password=str((data.get('password') or [''])[0])
        ok, role = verify_user(self.paths, username, password)
        if not ok:
            attempts.append(now); self.login_attempts[ip]=attempts; self.login_page("Invalid credentials"); return
        self.login_attempts.pop(ip, None); session=create_session(self.paths, username, role)
        db=self.db()
        try: db.audit("dashboard_login", actor=username, entity_type="session", entity_value=ip, details={"role":role})
        finally: db.close()
        self.send_response(HTTPStatus.SEE_OTHER); self.send_header("Location","/"); self.send_header("Set-Cookie",session_cookie(session,secure=False)); self.send_header("Cache-Control","no-store"); self.end_headers()

    def recon_workspace(self) -> None:
        p=self.query()
        target=str((p.get('target') or [''])[0]).strip()
        view=str((p.get('view') or ['overview'])[0]).strip().lower()
        category=str((p.get('category') or [''])[0]).strip().lower()
        raw=str((p.get('raw') or [''])[0]).strip().lower()
        q=str((p.get('q') or [''])[0]).strip()
        days=parse_int((p.get('days') or [0])[0],0,0,3650)
        legacy_kind=str((p.get('kind') or [''])[0]).strip().lower()
        if legacy_kind and 'view' not in p:
            view='raw'; raw={'subdomain':'host','endpoint':'endpoint','url':'url','port':'port','javascript':'javascript'}.get(legacy_kind,legacy_kind)
        if view not in {'overview','categories','raw'}: view='overview'
        db=self.db()
        try:
            items,meta=_recon_surface_items(db,target)
        finally:
            db.close()
        targets=meta['targets']
        since=''
        if days: since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z')
        filtered=[x for x in items if (not q or q.lower() in (' '.join([str(x.get('value','')),str(x.get('detail','')),str(x.get('target','')),' '.join(x.get('categories',[])),' '.join(x.get('sources',[]))])).lower()) and (not since or str(x.get('last_seen') or '')>=since)]
        counts={kind:sum(1 for x in items if x['kind']==kind) for kind in RECON_RAW_META}
        category_counts={key:sum(1 for x in items if key in x['categories']) for key in RECON_CATEGORY_ORDER}
        state_counts={state:sum(1 for x in items if x['change_state']==state) for state in ('new','changed','reappeared','disappeared','stable')}
        high_interest=[x for x in filtered if parse_int(x.get('interest'),0)>=70]
        tabs="<nav class='segmented' aria-label='Recon views'>"+''.join(
            f"<a class='{'active' if view==key else ''}' href='{_query_link('/recon',view=key,target=target)}'>{label}</a>"
            for key,label in [('overview','Overview'),('categories','Categories'),('raw','Raw Data')]
        )+"</nav>"
        target_controls=_filter_panel(
            f"<label>Target{_select('target',targets,target,'All targets')}</label><input type='hidden' name='view' value='{_esc(view)}'>",
            {'Target':target},_query_link('/recon',view=view),title='Recon focus',result_count=len(filtered)
        )
        header=_page_header('Recon','Understand the attack surface first. Overview explains the current picture, Categories organize security context, and Raw Data preserves full evidence.',"<a class='button secondary' href='/smart-recon'>Next recon action</a><a class='button' href='/runs'>Run history</a>",'01 · Discover')
        common=header+tabs+target_controls
        if view=='overview':
            summary="<div class='metrics-grid'>"+''.join([
                _metric_card('Attack-surface items',len(items),'Unified observations across all recon sources','info',_query_link('/recon',view='raw',target=target)),
                _metric_card('High-interest',len([x for x in items if parse_int(x.get('interest'),0)>=70]),'Prioritized surface — not vulnerability claims','orange',_query_link('/recon',view='categories',target=target)),
                _metric_card('New / changed',state_counts['new']+state_counts['changed']+state_counts['reappeared'],'Material change states from run comparisons','purple',_query_link('/recon',view='overview',target=target)+'#changes'),
                _metric_card('Coverage',str(meta['coverage_overall'])+'%','Observation confidence across selected scope','success' if meta['coverage_overall']>=75 else 'amber','/recon-coverage'+(('?target='+urllib.parse.quote(target)) if target else '')),
            ])+"</div>"
            raw_pulse="<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Attack Surface Summary</h3><span class='muted small'>Inventory by raw evidence source</span></div><div class='attention-grid'>"+''.join(
                f"<a class='attention-card' href='{_query_link('/recon',view='raw',raw=k,target=target)}'><span>{_esc(RECON_RAW_META[k][1])}</span><strong>{counts[k]}</strong><small>{_esc(RECON_RAW_META[k][0])}</small></a>" for k in RECON_RAW_META
            )+"</div></section>"
            change_cards=''.join(
                f"<a class='attention-card' href='{_query_link('/recon',view='raw',target=target)}'><span>{_esc(label)}</span><strong>{state_counts[key]}</strong><small>surface items</small></a>"
                for key,label in [('new','New'),('changed','Changed'),('reappeared','Reappeared'),('disappeared','Disappeared')]
            )
            changes=f"<section class='panel' id='changes' style='margin-top:16px'><div class='panel-head'><h3>New / Changed Surface</h3><span class='muted small'>Run-to-run state, not a vulnerability verdict</span></div><div class='attention-grid'>{change_cards}</div></section>"
            top=high_interest[:12]
            top_rows=''.join(f"<tr><td><strong>{x['interest']}</strong></td><td>{_pill(x['kind'])}</td><td>{_esc(x['target'])}</td><td><code>{_esc(x['value'])}</code></td><td>{' '.join(_pill(RECON_CATEGORY_META[c][0],'info') for c in x['categories'])}</td><td>{_pill(x['change_state'])}</td><td>{_esc(', '.join(x['sources'][:3]))}</td></tr>" for x in top)
            interest=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>High-interest Areas</h3><span class='muted small'>Interest ranks review value only; it does not claim a vulnerability.</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Interest</th><th>Type</th><th>Target</th><th>Surface</th><th>Categories</th><th>Change</th><th>Provenance</th></tr></thead><tbody>{top_rows or '<tr><td colspan=7>No high-interest surface is currently indexed</td></tr>'}</tbody></table></div></section>"
            blind=''.join(f"<li>{_esc(x)}</li>" for x in meta['blind_spots']) or '<li>No major blind spot identified by current coverage heuristics.</li>'
            coverage=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Coverage / Blind Spots</h3><span class='muted small'>Coverage {meta['coverage_overall']}%</span></div><div class='panel-body'><ul>{blind}</ul><p class='muted small'>Low coverage means observations are missing; it never means the target is safe.</p></div></section>"
            self.send_html('Recon',common+summary+raw_pulse+changes+interest+coverage); return
        if view=='categories':
            cards=[]
            for key in RECON_CATEGORY_ORDER:
                label,desc,icon=RECON_CATEGORY_META[key]
                members=[x for x in filtered if key in x['categories']]
                high=sum(1 for x in members if parse_int(x.get('interest'),0)>=70)
                changed=sum(1 for x in members if x['change_state']!='stable')
                cards.append(f"<a class='workspace-tile' href='{_query_link('/recon',view='categories',category=key,target=target)}'><span class='workspace-tile-icon'>{_esc(icon)}</span><span><strong>{_esc(label)}</strong><small>{len(members)} items · {high} high-interest · {changed} changed<br>{_esc(desc)}</small></span></a>")
            category_grid="<div class='workspace-strip' style='grid-template-columns:repeat(auto-fit,minmax(260px,1fr))'>"+''.join(cards)+"</div>"
            chosen=category if category in RECON_CATEGORY_META else ''
            members=[x for x in filtered if not chosen or chosen in x['categories']]
            fields=f"<label class='filter-wide'>Search categorized surface<input name='q' value='{_esc(q)}' placeholder='Host, route, category, source…'></label><label>Category{_select_pairs('category',[(k,RECON_CATEGORY_META[k][0]) for k in RECON_CATEGORY_ORDER],chosen,'All categories')}</label><label>Seen{_select_pairs('days',[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')],str(days) if days else '','Any time')}</label><input type='hidden' name='view' value='categories'><input type='hidden' name='target' value='{_esc(target)}'>"
            controls=_filter_panel(fields,{'Category':RECON_CATEGORY_META.get(chosen,('',))[0] if chosen else '', 'Search':q,'Window':str(days)+' days' if days else ''},_query_link('/recon',view='categories',target=target),title='Category filters',result_count=len(members))
            rows=''.join(f"<tr><td><strong>{x['interest']}</strong></td><td>{_pill(x['kind'])}</td><td>{_esc(x['target'])}</td><td><code>{_esc(x['value'])}</code><br><span class='muted small'>{_esc(x['detail'])}</span></td><td>{' '.join(_pill(RECON_CATEGORY_META[c][0],'info') for c in x['categories'])}</td><td>{_pill(x['change_state'])}</td><td>{_esc(', '.join(x['sources'][:3]))}</td><td>{_esc(x['last_seen'])}</td></tr>" for x in members[:500])
            title=RECON_CATEGORY_META[chosen][0] if chosen else 'All categorized surface'
            table=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>{_esc(title)}</h3><span class='muted small'>Multi-label categories: one item may appear in more than one security context.</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Interest</th><th>Type</th><th>Target</th><th>Surface</th><th>Labels</th><th>Change</th><th>Provenance</th><th>Last seen</th></tr></thead><tbody>{rows or '<tr><td colspan=8>No surface matches this category</td></tr>'}</tbody></table></div></section>"
            self.send_html('Recon categories',common+category_grid+controls+table); return
        # Raw Data: source-faithful evidence with minimal interpretation.
        chosen=raw if raw in RECON_RAW_META else ''
        members=[x for x in filtered if not chosen or x['kind']==chosen]
        raw_tiles="<div class='workspace-strip'>"+''.join(f"<a class='workspace-tile' href='{_query_link('/recon',view='raw',raw=k,target=target)}'><span class='workspace-tile-icon'>{_esc(k[:2].upper())}</span><span><strong>{_esc(RECON_RAW_META[k][0])}</strong><small>{counts[k]} · {_esc(RECON_RAW_META[k][1])}</small></span></a>" for k in RECON_RAW_META)+"</div>"
        fields=f"<label class='filter-wide'>Search raw recon data<input name='q' value='{_esc(q)}' placeholder='Exact host, URL, route, service or source…'></label><label>Raw type{_select_pairs('raw',[(k,v[0]) for k,v in RECON_RAW_META.items()],chosen,'All raw data')}</label><label>Seen{_select_pairs('days',[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')],str(days) if days else '','Any time')}</label><input type='hidden' name='view' value='raw'><input type='hidden' name='target' value='{_esc(target)}'>"
        controls=_filter_panel(fields,{'Type':RECON_RAW_META.get(chosen,('',))[0] if chosen else '', 'Search':q,'Window':str(days)+' days' if days else ''},_query_link('/recon',view='raw',target=target),title='Raw data filters',result_count=len(members))
        rows=''.join(f"<tr><td>{_pill(x['kind'])}</td><td>{_esc(x['target'])}</td><td><code>{_esc(x['value'])}</code><br><span class='muted small'>{_esc(x['detail'])}</span></td><td>{_confidence(x['confidence']) if x['confidence'] else '—'}</td><td>{_esc(', '.join(x['sources'][:4]))}</td><td>{_esc(x['first_seen'])}</td><td>{_esc(x['last_seen'])}</td><td>{_esc(x['last_run_id'])}</td></tr>" for x in members[:500])
        table=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>{_esc(RECON_RAW_META[chosen][0] if chosen else 'All raw recon data')}</h3><span class='muted small'>Source-faithful inventory; use Categories for security context.</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Type</th><th>Target</th><th>Observation</th><th>Confidence</th><th>Provenance</th><th>First seen</th><th>Last seen</th><th>Run</th></tr></thead><tbody>{rows or '<tr><td colspan=8>No raw observations match the current filters</td></tr>'}</tbody></table></div></section>"
        self.send_html('Recon raw data',common+raw_tiles+controls+table)

    def analysis_engine(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT * FROM analysis_runs WHERE status='success' ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1")
            runs=db.all("SELECT id,source_run_id,target,engine_version,rule_version,status,started_at,finished_at FROM analysis_runs ORDER BY started_at DESC LIMIT 12")
            analysis_id=str(latest['id']) if latest else ''
            summary=_json(latest['summary_json'],{}) if latest else {}
            evidence_count=int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?",(analysis_id,)) or {'count':0})['count']) if analysis_id else 0
            candidate_counts=db.one("SELECT COUNT(*) total,SUM(candidate_state='strong_candidate') strong,SUM(candidate_state='insufficient_evidence') insufficient,ROUND(AVG(observation_quality),1) observation,ROUND(AVG(evidence_coverage),1) coverage FROM bug_candidates WHERE analysis_id=?",(analysis_id,)) if analysis_id else None
            quality_row=db.one("SELECT health_score,metrics_json,created_at FROM engine_quality_snapshots WHERE analysis_id=? ORDER BY id DESC LIMIT 1",(analysis_id,)) if analysis_id else None
        finally:
            db.close()
        total=int(candidate_counts['total'] or 0) if candidate_counts else 0
        strong=int(candidate_counts['strong'] or 0) if candidate_counts else 0
        insufficient=int(candidate_counts['insufficient'] or 0) if candidate_counts else 0
        observation=float(candidate_counts['observation'] or 0) if candidate_counts else 0
        coverage=float(candidate_counts['coverage'] or 0) if candidate_counts else 0
        health=int(quality_row['health_score'] or 0) if quality_row else round((observation+coverage)/2) if candidate_counts else 0
        analyzed=parse_int(summary.get('alerts'),0) if latest else 0
        header=_page_header('Analysis','The intelligence engine works behind the scenes. This page shows health only; evidence and reasoning are revealed on-demand inside each Potential Finding.',"<a class='button' href='/potential-findings'>Review Potential Findings</a>",'02 · Understand')
        state=_pill('healthy' if latest and health>=70 else 'limited evidence' if latest else 'not run','success' if latest and health>=70 else 'amber')
        cards="<div class='metrics-grid'>"+''.join([
            _metric_card('Analyzed observations',analyzed,'Latest completed analysis','blue'),
            _metric_card('Evidence records',evidence_count,'Provenance-linked evidence used by reasoning','purple'),
            _metric_card('Potential findings',total,f'{strong} mature enough for priority review','orange','/potential-findings'),
            _metric_card('Insufficient evidence',insufficient,'Held back rather than over-claimed','amber'),
            _metric_card('Analysis health',f'{health}%',f'Observation quality {observation:.0f}% · coverage {coverage:.0f}%','success' if health>=70 else 'amber'),
        ])+"</div>"
        status=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Invisible Security Intelligence Core</h3>{state}</div><div class='panel-body'><div class='callout'><strong>Evidence-first, audit-on-demand</strong><span>Correlation, hypothesis competition, falsification, calibration, evidence deduplication and quality gates remain internal. Every promoted conclusion must retain traceable source evidence and an immutable audit snapshot.</span></div></div></section>"
        run_rows=''.join(f"<tr><td><code>{_esc(r['id'])}</code></td><td><code>{_esc(r['source_run_id'])}</code></td><td>{_esc(r['target'])}</td><td>{_esc(r['engine_version'])} / {_esc(r['rule_version'])}</td><td>{_pill(r['status'])}</td><td>{_esc(r['finished_at'] or r['started_at'])}</td></tr>" for r in runs)
        history=f"<details style='margin-top:16px'><summary>Analysis run history</summary><div class='table-wrap' style='margin-top:10px'><table><thead><tr><th>Analysis</th><th>Source run</th><th>Target</th><th>Engine / rules</th><th>Status</th><th>Finished</th></tr></thead><tbody>{run_rows or '<tr><td colspan=6>No analysis runs</td></tr>'}</tbody></table></div></details>"
        self.send_html('Analysis',header+cards+status+history)

    def bug_candidates(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); family=str((p.get('family') or [''])[0]); state=str((p.get('state') or [''])[0]); decision=str((p.get('decision') or [''])[0]); display=str((p.get('display') or ['cards'])[0]); view=str((p.get('view') or ['actionable'])[0])
        q=str((p.get('q')or[''])[0]).strip(); reachability=str((p.get('reachability')or[''])[0]); sort=str((p.get('sort')or['investigation'])[0])
        min_likelihood=parse_int((p.get('min_likelihood')or[0])[0],0,0,100); min_evidence=parse_int((p.get('min_evidence')or[0])[0],0,0,100); min_exploitability=parse_int((p.get('min_exploitability')or[0])[0],0,0,100); min_investigation=parse_int((p.get('min_investigation')or[0])[0],0,0,100)
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            where=['analysis_id=?']; args:list[Any]=[analysis_id]
            if view=='actionable':
                where.append("candidate_state NOT IN ('weak_signal','insufficient_evidence','rejected')")
                where.append("analyst_decision NOT IN ('rejected','duplicate','out_of_scope')")
            elif view=='strong':
                where.append("candidate_state IN ('strong_candidate','confirmed_by_analyst')")
            elif view=='needs_review':
                where.append("analyst_decision='unreviewed'")
            elif view=='needs_evidence':
                where.append("analyst_decision='needs_more_evidence'")
            if target: where.append('target=?'); args.append(target)
            if family: where.append('bug_family=?'); args.append(family)
            if state: where.append('candidate_state=?'); args.append(state)
            if decision: where.append('analyst_decision=?'); args.append(decision)
            if q:where.append('(title LIKE ? OR summary LIKE ? OR endpoint LIKE ? OR source_ref LIKE ?)');args.extend([f'%{q}%']*4)
            if reachability:where.append('reachability_state=?');args.append(reachability)
            if min_likelihood:where.append('calibrated_likelihood>=?');args.append(min_likelihood)
            if min_evidence:where.append('evidence_strength>=?');args.append(min_evidence)
            if min_exploitability:where.append('exploitability_confidence>=?');args.append(min_exploitability)
            if min_investigation:where.append('investigation_value>=?');args.append(min_investigation)
            order={'investigation':'investigation_value DESC,calibrated_likelihood DESC','likelihood':'calibrated_likelihood DESC,evidence_strength DESC','evidence':'evidence_strength DESC,investigation_value DESC','exploitability':'exploitability_confidence DESC,impact_potential DESC','impact':'impact_potential DESC,investigation_value DESC','updated':'updated_at DESC,investigation_value DESC'}.get(sort,'investigation_value DESC,calibrated_likelihood DESC')
            rows=[dict(r) for r in db.all(f"SELECT * FROM bug_candidates WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 500",args)] if analysis_id else []
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM bug_candidates WHERE analysis_id=? ORDER BY target",(analysis_id,))] if analysis_id else []
            families=[str(r[0]) for r in db.all("SELECT DISTINCT bug_family FROM bug_candidates WHERE analysis_id=? ORDER BY bug_family",(analysis_id,))] if analysis_id else []
            reachabilities=[str(r[0]) for r in db.all("SELECT DISTINCT reachability_state FROM bug_candidates WHERE analysis_id=? ORDER BY reachability_state",(analysis_id,))] if analysis_id else []
            counts=db.one("SELECT COUNT(*) total,SUM(candidate_state='strong_candidate') strong,SUM(candidate_state='plausible') plausible,SUM(analyst_decision='unreviewed') unreviewed FROM bug_candidates WHERE analysis_id=?",(analysis_id,)) if analysis_id else None
        finally: db.close()
        total=int(counts['total'] or 0) if counts else 0; strong=int(counts['strong'] or 0) if counts else 0; plausible=int(counts['plausible'] or 0) if counts else 0; unreviewed=int(counts['unreviewed'] or 0) if counts else 0
        shared=dict(target=target,family=family,state=state,decision=decision,q=q,reachability=reachability,min_likelihood=min_likelihood,min_evidence=min_evidence,min_exploitability=min_exploitability,min_investigation=min_investigation,sort=sort,view=view)
        toggle_url=_query_link('/potential-findings',display='table' if display!='table' else 'cards',**shared)
        toggle_label='Table view' if display!='table' else 'Card view'
        header=_breadcrumb(('Analysis','/analysis'),'Potential findings')+_page_header('Potential findings','Reviewed analysis output where a probable security issue is worth analyst attention. These are not confirmed vulnerabilities until validated.',f"<a class='button secondary' href='{toggle_url}'>{toggle_label}</a><a class='button' href='/workbench'>Review queue</a>",'03 · Investigate · probability, not proof')
        sort_pairs=[('investigation','Investigation value'),('likelihood','Likelihood'),('evidence','Evidence strength'),('exploitability','Exploitability'),('impact','Impact potential'),('updated','Recently updated')]
        fields=f"<label class='filter-wide'>Search candidates<input name='q' value='{_esc(q)}' placeholder='Title, endpoint or summary'></label><label>View{_select_pairs('view',[('actionable','Actionable'),('strong','Strong / confirmed'),('needs_review','Needs review'),('needs_evidence','Needs evidence'),('all','All candidates')],view,'Actionable')}</label><label>Target{_select('target',targets,target,'All targets')}</label><label>Bug family{_select('family',families,family,'All families')}</label><label>State{_select('state',['weak_signal','insufficient_evidence','possible','plausible','strong_candidate','confirmed_by_analyst','rejected'],state,'Any state')}</label><label>Decision{_select('decision',ANALYST_DECISIONS,decision,'Any decision')}</label><label>Reachability{_select('reachability',reachabilities,reachability,'Any reachability')}</label><label>Likelihood ≥<input type='number' name='min_likelihood' min='0' max='100' value='{min_likelihood or ''}'></label><label>Evidence ≥<input type='number' name='min_evidence' min='0' max='100' value='{min_evidence or ''}'></label><label>Exploitability ≥<input type='number' name='min_exploitability' min='0' max='100' value='{min_exploitability or ''}'></label><label>Investigation ≥<input type='number' name='min_investigation' min='0' max='100' value='{min_investigation or ''}'></label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Investigation value')}</label><input type='hidden' name='display' value='{_esc(display)}'>"
        view_labels={'actionable':'Actionable','strong':'Strong / confirmed','needs_review':'Needs review','needs_evidence':'Needs evidence','all':'All candidates'}
        controls=_filter_panel(fields,{'View':view_labels.get(view,view),'Search':q,'Target':target,'Family':family,'State':state,'Decision':decision,'Reachability':reachability,'Likelihood ≥':min_likelihood,'Evidence ≥':min_evidence,'Exploitability ≥':min_exploitability,'Investigation ≥':min_investigation,'Sort':dict(sort_pairs).get(sort,'') if sort!='investigation' else ''},'/potential-findings?view=actionable',title='Potential finding search & filters',result_count=len(rows))
        presets=_quick_views([('Actionable','/potential-findings?view=actionable',view=='actionable'),('Strong','/potential-findings?view=strong',view=='strong'),('Needs review','/potential-findings?view=needs_review',view=='needs_review'),('Needs evidence','/potential-findings?view=needs_evidence',view=='needs_evidence'),('All','/potential-findings?view=all',view=='all')])
        metrics="<div class='attention-grid'>"+_attention_item('All candidates',total,'Latest completed analysis','/potential-findings','info')+_attention_item('Strong',strong,'Highest-priority review set','/potential-findings?state=strong_candidate','danger')+_attention_item('Plausible',plausible,'Worth analyst attention','/potential-findings?state=plausible','orange')+_attention_item('Unreviewed',unreviewed,'No decision recorded','/potential-findings?decision=unreviewed','amber')+'</div>'
        if display=='table':
            table=[]
            for r in rows:
                link=f"/bug-candidate?id={urllib.parse.quote(str(r['candidate_id']))}"
                table.append(f"<tr><td><a class='row-link' href='{link}'>{_esc(r['title'])}</a><br><code>{_esc(r['endpoint'] or r['source_ref'])}</code></td><td>{_esc(r['target'])}</td><td>{_pill(r['candidate_state'])}</td><td>{_pill(r.get('reachability_state','unknown'))}</td><td>{r.get('calibrated_likelihood',r['likelihood_score'])} / {r['evidence_strength']} / {r.get('exploitability_confidence',0)} / {r['impact_potential']}</td><td><strong>{r.get('investigation_value',r['priority_score'])}</strong></td><td>{_pill(r['analyst_decision'])}</td></tr>")
            content=f"<div class='table-wrap' style='margin-top:16px'><table><thead><tr><th>Candidate</th><th>Target</th><th>State</th><th>Reachability</th><th>L / E / X / I</th><th>Investigation</th><th>Decision</th></tr></thead><tbody>{''.join(table) or '<tr><td colspan=7>No candidates match this view</td></tr>'}</tbody></table></div>"
        else:
            content=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Ranked candidates</h3><span class='muted small'>{len(rows)} shown</span></div>{''.join(_candidate_card(r) for r in rows) or _empty('No candidates match this view')}</section>"
        self.send_html('Potential findings',header+presets+metrics+controls+content)

    def bug_candidate_detail(self) -> None:
        candidate_id=str((self.query().get('id') or [''])[0]); db=self.db()
        try:
            row=db.one("SELECT * FROM bug_candidates WHERE candidate_id=?",(candidate_id,))
            if not row: self.send_html('Not found',_empty('Bug candidate not found'),404); return
            candidate=dict(row)
            alert=db.one("SELECT id,title,item,severity,status,risk_score FROM alerts WHERE id=?",(candidate['alert_id'],)) if candidate['alert_id'] is not None else None
            dossier=build_evidence_dossier(db,candidate_id)
        finally: db.close()
        supporting=dossier['supporting']; contradicting=dossier['contradicting']; excluded=dossier['excluded']; groups=dossier['groups']; reasoning=dossier['reasoning']; ranked_families=dossier['family_rankings']; confidence=dossier['confidence']; integrity=dossier['integrity']; timeline=dossier['timeline']; history=dossier['history']; versions=dossier['versions']
        missing=_json(candidate['missing_evidence_json'],[]) or [str(x.get('fact')) for x in _json(candidate.get('unknowns_json','[]'),[]) if isinstance(x,Mapping) and x.get('fact')]
        actions="<a class='button ghost' href='/potential-findings'>← Potential Findings</a>"+(f"<a class='button secondary' href='/alert?id={int(candidate['alert_id'])}'>Open source alert</a>" if candidate['alert_id'] is not None else '')
        header=_breadcrumb(('Potential Findings','/potential-findings'),'Evidence dossier')+_page_header(candidate['title'],candidate['summary'],actions,f"{candidate['target']} · {candidate['bug_family']} · UNVERIFIED")
        analysis_quality=parse_int(confidence.get('analysis_quality'),0)
        scores="<div class='metrics-grid'>"+''.join([
            _metric_card('Likelihood',f"{candidate.get('calibrated_likelihood',candidate['likelihood_score'])}%",'Calibrated hypothesis likelihood — not confirmation','orange'),
            _metric_card('Evidence strength',f"{candidate['evidence_strength']}%",f"{len(groups)} independent source group(s)",'blue'),
            _metric_card('Analysis quality',f"{analysis_quality}%",'Observation quality plus evidence coverage','success' if analysis_quality>=70 else 'amber'),
            _metric_card('Investigation value',candidate.get('investigation_value',candidate['priority_score']),'Priority for analyst review','purple'),
        ])+"</div>"
        audit_tone='success' if integrity.get('status')=='verified' else 'amber'
        audit_summary=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Evidence Dossier</h3>{_pill('audit '+str(integrity.get('status')),audit_tone)}</div><div class='panel-body'><div class='attention-grid'>"+''.join([
            f"<div class='attention-card'><span>Evidence used</span><strong>{len(supporting)+len(contradicting)}</strong><small>{len(supporting)} supporting · {len(contradicting)} contradicting</small></div>",
            f"<div class='attention-card'><span>Independent groups</span><strong>{len(groups)}</strong><small>correlated signals are not double-counted</small></div>",
            f"<div class='attention-card'><span>Suppressed signals</span><strong>{len(excluded)}</strong><small>excluded with a recorded reason</small></div>",
            f"<div class='attention-card'><span>Snapshot integrity</span><strong>{integrity.get('verified',0)}/{integrity.get('snapshots',0)}</strong><small>source snapshots verified</small></div>",
        ])+"</div><div class='callout' style='margin-top:14px'><strong>No conclusion without traceable evidence</strong><span>Every assertion promoted here must resolve to a stored evidence record and, where available, an immutable source snapshot. Internal chain-of-thought is never exposed; only audit-grade facts, provenance, alternatives, contradictions and uncertainty are shown.</span></div></div></section>"
        support_html=''.join(_audit_evidence_item(x,'support') for x in supporting) or _empty('No supporting evidence')
        against_html=''.join(_audit_evidence_item(x,'contradict') for x in contradicting) or _empty('No contradicting evidence','No contradiction recorded does not confirm the hypothesis.')
        missing_html=''.join(f"<li>{_esc(x.get('fact') if isinstance(x,Mapping) else x)}</li>" for x in missing) or '<li>No missing-evidence checklist recorded.</li>'
        evidence_section=f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Supporting evidence</h3><span class='muted small'>{len(supporting)} independent records</span></div><div class='panel-body evidence-feed'>{support_html}</div></section><section class='panel'><div class='panel-head'><h3>Contradicting evidence</h3><span class='muted small'>{len(contradicting)} independent records</span></div><div class='panel-body evidence-feed'>{against_html}</div></section></div>"
        gaps=f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Critical missing evidence</h3></div><div class='panel-body'><ul>{missing_html}</ul><p class='muted small'>Unknown is not negative evidence. Missing server-side facts limit confidence and may cause the engine to abstain.</p></div></section><section class='panel'><div class='panel-head'><h3>Safe next investigation</h3></div><div class='panel-body'><div class='callout'><strong>Authorized review only</strong><span>{_esc(candidate['safe_next_action'])}</span></div></div></section></div>"
        exclusion_html=''.join(_audit_exclusion_item(x) for x in excluded) or _empty('No evidence was suppressed','The current evidence set contains no correlated duplicates that were discarded.')
        group_rows=''.join(f"<tr><td>{_esc(group)}</td><td>{len(ids)}</td><td>{' '.join(f'<code>{_esc(i[:8])}</code>' for i in ids)}</td></tr>" for group,ids in sorted(groups.items()))
        groups_section=f"<details style='margin-top:16px'><summary>Evidence independence & excluded signals</summary><section class='panel' style='margin-top:10px'><div class='panel-head'><h3>Independent evidence groups</h3><span class='muted small'>Multiple signals from one root count once</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Source group</th><th>Evidence</th><th>Records</th></tr></thead><tbody>{group_rows or '<tr><td colspan=3>No groups</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:10px'><div class='panel-head'><h3>Excluded / suppressed evidence</h3><span class='muted small'>{len(excluded)} signal(s)</span></div><div class='panel-body evidence-feed'>{exclusion_html}</div></section></details>"
        falsification=reasoning.get('falsification',{}) if isinstance(reasoning,Mapping) else {}
        alternatives=[r for r in ranked_families if parse_int(r.get('rank'),0)>1]
        alt_html=''.join(f"<li><strong>{_esc(r.get('bug_family'))}</strong> — score {_esc(r.get('score'))}</li>" for r in alternatives) or '<li>No material alternative family outranked the current hypothesis.</li>'
        wrong_html=''.join(f"<li>{_esc(x)}</li>" for x in (falsification.get('why_it_may_be_wrong') or [])) or '<li>No structured contradiction explanation recorded.</li>'
        reject_html=''.join(f"<li>{_esc(x)}</li>" for x in (falsification.get('would_reject') or [])) or '<li>No formal rejection condition recorded.</li>'
        confidence_rows=''.join(f"<tr><td>{_esc(label)}</td><td><strong>{_esc(value)}</strong></td></tr>" for label,value in [
            ('Calibrated likelihood',str(confidence.get('calibrated_likelihood',0))+'%'),('Evidence strength',str(confidence.get('evidence_strength',0))+'%'),('Observation quality',str(confidence.get('observation_quality',0))+'%'),('Evidence coverage',str(confidence.get('evidence_coverage',0))+'%'),('Exploitability confidence',str(confidence.get('exploitability_confidence',0))+'%'),('Independent groups',confidence.get('independent_evidence_groups',0)),('Contradicting evidence',confidence.get('contradicting_evidence',0))])
        reasoning_section=f"<details style='margin-top:16px'><summary>Structured reasoning, alternatives & confidence</summary><div class='two-col' style='margin-top:10px'><section class='panel'><div class='panel-head'><h3>Why this may be wrong</h3></div><div class='panel-body'><ul>{wrong_html}</ul><h4>Alternative explanations / families</h4><ul>{alt_html}</ul><h4>What would reject it</h4><ul>{reject_html}</ul></div></section><section class='panel'><div class='panel-head'><h3>Confidence breakdown</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><tbody>{confidence_rows}</tbody></table></div></section></div></details>"
        timeline_rows=''.join(f"<tr><td>{_esc(x.get('at'))}</td><td>{_pill(x.get('kind'))}</td><td>{_esc(x.get('title'))}</td><td><code>{_esc(x.get('source_run_id') or x.get('evidence_id') or '')}</code></td></tr>" for x in timeline[-100:])
        history_rows=''.join(f"<tr><td>{_esc(x.get('finished_at') or x.get('updated_at'))}</td><td><code>{_esc(x.get('source_run_id'))}</code></td><td>{_esc(x.get('calibrated_likelihood'))}%</td><td>{_esc(x.get('evidence_strength'))}%</td><td>{_esc(x.get('evidence_coverage'))}%</td><td>{_pill(x.get('candidate_state'))}</td></tr>" for x in history)
        version_rows=''.join(f"<tr><td>v{_esc(x.get('version'))}</td><td>{_esc(x.get('engine_version'))} / {_esc(x.get('rule_version'))}</td><td><code>{_esc(str(x.get('analysis_snapshot_hash') or '')[:16])}</code></td><td>{_esc(x.get('created_at'))}</td></tr>" for x in versions)
        chronology=f"<details style='margin-top:16px'><summary>Timeline & analysis history</summary><section class='panel' style='margin-top:10px'><div class='panel-head'><h3>Evidence timeline</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>When</th><th>Type</th><th>Event</th><th>Reference</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan=4>No timeline</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:10px'><div class='panel-head'><h3>Cross-run analysis history</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>When</th><th>Run</th><th>Likelihood</th><th>Evidence</th><th>Coverage</th><th>State</th></tr></thead><tbody>{history_rows or '<tr><td colspan=6>No historical analyses</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:10px'><div class='panel-head'><h3>Immutable dossier versions</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Version</th><th>Engine / rules</th><th>Snapshot hash</th><th>Created</th></tr></thead><tbody>{version_rows or '<tr><td colspan=4>No version snapshot</td></tr>'}</tbody></table></div></section></details>"
        decision_options=''.join(f"<option value='{_esc(x)}'{' selected' if x==candidate['analyst_decision'] else ''}>{_esc(x.replace('_',' '))}</option>" for x in ANALYST_DECISIONS)
        reason_options=''.join(f"<option value='{_esc(x)}'{' selected' if x==candidate.get('feedback_reason','') else ''}>{_esc(x.replace('_',' ') or '— select reason —')}</option>" for x in FEEDBACK_REASON_CODES)
        decision_form=f"<section class='panel'><div class='panel-head'><h3>Analyst decision</h3>{_pill(candidate['analyst_decision'])}</div><div class='panel-body'><form method='post' action='/bug-candidates/decision'><input type='hidden' name='candidate_id' value='{_esc(candidate_id)}'><input type='hidden' name='return' value='{_esc(self.path)}'><label>Decision<br><select name='decision'>{decision_options}</select></label><label>Reason code<br><select name='reason'>{reason_options}</select></label><label>Evidence-backed note<br><textarea name='note' placeholder='Why was this candidate confirmed, rejected, or left pending?'>{_esc(candidate['analyst_note'])}</textarea></label><button>Save decision</button></form></div></section>"
        context=f"<section class='panel'><div class='panel-head'><h3>Audit facts</h3></div><div class='panel-body kv'><strong>Status</strong><span>{_pill('Unverified')}</span><strong>Candidate state</strong><span>{_pill(candidate['candidate_state'])}</span><strong>Preconditions</strong><span>{_pill(candidate.get('precondition_state','unknown'))}</span><strong>Reachability</strong><span>{_pill(candidate.get('reachability_state','unknown'))}</span><strong>Endpoint</strong><code>{_esc(candidate['endpoint'] or '—')}</code><strong>Analysis</strong><code>{_esc(candidate['analysis_id'])}</code><strong>Source run</strong><code>{_esc(candidate['source_run_id'])}</code><strong>Rule version</strong><code>{_esc(candidate['rule_version'])}</code></div></section>"
        alert_context=f"<div class='callout' style='margin-top:16px'><strong>Source alert #{int(alert['id'])}: {_esc(alert['title'])}</strong><span class='muted'>{_esc(alert['item'])} · {_esc(alert['severity'])} · risk {alert['risk_score']} · {_esc(alert['status'])}</span></div>" if alert else ''
        main=header+scores+audit_summary+alert_context+evidence_section+gaps+groups_section+reasoning_section+chronology
        body=main+f"<div class='two-col' style='margin-top:16px'><main><details><summary>Engine metadata</summary><pre>{_esc(json_dumps({'analysis':dossier.get('analysis',{}),'reasoning_version':reasoning.get('engine_version') if isinstance(reasoning,Mapping) else '', 'rule_version':reasoning.get('rule_version') if isinstance(reasoning,Mapping) else ''},pretty=True))}</pre></details></main><aside class='stack'>{decision_form}{context}</aside></div>"
        self.send_html("Potential Finding · Evidence Dossier",body)

    def security_reasoning_page(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            data=reasoning_summary(db,analysis_id) if analysis_id else {}
            calibration=family_calibration_report(db)
            top=[dict(r) for r in db.all("SELECT * FROM bug_candidates WHERE analysis_id=? ORDER BY investigation_value DESC LIMIT 30",(analysis_id,))] if analysis_id else []
        finally: db.close()
        counts=data.get('counts',{})
        cards="<div class='metrics-grid'>"+_metric_card('Candidates',counts.get('total',0),'Latest completed analysis','blue')+_metric_card('Strong',counts.get('strong',0),'Passed family preconditions and evidence gates','danger')+_metric_card('Insufficient evidence',counts.get('insufficient',0),'Missing required security preconditions','amber')+_metric_card('Average exploitability',f"{counts.get('avg_exploitability',0) or 0}%",'Separate from bug likelihood','orange')+_metric_card('Evidence coverage',f"{counts.get('avg_coverage',0) or 0}%",'Required, supporting and falsification coverage','purple')+"</div>"
        family_rows=''.join(f"<tr><td>{_esc(r.get('bug_family'))}</td><td>{r.get('count')}</td><td>{r.get('likelihood')}</td><td>{r.get('exploitability')}</td><td>{r.get('coverage')}</td></tr>" for r in data.get('families',[]))
        calibration_rows=''.join(f"<tr><td>{_esc(r.get('target'))}</td><td>{_esc(r.get('family'))}</td><td>{r.get('samples')}</td><td>{r.get('average_predicted')}</td><td>{r.get('observed_useful_rate')}</td><td>{_pill(r.get('status'))}</td></tr>" for r in calibration.get('families',[]))
        items=''.join(_candidate_card(r,compact=True) for r in top)
        body=_page_header('Security reasoning','Evidence provenance, family-specific preconditions, falsification, formal unknowns, calibrated Top-3 ranking and exploitability confidence.',"<a class='button secondary' href='/candidate-quality'>Quality</a><a class='button' href='/bug-candidates'>Candidates</a>",'Security Reasoning Core 4.6')+cards+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Family performance</h3></div><div class='table-wrap'><table><thead><tr><th>Family</th><th>Count</th><th>Likelihood</th><th>Exploitability</th><th>Coverage</th></tr></thead><tbody>{family_rows or '<tr><td colspan=5>No reasoning results</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Evaluation</h3></div><div class='panel-body'><pre>{_esc(json_dumps(data.get('evaluation',{}),pretty=True))}</pre></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Family calibration</h3></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Family</th><th>Samples</th><th>Predicted</th><th>Observed useful</th><th>Status</th></tr></thead><tbody>{calibration_rows or '<tr><td colspan=6>No reviewed or gold-labelled samples yet</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Highest investigation value</h3></div>{items or _empty('No candidates')}</section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Shadow rules</h3></div><div class='panel-body'><pre>{_esc(json_dumps(data.get('shadow_rules',{}),pretty=True))}</pre></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Regression gate</h3></div><div class='panel-body'><pre>{_esc(json_dumps(data.get('regression_gate',{}),pretty=True))}</pre></div></section>"
        self.send_html('Security reasoning',body)

    def candidate_quality_page(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            evaluation=candidate_evaluation(db,analysis_id) if analysis_id else {}
            calibration=candidate_calibration(db)
            profiles=db.all("SELECT analysis_profile,COUNT(*) count,ROUND(AVG(observation_quality),1) observation,ROUND(AVG(investigation_value),1) investigation FROM bug_candidates WHERE analysis_id=? GROUP BY analysis_profile",(analysis_id,)) if analysis_id else []
        finally: db.close()
        cards="<div class='metrics-grid'>"+_metric_card('Candidates',evaluation.get('candidates',0),'Latest analysis','blue')+_metric_card('Strong',evaluation.get('strong',0),'Strong or analyst-confirmed','danger')+_metric_card('Precision proxy',f"{float(evaluation.get('precision_proxy',0))*100:.1f}%",'Based on structured analyst decisions','success')+_metric_card('Independent sources',evaluation.get('average_independent_sources',0),'Average evidence source groups','purple')+"</div>"
        profile_rows=''.join(f"<tr><td>{_pill(r['analysis_profile'])}</td><td>{r['count']}</td><td>{r['observation']}%</td><td>{r['investigation']}</td></tr>" for r in profiles)
        family_rows=''.join(f"<tr><td>{_esc(family)}</td><td>{data.get('total')}</td><td>{data.get('reviewed')}</td><td>{data.get('average_predicted')}</td><td>{data.get('observed_confirmed_rate')}</td><td>{_pill(data.get('status'))}</td></tr>" for family,data in calibration.get('families',{}).items())
        body=_page_header("Candidate quality","Reliability, independent evidence, per-family calibration and structured evaluation.","<a class='button secondary' href='/bug-candidates'>Bug candidates</a>","Candidate Reliability Engine 4.2")+cards+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Analysis profiles</h3></div><div class='table-wrap'><table><thead><tr><th>Profile</th><th>Candidates</th><th>Observation quality</th><th>Investigation value</th></tr></thead><tbody>{profile_rows or '<tr><td colspan=4>No data</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Evaluation snapshot</h3></div><div class='panel-body'><pre>{_esc(json_dumps(evaluation,pretty=True))}</pre></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Per-family calibration</h3></div><div class='table-wrap'><table><thead><tr><th>Family</th><th>Total</th><th>Reviewed</th><th>Predicted</th><th>Observed confirmed</th><th>Status</th></tr></thead><tbody>{family_rows or '<tr><td colspan=6>No structured feedback yet</td></tr>'}</tbody></table></div></section>"
        self.send_html('Candidate quality',body)

    def candidate_bundles_page(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            rows=db.all("SELECT * FROM candidate_bundles WHERE analysis_id=? ORDER BY priority_score DESC",(latest['id'],)) if latest else []
        finally: db.close()
        items=[]
        for row in rows:
            members=_json(row['members_json'],[])
            links=' '.join(f"<a class='pill' href='/bug-candidate?id={urllib.parse.quote(str(member))}'>{_esc(str(member)[:8])}</a>" for member in members)
            items.append(f"<article class='card'><div class='split'><div><div class='eyebrow'>{_esc(row['target'])} · {_esc(row['primary_family'])}</div><h2>{_esc(row['title'])}</h2><p>{_esc(row['summary'])}</p></div><div class='risk-badge tone-orange'>{row['priority_score']}</div></div><div>{links}</div></article>")
        body=_page_header("Candidate bundles","Related bug-family hypotheses grouped around the same endpoint, alert or semantic boundary.","<a class='button secondary' href='/bug-candidates'>All candidates</a>","Semantic Candidate Intelligence 4.3")+(''.join(items) if items else _empty('No candidate bundles','Bundles appear when multiple bug-family hypotheses share the same boundary.'))
        self.send_html('Candidate bundles',body)

    def semantic_intelligence_page(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            units=db.all("SELECT * FROM semantic_js_units WHERE analysis_id=? ORDER BY confidence DESC LIMIT 500",(analysis_id,)) if analysis_id else []
            flags=db.all("SELECT * FROM feature_flags WHERE analysis_id=? ORDER BY confidence DESC LIMIT 300",(analysis_id,)) if analysis_id else []
            contracts=db.all("SELECT * FROM endpoint_contracts WHERE analysis_id=? ORDER BY confidence DESC LIMIT 500",(analysis_id,)) if analysis_id else []
            shapes=db.all("SELECT * FROM response_shape_fingerprints WHERE analysis_id=? ORDER BY confidence DESC LIMIT 300",(analysis_id,)) if analysis_id else []
        finally: db.close()
        unit_rows=''.join(f"<tr><td><code>{_esc(r['js_url'])}</code></td><td>{_pill(r['unit_type'])}</td><td><code>{_esc(_json(r['value_json'],{}).get('value',''))}</code></td><td>{_confidence(r['confidence'])}</td></tr>" for r in units)
        flag_rows=''.join(f"<tr><td>{_esc(r['flag_name'])}</td><td><code>{_esc(r['observed_value'])}</code></td><td><code>{_esc(r['js_url'])}</code></td><td>{_confidence(r['confidence'])}</td></tr>" for r in flags)
        contract_rows=''.join(f"<tr><td><code>{_esc(r['endpoint'])}</code></td><td>{_esc(r['method'])}</td><td>{_pill(r['auth_boundary'])}</td><td>{len(_json(r['output_fields_json'],[]))}</td><td>{_confidence(r['confidence'])}</td></tr>" for r in contracts)
        shape_rows=''.join(f"<tr><td><code>{_esc(r['endpoint'])}</code></td><td>{_esc(r['status_code'])}</td><td>{len(_json(r['keys_json'],[]))}</td><td>{len(_json(r['sensitive_keys_json'],[]))}</td><td>{_confidence(r['confidence'])}</td></tr>" for r in shapes)
        body=_page_header("Semantic intelligence","Feature flags, semantic JavaScript units, endpoint contracts, authentication boundaries and response shapes.","<a class='button secondary' href='/candidate-bundles'>Candidate bundles</a>","Semantic Candidate Intelligence 4.3")+f"<div class='two-col'><section class='panel'><div class='panel-head'><h3>Feature flags</h3></div><div class='table-wrap'><table><thead><tr><th>Flag</th><th>Value</th><th>JavaScript</th><th>Confidence</th></tr></thead><tbody>{flag_rows or '<tr><td colspan=4>No feature flags</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Response shapes</h3></div><div class='table-wrap'><table><thead><tr><th>Endpoint</th><th>Status</th><th>Keys</th><th>Sensitive</th><th>Confidence</th></tr></thead><tbody>{shape_rows or '<tr><td colspan=5>No response shapes</td></tr>'}</tbody></table></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Endpoint contracts</h3></div><div class='table-wrap'><table><thead><tr><th>Endpoint</th><th>Method</th><th>Authentication boundary</th><th>Output fields</th><th>Confidence</th></tr></thead><tbody>{contract_rows or '<tr><td colspan=5>No endpoint contracts</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Semantic JavaScript units</h3></div><div class='table-wrap'><table><thead><tr><th>JavaScript</th><th>Unit</th><th>Value</th><th>Confidence</th></tr></thead><tbody>{unit_rows or '<tr><td colspan=4>No semantic units</td></tr>'}</tbody></table></div></section>"
        self.send_html('Semantic intelligence',body)

    def behavioral_intelligence_page(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            data=behavioral_summary(db,analysis_id) if analysis_id else {}
        finally: db.close()
        counts=data.get('counts',{})
        boundary=data.get('boundary_diffs',[])
        shapes=data.get('response_shape_diffs',[])
        protocols=data.get('protocol_findings',[])
        relations=data.get('identity_relations',[])
        metrics="<div class='metrics-grid'>"+_metric_card('Boundary changes',counts.get('boundary_diffs',0),'Cross-run authentication boundary comparisons','orange')+_metric_card('Response diffs',counts.get('response_shape_diffs',0),'Redacted structural response comparisons','blue')+_metric_card('Protocol findings',counts.get('protocol_findings',0),'REST, GraphQL, WebSocket, OAuth/OIDC and cache','purple')+_metric_card('High priority',counts.get('high_priority',0),'Behavioral changes needing attention','danger')+_metric_card('Identity relations',counts.get('identity_relations',0),'Identity, tenant, role and object graph edges','success')+"</div>"
        boundary_rows=''.join(f"<tr><td><code>{_esc(r['endpoint'])}</code></td><td>{_pill(r['previous_boundary'])} → {_pill(r['current_boundary'])}</td><td>{_pill(r['transition'])}</td><td>{_pill(r['severity'])}</td><td>{_confidence(r['confidence'])}</td></tr>" for r in boundary if r.get('transition')!='stable')
        shape_rows=''.join(f"<tr><td><code>{_esc(r['endpoint'])}</code></td><td>{_pill(r['transition'])}</td><td>{len(_json(r['added_keys_json'],[]))}</td><td>{len(_json(r['sensitive_added_json'],[]))}</td><td>{_pill(r['severity'])}</td><td>{_confidence(r['confidence'])}</td></tr>" for r in shapes if r.get('transition')!='stable')
        protocol_rows=''.join(f"<tr><td>{_pill(r['protocol'])}</td><td><code>{_esc(r['entity'])}</code></td><td>{_esc(r['kind'].replace('_',' '))}</td><td>{_pill(r['severity'])}</td><td>{_confidence(r['confidence'])}</td><td>{_esc(r['summary'])}</td></tr>" for r in protocols)
        relation_rows=''.join(f"<tr><td>{_pill(r['source_type'])} <code>{_esc(r['source_value'])}</code></td><td>{_esc(r['relation'].replace('_',' '))}</td><td>{_pill(r['destination_type'])} <code>{_esc(r['destination_value'])}</code></td><td>{_confidence(r['confidence'])}</td></tr>" for r in relations[:300])
        header=_page_header('Behavioral intelligence','Offline comparison of stored authentication boundaries, response structures and protocol-specific evidence. No active validation is performed.',"<a class='button secondary' href='/bug-candidates'>Bug candidates</a>",'Behavioral Intelligence Engine 4.5')
        body=header+metrics+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Authentication boundary changes</h3></div><div class='table-wrap'><table><thead><tr><th>Endpoint</th><th>Transition</th><th>Type</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>{boundary_rows or '<tr><td colspan=5>No changed boundaries yet. Replay after another stored analysis to build history.</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Structural response changes</h3></div><div class='table-wrap'><table><thead><tr><th>Endpoint</th><th>Transition</th><th>Added</th><th>Sensitive</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>{shape_rows or '<tr><td colspan=6>No structural response changes yet.</td></tr>'}</tbody></table></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Protocol-specific findings</h3></div><div class='table-wrap'><table><thead><tr><th>Protocol</th><th>Entity</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>Summary</th></tr></thead><tbody>{protocol_rows or '<tr><td colspan=6>No protocol findings</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Identity and authorization graph</h3><span class='muted small'>{len(relations)} relation(s)</span></div><div class='table-wrap'><table><thead><tr><th>Source</th><th>Relation</th><th>Destination</th><th>Confidence</th></tr></thead><tbody>{relation_rows or '<tr><td colspan=4>No identity relations</td></tr>'}</tbody></table></div></section>"
        self.send_html('Behavioral intelligence',body)

    def hypotheses(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            rows=db.all("SELECT r.*,a.title,a.item,a.status,a.severity FROM analysis_results r JOIN alerts a ON a.id=r.alert_id WHERE r.analysis_id=? ORDER BY r.adjusted_score DESC,r.confidence DESC LIMIT 300",(latest['id'],)) if latest else []
        finally: db.close()
        items=[]
        for r in rows:
            supporting=_json(r['evidence_for_json'],[]); opposing=_json(r['evidence_against_json'],[]); schema=_json(r['endpoint_schema_json'],{})
            evidence_for="".join(f"<li><strong>{_esc(e.get('weight'))}</strong> {_esc(e.get('text'))}</li>" for e in supporting) or '<li>No positive evidence recorded</li>'
            evidence_against="".join(f"<li><strong>{_esc(e.get('weight'))}</strong> {_esc(e.get('text'))}</li>" for e in opposing) or '<li>No contradicting evidence recorded</li>'
            items.append(f"<article class='card'><div class='split'><div><div class='eyebrow'>Alert #{int(r['alert_id'])} · {_esc(r['business_context'])}</div><h2><a href='/alert?id={int(r['alert_id'])}'>{_esc(r['title'])}</a></h2><p>{_esc(r['hypothesis'])}</p></div><div>{_risk_meter(r['adjusted_score'])}</div></div><div class='two-col'><div><h3>Evidence for</h3><ul>{evidence_for}</ul></div><div><h3>Evidence against</h3><ul>{evidence_against}</ul></div></div><div class='callout'><strong>Next action:</strong> {_esc(r['next_action'])}</div><details><summary>Endpoint schema and temporal context</summary><pre>{_esc(json_dumps({'schema':schema,'temporal':_json(r['temporal_json'],{})},pretty=True))}</pre></details></article>")
        body=_page_header("Security hypotheses","Falsifiable, evidence-linked hypotheses. These are review candidates, not confirmed vulnerabilities.","<a class='button secondary' href='/analysis'>Analysis overview</a>","Hypothesis engine")+''.join(items) if items else _page_header("Security hypotheses","No analysis results are available yet.","<a class='button' href='/analysis'>Analysis overview</a>","Hypothesis engine")+_empty("No hypotheses","Run analysis on a completed recon run.")
        self.send_html("Hypotheses",body)

    def analysis_clusters(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            rows=db.all("SELECT c.*,a.title,a.target,a.category,a.risk_score FROM analysis_clusters c JOIN alerts a ON a.id=c.primary_alert_id WHERE c.analysis_id=? ORDER BY c.member_count DESC,a.risk_score DESC",(latest['id'],)) if latest else []
        finally: db.close()
        table="".join(f"<tr><td><code>{_esc(r['cluster_key'])}</code></td><td>{int(r['member_count'])}</td><td><a href='/alert?id={int(r['primary_alert_id'])}'>#{int(r['primary_alert_id'])} {_esc(r['title'])}</a></td><td>{_esc(r['target'])}</td><td>{_esc(r['category'])}</td><td><code>{_esc(r['members_json'])}</code></td></tr>" for r in rows)
        body=_page_header("Similarity clusters","Related alerts grouped by normalized endpoint, category and evidence structure.","<a class='button secondary' href='/analysis'>Analysis overview</a>","Duplicate engine")+f"<div class='card'><div class='table-wrap'><table><thead><tr><th>Cluster</th><th>Members</th><th>Primary</th><th>Target</th><th>Category</th><th>Alert IDs</th></tr></thead><tbody>{table or '<tr><td colspan=6>No clusters available</td></tr>'}</tbody></table></div></div>"
        self.send_html("Similarity clusters",body)

    def dataflows(self) -> None:
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            rows=db.all("SELECT * FROM js_dataflows WHERE analysis_id=? ORDER BY confidence DESC,js_url LIMIT 500",(latest['id'],)) if latest else []
            maps=db.all("SELECT * FROM source_map_intelligence WHERE analysis_id=? ORDER BY internal_source_count DESC LIMIT 100",(latest['id'],)) if latest else []
            secrets=db.all("SELECT * FROM secret_intelligence WHERE analysis_id=? ORDER BY confidence DESC LIMIT 100",(latest['id'],)) if latest else []
        finally: db.close()
        flow_rows="".join(f"<tr><td><code>{_esc(r['js_url'])}</code></td><td>{_pill(r['source_kind'],'blue')}</td><td>→</td><td>{_pill(r['sink_kind'],'purple')}</td><td>{_confidence(r['confidence'])}</td><td><code>{_esc(str(r['snippet'])[:600])}</code></td></tr>" for r in rows)
        map_rows="".join(f"<tr><td><code>{_esc(r['js_url'])}</code></td><td><code>{_esc(r['source_map_url'])}</code></td><td>{int(r['source_count'])}</td><td>{int(r['internal_source_count'])}</td></tr>" for r in maps)
        secret_rows="".join(f"<tr><td><code>{_esc(r['js_url'])}</code></td><td>{_esc(r['secret_kind'])}</td><td>{_esc(r['assessment'])}</td><td>{_confidence(r['confidence'])}</td><td><code>{_esc(r['value_fingerprint'])}</code></td></tr>" for r in secrets)
        body=_page_header("JavaScript intelligence","Static source-to-sink candidates, source-map context and secret confidence. Static matches require human verification.","<a class='button secondary' href='/javascript'>JavaScript inventory</a>","Code and data-flow analysis")+f"<div class='card'><h2>Data-flow candidates</h2><div class='table-wrap'><table><thead><tr><th>JavaScript</th><th>Source</th><th></th><th>Sink</th><th>Confidence</th><th>Context</th></tr></thead><tbody>{flow_rows or '<tr><td colspan=6>No data-flow candidates</td></tr>'}</tbody></table></div></div><div class='two-col'><div class='card'><h2>Source maps</h2><table><thead><tr><th>JavaScript</th><th>Map</th><th>Sources</th><th>Internal</th></tr></thead><tbody>{map_rows or '<tr><td colspan=4>No source-map intelligence</td></tr>'}</tbody></table></div><div class='card'><h2>Secret candidates</h2><table><thead><tr><th>JavaScript</th><th>Kind</th><th>Assessment</th><th>Confidence</th><th>Fingerprint</th></tr></thead><tbody>{secret_rows or '<tr><td colspan=5>No secret candidates</td></tr>'}</tbody></table></div></div>"
        self.send_html("JavaScript intelligence",body)

    def analysis_quality_page(self) -> None:
        db=self.db()
        try:
            quality=analysis_quality(db); calibration=calibration_report(db)
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            playbooks=PLAYBOOKS
        finally: db.close()
        buckets=calibration.get('buckets',{})
        bucket_rows="".join(f"<tr><td>{_esc(name)}</td><td>{int(value.get('count',0))}</td><td>{float(value.get('observed_useful_rate',0)):.1%}</td><td>{float(value.get('expected_midpoint',0)):.0%}</td><td>{_pill(value.get('status'))}</td></tr>" for name,value in buckets.items())
        category_rows="".join(f"<tr><td>{_esc(category)}</td><td><code>{_esc(json_dumps(states))}</code></td></tr>" for category,states in quality.get('categories',{}).items())
        playbook_cards="".join(f"<div class='card'><h3>{_esc(value['title'])}</h3><ol>{''.join(f'<li>{_esc(check)}</li>' for check in value['checks'])}</ol></div>" for value in playbooks.values())
        cards="".join([_metric_card("Precision proxy",f"{quality.get('precision_proxy',0):.1%}","Useful / useful + noisy","success"),_metric_card("False-positive proxy",f"{quality.get('false_positive_proxy',0):.1%}","Based on analyst workflow states","orange"),_metric_card("Backlog",quality.get('unreviewed_backlog',0),"New through investigating","blue"),_metric_card("Latest analysis",latest['id'] if latest else '—',"Replay-safe and versioned","purple")])
        body=_page_header("Analysis quality","Calibration, feedback outcomes, noisy categories and analyst playbooks.","<a class='button secondary' href='/analysis'>Analysis overview</a>","Engine observability")+f"<div class='metrics-grid'>{cards}</div><div class='two-col'><div class='card'><h2>Confidence calibration</h2><table><thead><tr><th>Bucket</th><th>Decisions</th><th>Observed useful</th><th>Expected</th><th>Status</th></tr></thead><tbody>{bucket_rows}</tbody></table></div><div class='card'><h2>Category outcomes</h2><table><thead><tr><th>Category</th><th>Workflow outcomes</th></tr></thead><tbody>{category_rows or '<tr><td colspan=2>No reviewed alerts yet</td></tr>'}</tbody></table></div></div><h2>Review playbooks</h2><div class='card-grid'>{playbook_cards}</div>"
        self.send_html("Analysis quality",body)

    def incidents(self) -> None:
        db=self.db()
        try: rows=db.all("SELECT * FROM change_incidents ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,risk_score DESC,last_seen DESC LIMIT 500")
        finally: db.close()
        header=_page_header("Correlated incidents", "Related changes grouped into analyst-sized events instead of isolated notifications.", "<a class='button' href='/workbench'>Open workbench</a>", "Change correlation")
        cards=[]
        for r in rows:
            details = _json(r['details_json'], {})
            summary = details.get("summary", "")
            summary_html = f"<p class='muted'>{_esc(summary)}</p>" if summary else ""
            cards.append(f"<article class='card'><div style='display:flex;justify-content:space-between;gap:10px'><div>{_pill(r['severity'])} {_pill(r['status'])}</div><strong class='tone-{_tone(r['severity'])}'>{r['risk_score']}</strong></div><h3 style='margin-top:14px'>{_esc(r['title'])}</h3><div class='queue-meta'><span>{_esc(r['target'])}</span><span>{r['event_count']} events</span><span>{_esc(r['last_seen'])}</span></div>{summary_html}</article>")
        self.send_html("Incidents",header+("<div class='three-col'>"+''.join(cards)+"</div>" if cards else _empty('No correlated incidents','Changes will appear here when correlation rules group related observations.')))

    def lifecycle(self) -> None:
        db=self.db()
        try: rows=db.all("SELECT l.*,a.confidence,a.resolved FROM asset_lifecycle l LEFT JOIN assets a ON a.target=l.target AND a.host=l.host ORDER BY l.last_seen DESC LIMIT 1000")
        finally: db.close()
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td><a class='row-link mono' href='/asset?target={urllib.parse.quote(str(r['target']))}&host={urllib.parse.quote(str(r['host']))}'>{_esc(r['host'])}</a></td><td>{_pill(r['state'])}</td><td>{_confidence(r['confidence'] or 0)}</td><td>{_pill('resolved','success') if r['resolved'] else _pill('unresolved','neutral')}</td><td>{_esc(r['first_seen'])}</td><td>{_esc(r['last_seen'])}</td><td>{r['transitions']}</td></tr>" for r in rows)
        header=_page_header("Asset lifecycle", "Track when assets appear, disappear, retire, or return to the attack surface.", eyebrow="Historical intelligence")
        self.send_html("Asset lifecycle",header+f"<div class='table-wrap'><table><thead><tr><th>Target</th><th>Host</th><th>State</th><th>Confidence</th><th>Resolution</th><th>First</th><th>Last</th><th>Transitions</th></tr></thead><tbody>{body or '<tr><td colspan=8>No lifecycle data</td></tr>'}</tbody></table></div>")

    def views(self) -> None:
        db=self.db()
        try: rows=db.all("SELECT * FROM saved_views ORDER BY owner,name")
        finally: db.close()
        body=''.join(f"<tr><td>{_esc(r['owner'])}</td><td>{_esc(r['name'])}</td><td>{_esc(r['view_type'])}</td><td><code>{_esc(r['query_json'])}</code></td><td>{_esc(r['updated_at'])}</td></tr>" for r in rows)
        self.send_html("Saved views",f"<h1>Saved views</h1><p>Views can be created with the CLI or local API.</p><table><thead><tr><th>Owner</th><th>Name</th><th>Type</th><th>Query</th><th>Updated</th></tr></thead><tbody>{body or '<tr><td colspan=5>No saved views</td></tr>'}</tbody></table>")

    def overview(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        runtime_paths = getattr(self, 'paths', AppPaths.from_root(Path(self.db_path).resolve().parent.parent))
        runtime_config = getattr(self, 'config', Config(runtime_paths))
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT target FROM (SELECT DISTINCT target FROM security_cases UNION SELECT DISTINCT target FROM alerts UNION SELECT DISTINCT target FROM assets UNION SELECT DISTINCT target FROM run_targets) ORDER BY target")]
            # Keep the post-login Command Center on a bounded, DB-only fast path.
            # Deep diagnostics, safety/audit verification, coverage reconstruction and
            # target-memory synthesis remain available from their dedicated pages.
            snapshot=_command_center_snapshot(db,target)
        finally: db.close()
        data=snapshot['cockpit']; latest_run=snapshot['latest_run']; latest_analysis=snapshot['latest_analysis']; decisions=snapshot['decisions']; changes=snapshot['changes']; next_action=snapshot['next_action']
        controls=f"<form class='filters'><label>Focus target<br>{_select('target',targets,target,'All targets')}</label><button>Apply focus</button><a class='button ghost' href='/'>Clear</a></form>"
        header=_breadcrumb('Workspace','Command Center')+_page_header('Command Center','A decision-first view of what changed, what deserves attention, and the single best next action.',"<form method='post' action='/workspace/sync' style='display:inline'><input type='hidden' name='target' value='"+_esc(target)+"'><input type='hidden' name='return' value='/'><button>Refresh intelligence</button></form><a class='button secondary' href='/search?q=*'>Search workspace</a>",f'Recon Monitor {APP_VERSION} · Decision workspace')
        focus_name=_esc(target) if target else 'All authorized targets'
        hero=f"<section class='workspace-hero'><div class='workspace-hero-copy'><small>Command Center 2.0 · Decision inbox · Security stories · Coverage snapshot</small><strong>{focus_name}</strong><p>Start with the highest-value decision. Recon, analysis, findings and change intelligence stay connected, while low-value inventory stays out of the way.</p></div><div class='workspace-hero-status'><span class='status-dot'></span><span>Workspace</span><strong>FAST VIEW</strong></div></section>"
        kpis="<div class='command-kpi-row'>"+_attention_item('Decisions now',len(decisions),'Ranked actions worth analyst attention','/workbench','info')+_attention_item('High-interest changes',snapshot['high_changes'],'Material changes since the latest baseline',_query_link('/alerts',target=target),'danger')+_attention_item('High-value findings',data['high_value_candidates'],'Unreviewed candidates with priority ≥70',_query_link('/potential-findings',target=target),'orange')+_attention_item('Evidence gaps',data['needs_evidence'],'Cases blocked by missing observations',_query_link('/evidence-gaps',target=target),'amber')+'</div>'
        decision_html=''.join(_command_decision_item(item,idx) for idx,item in enumerate(decisions,1))
        inbox=f"<section class='panel'><div class='panel-head'><div><h3>What needs your attention?</h3><span class='muted small'>Decision inbox · ranked across run health, potential findings, open cases and material surface changes.</span></div><a class='small' href='/workbench'>Full review queue →</a></div><div class='panel-body command-decision-list'>{decision_html or _empty('Nothing urgent is competing for attention','Refresh workspace intelligence or run the next authorized recon.')}</div></section>"
        action=f"<section class='command-primary-action'><small>{_esc(next_action.get('eyebrow') or 'Next best action')}</small><h2>{_esc(next_action.get('title'))}</h2><p>{_esc(next_action.get('detail'))}</p><a class='button' href='{_esc(next_action.get('href') or '/')}'>Open next action →</a></section>"
        latest_run_label=str(latest_run.get('status')) if latest_run else 'No run yet'; latest_run_meta=(str(latest_run.get('finished_at') or latest_run.get('started_at') or '') if latest_run else 'Create a baseline to unlock change intelligence')
        latest_analysis_label=str(latest_analysis.get('id')) if latest_analysis else 'No analysis'; latest_analysis_meta=(str(latest_analysis.get('finished_at') or latest_analysis.get('started_at') or '') if latest_analysis else 'Analysis will appear after collected evidence is processed')
        pulse_rows=[
            ('Latest recon',latest_run_label,latest_run_meta),
            ('Latest analysis',latest_analysis_label,latest_analysis_meta),
            ('Platform health','ON DEMAND','Open Diagnostics for a full subsystem check'),
            ('Safety gate','ON DEMAND','Open Safety Center for authorization, scope and audit integrity'),
        ]
        pulse=''.join(f"<div class='pulse-row'><div><span>{_esc(label)}</span><small>{_esc(detail)}</small></div><b>{_esc(value)}</b></div>" for label,value,detail in pulse_rows)
        side=f"<aside class='stack'>{action}<section class='panel'><div class='panel-head'><h3>Workspace pulse</h3><a class='small' href='/diagnostics'>Diagnostics</a></div><div class='panel-body command-pulse'>{pulse}</div></section></aside>"
        change_cards=[]
        for event in changes[:6]:
            tone='danger' if event.get('priority')=='high' else 'amber' if event.get('priority')=='medium' else 'neutral'
            change_cards.append(f"<a class='change-event' href='{_query_link('/alerts',target=str(event.get('target') or target))}'><i class='tone-{tone}'></i><div><strong>{_esc(str(event.get('kind') or 'surface').replace('_',' ').title())} · {_esc(event.get('change'))}</strong><span>{_esc(event.get('value'))}</span><small>{_esc(event.get('details'))}</small></div><b class='tone-{tone}'>{_esc(event.get('priority'))}</b></a>")
        change_panel=f"<section class='panel'><div class='panel-head'><div><h3>What changed?</h3><span class='muted small'>Newest material changes from the latest successful re-check.</span></div><a class='small' href='{_query_link('/change-intelligence',target=target)}'>Open change intelligence →</a></div><div class='panel-body change-stream'>{''.join(change_cards) or _empty('No material re-check delta yet','Choose a target with at least two successful recon runs to compare baselines.')}</div></section>"
        recent_rows=''.join(f"<tr><td><a class='row-link' href='/runs'>{_esc(r.get('id'))}</a></td><td>{_pill(r.get('status'))}</td><td>{_esc(r.get('started_at'))}</td><td>{_esc(r.get('finished_at') or '—')}</td><td>{_esc(r.get('target_count'))}</td></tr>" for r in snapshot['recent_runs'])
        recent_panel=f"<section class='panel'><div class='panel-head'><div><h3>Recent research activity</h3><span class='muted small'>A compact operational trail — details stay in Run history.</span></div><a class='small' href='/runs'>Run history →</a></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Finished</th><th>Targets</th></tr></thead><tbody>{recent_rows or '<tr><td colspan=5>No runs recorded yet</td></tr>'}</tbody></table></div></section>"
        workspace_strip="<div class='workspace-strip'><a class='workspace-tile' href='/recon'><span class='workspace-tile-icon'>01</span><span><strong>Recon</strong><small>Discover and map the surface</small></span></a><a class='workspace-tile' href='/analysis'><span class='workspace-tile-icon'>02</span><span><strong>Analysis</strong><small>Understand collected evidence</small></span></a><a class='workspace-tile' href='/potential-findings'><span class='workspace-tile-icon'>03</span><span><strong>Potential Findings</strong><small>Review probable security issues</small></span></a><a class='workspace-tile' href='/alerts'><span class='workspace-tile-icon'>04</span><span><strong>Alerts</strong><small>Investigate meaningful change</small></span></a></div>"
        body=header+hero+controls+kpis+f"<div class='command-v2-grid'>{inbox}{side}</div>"+f"<div class='two-col' style='margin-top:16px'>{change_panel}{recent_panel}</div>"+workspace_strip
        self.send_html('Command center',body)

    def workbench(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); assignee=str((p.get('assignee') or [''])[0]); view=str((p.get('view') or ['now'])[0])
        q=str((p.get('q')or[''])[0]).strip(); family=str((p.get('family')or[''])[0]); candidate_state=str((p.get('state')or[''])[0]); lifecycle=str((p.get('lifecycle')or[''])[0]); min_investigation=parse_int((p.get('min_investigation')or[0])[0],0,0,100)
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT target FROM (SELECT DISTINCT target FROM alerts UNION SELECT DISTINCT target FROM bug_candidates) ORDER BY target")]
            assignees=[str(r[0]) for r in db.all("SELECT DISTINCT assignee FROM alerts WHERE assignee<>'' ORDER BY assignee")]
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            families=[str(r[0]) for r in db.all("SELECT DISTINCT bug_family FROM bug_candidates WHERE analysis_id=? ORDER BY bug_family",(analysis_id,))] if analysis_id else []
            states=[str(r[0]) for r in db.all("SELECT DISTINCT candidate_state FROM bug_candidates WHERE analysis_id=? ORDER BY candidate_state",(analysis_id,))] if analysis_id else []
            lifecycles=[str(r[0]) for r in db.all("SELECT DISTINCT lifecycle_state FROM bug_candidates WHERE analysis_id=? ORDER BY lifecycle_state",(analysis_id,))] if analysis_id else []
            cwhere=['analysis_id=?']; cargs:list[Any]=[analysis_id]
            if target: cwhere.append('target=?'); cargs.append(target)
            if q: cwhere.append('(title LIKE ? OR summary LIKE ? OR endpoint LIKE ? OR source_ref LIKE ?)'); cargs.extend([f'%{q}%']*4)
            if family:cwhere.append('bug_family=?');cargs.append(family)
            if candidate_state:cwhere.append('candidate_state=?');cargs.append(candidate_state)
            if lifecycle:cwhere.append('lifecycle_state=?');cargs.append(lifecycle)
            if min_investigation:cwhere.append('investigation_value>=?');cargs.append(min_investigation)
            if view=='now': cwhere.append("analyst_decision='unreviewed' AND candidate_state IN ('strong_candidate','plausible')")
            elif view=='evidence': cwhere.append("(analyst_decision='needs_more_evidence' OR (analyst_decision='unreviewed' AND candidate_state IN ('insufficient_evidence','possible','weak_signal')))")
            elif view=='watch': cwhere.append("lifecycle_state IN ('recurring','persistent','stale') AND analyst_decision NOT IN ('rejected','confirmed_by_analyst')")
            elif view=='confirmed': cwhere.append("analyst_decision='confirmed_by_analyst'")
            elif view=='all': cwhere.append("analyst_decision NOT IN ('rejected','duplicate','out_of_scope')")
            candidates=[dict(r) for r in db.all(f"SELECT * FROM bug_candidates WHERE {' AND '.join(cwhere)} ORDER BY investigation_value DESC,likelihood_score DESC LIMIT 100",cargs)] if analysis_id else []
            count_rows=db.all("SELECT CASE WHEN analyst_decision='confirmed_by_analyst' THEN 'confirmed' WHEN analyst_decision='needs_more_evidence' OR candidate_state IN ('insufficient_evidence','possible','weak_signal') THEN 'evidence' WHEN lifecycle_state IN ('recurring','persistent','stale') THEN 'watch' WHEN analyst_decision='unreviewed' AND candidate_state IN ('strong_candidate','plausible') THEN 'now' ELSE 'all' END bucket,COUNT(*) count FROM bug_candidates WHERE analysis_id=? " + ("AND target=? " if target else "") + "GROUP BY bucket",(analysis_id,target) if target and analysis_id else (analysis_id,)) if analysis_id else []
            candidate_counts={str(r['bucket']):int(r['count']) for r in count_rows}
            awhere=["status NOT IN ('resolved','ignored','false_positive','out_of_scope')"]; aargs:list[Any]=[]
            if target: awhere.append('target=?'); aargs.append(target)
            if assignee: awhere.append('assignee=?'); aargs.append(assignee)
            alerts=db.all(f"SELECT * FROM alerts WHERE {' AND '.join(awhere)} ORDER BY CASE priority WHEN 'urgent' THEN 4 WHEN 'high' THEN 3 WHEN 'normal' THEN 2 ELSE 1 END DESC,risk_score DESC,last_seen DESC LIMIT 15",aargs)
            bundles=db.all("SELECT * FROM candidate_bundles WHERE analysis_id=? " + ("AND target=? " if target else "") + "ORDER BY priority_score DESC LIMIT 6",(analysis_id,target) if target and analysis_id else (analysis_id,)) if analysis_id else []
            notes=db.all("SELECT target,entity_type,entity_value,note,created_at FROM investigation_notes " + ("WHERE target=? " if target else "") + "ORDER BY created_at DESC LIMIT 6",(target,) if target else ())
        finally: db.close()
        tabs=[('now','Review now'),('evidence','Needs evidence'),('watch','Watchlist'),('confirmed','Confirmed'),('all','All active')]
        shared=dict(target=target,assignee=assignee,q=q,family=family,state=candidate_state,lifecycle=lifecycle,min_investigation=min_investigation)
        tab_html="<nav class='segmented'>"+''.join(f"<a class='{'active' if view==key else ''}' href='{_query_link('/workbench',view=key,**shared)}'>{label} <b>{candidate_counts.get(key,0)}</b></a>" for key,label in tabs)+"</nav>"
        header=_breadcrumb('Workspace','Review queue')+_page_header('Review queue','A single ordered list of decisions. Use filters to isolate one target, bug family, lifecycle state or investigation threshold.',"<a class='button secondary' href='/daily'>Recent changes</a><a class='button' href='/bug-candidates'>All candidates</a>",'Analyst workspace')
        fields=f"<label class='filter-wide'>Search candidates<input name='q' value='{_esc(q)}' placeholder='Title, endpoint or evidence summary'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Bug family{_select('family',families,family,'All families')}</label><label>Candidate state{_select('state',states,candidate_state,'Any state')}</label><label>Lifecycle{_select('lifecycle',lifecycles,lifecycle,'Any lifecycle')}</label><label>Alert owner{_select('assignee',assignees,assignee,'Any owner')}</label><label>Min investigation<input type='number' name='min_investigation' min='0' max='100' value='{min_investigation or ''}' placeholder='0'></label><input type='hidden' name='view' value='{_esc(view)}'>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Family':family,'State':candidate_state,'Lifecycle':lifecycle,'Alert owner':assignee,'Investigation ≥':min_investigation},'/workbench',title='Review queue filters',result_count=len(candidates))
        candidate_html=''.join(_candidate_card(r) for r in candidates)
        alert_html=''.join(f"<a class='queue-card' href='/alert?id={r['id']}'><div class='risk-badge tone-{_tone(r['severity'])}'>{r['risk_score']}</div><div class='queue-main'><strong>{_esc(r['title'])}</strong><div class='muted mono small'>{_esc(r['item'])}</div><div class='queue-meta'>{_pill(r['severity'])}{_pill(r['status'])}{_pill(r['priority'])}<span>{_esc(r['target'])}</span><span>{_esc(r['assignee'] or 'unassigned')}</span></div></div><div class='queue-action'><strong>{_esc(_suggested_action(dict(r))[0])}</strong><br><span class='faint'>Open alert evidence</span></div></a>" for r in alerts)
        bundle_html=''.join(f"<a class='evidence-item' href='/candidate-bundles'><div class='evidence-icon'>CB</div><div><strong>{_esc(r['title'])}</strong><div class='queue-meta'><span>Priority {r['priority_score']}</span><span>{_esc(r['target'])}</span></div></div></a>" for r in bundles)
        note_html=''.join(f"<div class='timeline-item'><strong>{_esc(r['entity_type'])}: {_esc(r['entity_value'])}</strong><div class='muted'>{_esc(r['note'])}</div><small class='faint'>{_esc(r['target'])} · {_esc(r['created_at'])}</small></div>" for r in notes)
        queue_health=f"<div class='queue-health'><div><span>Filtered candidates</span><strong>{len(candidates)}</strong></div><div><span>Open alerts</span><strong>{len(alerts)}</strong></div><div><span>Strong now</span><strong>{candidate_counts.get('now',0)}</strong></div><div><span>Need evidence</span><strong>{candidate_counts.get('evidence',0)}</strong></div></div>"
        primary=f"<section class='panel'><div class='panel-head'><h3>{dict(tabs).get(view,'Review queue')}</h3><span class='muted small'>{len(candidates)} candidate decisions</span></div>{candidate_html or _empty('No candidates in this view','Change the filters or replay analysis for the latest completed run.')}</section>"
        if alert_html:
            primary+=f"<details style='margin-top:12px'><summary>Supporting unresolved alerts · {len(alerts)}</summary><div class='details-body' style='padding:0'>{alert_html}</div></details>"
        side=f"<aside class='stack sticky-rail'><section class='panel'><div class='panel-head'><h3>Queue health</h3></div><div class='panel-body'>{queue_health}</div></section><section class='panel'><div class='panel-head'><h3>Related security stories</h3><a class='small' href='/candidate-bundles'>All bundles</a></div><div class='panel-body evidence-feed'>{bundle_html or _empty('No bundles yet')}</div></section><section class='panel'><div class='panel-head'><h3>Recent notes</h3><a class='small' href='/notes'>All notes</a></div><div class='panel-body timeline'>{note_html or _empty('No analyst notes')}</div></section></aside>"
        body=header+controls+tab_html+f"<div class='command-grid' style='margin-top:14px'>{primary}{side}</div>"
        self.send_html('Review queue',body)

    def engine_quality_platform_page(self) -> None:
        p=self.query();target=str((p.get('target')or[''])[0]);family_q=str((p.get('family')or[''])[0]).strip();rule_q=str((p.get('rule')or[''])[0]).strip();parser_q=str((p.get('parser')or[''])[0]).strip();view=str((p.get('view')or['all'])[0]);min_total=parse_int((p.get('min_total')or[0])[0],0,0,100000)
        db=self.db()
        try:
            latest=db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")
            analysis_id=str(latest['id']) if latest else ''
            targets=[str(row[0]) for row in db.all("SELECT DISTINCT target FROM bug_candidates WHERE analysis_id=? ORDER BY target",(analysis_id,))] if analysis_id else []
            data=engine_quality_snapshot(db,analysis_id or None,target=target or None)
            governance=rule_governance(db)
        finally: db.close()
        family_items=[]
        for name,row in data.get('families',{}).items():
            if family_q and family_q.lower() not in name.lower():continue
            if min_total and parse_int(row.get('total'),0)<min_total:continue
            if view=='attention' and not (float(row.get('precision_proxy',0))<.5 or parse_int(row.get('avg_coverage'),0)<50):continue
            family_items.append((name,row))
        rules=[]
        for row in data.get('rules',[]):
            if rule_q and rule_q.lower() not in str(row.get('rule_id','')).lower():continue
            if min_total and parse_int(row.get('generated'),0)<min_total:continue
            if view=='attention' and not (float(row.get('noise_proxy',0))>=.5 or parse_int(row.get('negative'),0)>=3):continue
            rules.append(row)
        parsers=[row for row in data.get('parsers',[]) if not parser_q or parser_q.lower() in str(row.get('parser_name','')).lower()]
        budget=data.get('noise_budget',{}); learning=data.get('target_learning') or {}
        metrics="<div class='metrics-grid'>"+_metric_card('Engine health',data.get('health_score',0),'Composite quality, coverage and backlog score','success' if data.get('health_score',0)>=75 else 'amber')+_metric_card('Reviewed precision',f"{round(data.get('reviewed_precision_proxy',0)*100)}%",'Useful decisions among reviewed candidates','info')+_metric_card('Strong precision',f"{round(data.get('strong_precision_proxy',0)*100)}%",'Useful decisions among reviewed strong candidates','purple')+_metric_card('Evidence coverage',f"{data.get('average_evidence_coverage',0)}%",'Average candidate evidence completeness','orange')+_metric_card('Noise budget',f"{budget.get('candidate_count',0)}/{budget.get('maximum_candidates',0)}",f"{budget.get('profile','balanced')} profile · overflow {budget.get('overflow_count',0)}",'danger' if budget.get('overflow_count',0) else 'success')+_metric_card('Target learning',f"{learning.get('confidence',0)}%",learning.get('target',target or 'All targets'),'blue')+_metric_card('Unreviewed backlog',data.get('unreviewed_backlog',0),'Candidates awaiting a decision','danger' if data.get('unreviewed_backlog',0)>100 else 'blue')+_metric_card('Rules active',governance.get('counts',{}).get('active',0),'Governed active rules','success')+"</div>"
        warning_html=''.join(f"<div class='callout'><strong>Quality warning</strong><span>{_esc(item)}</span></div>" for item in data.get('warnings',[])) or _empty('No current quality warning','Quality metrics are provisional until enough candidate decisions are recorded.')
        family_rows=''.join(f"<tr><td>{_esc(name)}</td><td>{row['total']}</td><td>{row['reviewed']}</td><td>{round(row['precision_proxy']*100)}%</td><td>{row['avg_likelihood']}</td><td>{row['avg_coverage']}</td><td>{row['avg_exploitability']}</td></tr>" for name,row in family_items)
        rule_rows=''.join(f"<tr><td><code>{_esc(row['rule_id'])}</code></td><td>{row.get('generated',0)}</td><td>{row.get('useful',0)}</td><td>{row.get('negative',0)}</td><td>{round(row.get('precision_proxy',0)*100)}%</td><td>{round(row.get('noise_proxy',0)*100)}%</td></tr>" for row in rules)
        parser_rows=''.join(f"<tr><td>{_esc(row['parser_name'])}</td><td>{row['count']}</td><td>{row['quality']}</td><td>{row['trust']}</td></tr>" for row in parsers)
        view_pairs=[('all','All quality data'),('attention','Attention only')]
        fields=f"<label>Target{_select('target',targets,target,'All targets')}</label><label>Family contains<input name='family' value='{_esc(family_q)}' placeholder='e.g. authorization'></label><label>Rule contains<input name='rule' value='{_esc(rule_q)}' placeholder='Rule ID'></label><label>Parser contains<input name='parser' value='{_esc(parser_q)}' placeholder='Parser name'></label><label>Minimum generated<input type='number' name='min_total' min='0' value='{min_total or ''}'></label><label>View{_select_pairs('view',view_pairs,view,'All quality data')}</label>"
        controls=_filter_panel(fields,{'Target':target,'Family':family_q,'Rule':rule_q,'Parser':parser_q,'Generated ≥':min_total,'View':dict(view_pairs).get(view,'') if view!='all' else ''},'/engine-quality',title='Quality filters',result_count=len(family_items)+len(rules)+len(parsers))
        header=_page_header('Engine quality','Measure whether the security engines are becoming more useful, calibrated and less noisy. Filter by target, family, rule or parser.',"<form method='post' action='/platform/sync' style='display:inline'><input type='hidden' name='return' value='/engine-quality'><button>Refresh quality platform</button></form><a class='button secondary' href='/rules'>Rule governance</a>",f'Recon Monitor {APP_VERSION} · Engine Quality Platform')
        body=header+controls+metrics+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Attention</h3></div><div class='panel-body stack'>{warning_html}</div></section><section class='panel'><div class='panel-head'><h3>Quality interpretation</h3></div><div class='panel-body'><p><strong>Likelihood is not validation.</strong> Quality improves when candidates receive structured analyst decisions and correct-family labels.</p><p class='muted'>Current candidate rate: {data.get('candidate_rate_per_1000_evidence',0)} per 1,000 evidence records · False-positive proxy: {round(data.get('false_positive_proxy',0)*100)}% · Duplicate rate: {round(data.get('duplicate_rate',0)*100)}%</p></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Bug-family performance</h3><span class='muted small'>{len(family_items)} families</span></div><div class='table-wrap'><table><thead><tr><th>Family</th><th>Total</th><th>Reviewed</th><th>Precision proxy</th><th>Likelihood</th><th>Coverage</th><th>Exploitability</th></tr></thead><tbody>{family_rows or '<tr><td colspan=7>No families match the filters</td></tr>'}</tbody></table></div></section><div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Noisy and useful rules</h3><a class='small' href='/rules'>Govern rules</a></div><div class='table-wrap'><table><thead><tr><th>Rule</th><th>Generated</th><th>Useful</th><th>Negative</th><th>Precision</th><th>Noise</th></tr></thead><tbody>{rule_rows or '<tr><td colspan=6>No rules match the filters</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Parser evidence quality</h3></div><div class='table-wrap'><table><thead><tr><th>Parser</th><th>Evidence</th><th>Quality</th><th>Trust</th></tr></thead><tbody>{parser_rows or '<tr><td colspan=4>No parsers match the filters</td></tr>'}</tbody></table></div></section></div>"
        self.send_html('Engine quality',body)

    def cases_page(self) -> None:
        p=self.query()
        state=str((p.get('state')or[''])[0]); target=str((p.get('target')or[''])[0]); q=str((p.get('q')or[''])[0]).strip()
        family=str((p.get('family')or[''])[0]); owner=str((p.get('owner')or[''])[0]); validation_state=str((p.get('validation')or[''])[0])
        scope_status=str((p.get('scope')or[''])[0]); sort=str((p.get('sort')or['priority'])[0])
        min_priority=parse_int((p.get('min_priority')or[0])[0],0,0,100); min_readiness=parse_int((p.get('min_readiness')or[0])[0],0,0,100)
        page=max(1,parse_int((p.get('page')or[1])[0],1)); page_size=50
        db=self.db()
        try:
            rows=list_cases(db,state=state or None,target=target or None,q=q or None,family=family or None,assigned_to=owner or None,validation_state=validation_state or None,scope_status=scope_status or None,min_priority=min_priority,min_readiness=min_readiness,sort=sort,limit=page_size,offset=(page-1)*page_size)
            targets=[str(row[0]) for row in db.all("SELECT DISTINCT target FROM security_cases ORDER BY target")]
            families=[str(row[0]) for row in db.all("SELECT DISTINCT primary_family FROM security_cases WHERE primary_family<>'' ORDER BY primary_family")]
            owners=[str(row[0]) for row in db.all("SELECT DISTINCT assigned_to FROM security_cases WHERE assigned_to<>'' ORDER BY assigned_to")]
            validations=[str(row[0]) for row in db.all("SELECT DISTINCT validation_state FROM security_cases WHERE validation_state<>'' ORDER BY validation_state")]
            scopes=[str(row[0]) for row in db.all("SELECT DISTINCT scope_status FROM security_cases WHERE scope_status<>'' ORDER BY scope_status")]
            counts={str(row['state']):int(row['count']) for row in db.all("SELECT state,COUNT(*) count FROM security_cases GROUP BY state")}
            where=[];args=[]
            if state:where.append('state=?');args.append(state)
            if target:where.append('target=?');args.append(target)
            if q:where.append('(case_id LIKE ? OR title LIKE ? OR summary LIKE ?)');args.extend([f'%{q}%']*3)
            if family:where.append('primary_family=?');args.append(family)
            if owner=='__unassigned__':where.append("assigned_to=''")
            elif owner:where.append('assigned_to=?');args.append(owner)
            if validation_state:where.append('validation_state=?');args.append(validation_state)
            if scope_status:where.append('scope_status=?');args.append(scope_status)
            if min_priority:where.append('priority_score>=?');args.append(min_priority)
            if min_readiness:where.append('report_readiness>=?');args.append(min_readiness)
            clause=' WHERE '+' AND '.join(where) if where else ''
            total=parse_int((db.one(f"SELECT COUNT(*) count FROM security_cases{clause}",tuple(args)) or {'count':0})['count'],0)
        finally: db.close()
        tabs=['new','reviewing','needs_evidence','ready_for_validation','confirmed','ready_for_report','reported','closed']
        shared=dict(target=target,q=q,family=family,owner=owner,validation=validation_state,scope=scope_status,min_priority=min_priority,min_readiness=min_readiness,sort=sort)
        tab_html="<nav class='segmented'>"+''.join(f"<a class='{'active' if state==item else ''}' href='{_query_link('/cases',state=item,**shared)}'>{item.replace('_',' ')} <b>{counts.get(item,0)}</b></a>" for item in tabs)+"</nav>"
        owner_pairs=[('__unassigned__','Unassigned')]+[(item,item) for item in owners]
        sort_pairs=[('priority','Priority and workflow'),('updated','Recently updated'),('readiness','Report readiness'),('oldest','Oldest updated')]
        fields=f"<label class='filter-wide'>Search cases<input name='q' value='{_esc(q)}' placeholder='Case ID, title or summary'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>State{_select('state',tabs,state,'All states')}</label><label>Bug family{_select('family',families,family,'All families')}</label><label>Owner{_select_pairs('owner',owner_pairs,owner,'Any owner')}</label><label>Validation{_select('validation',validations,validation_state,'Any result')}</label><label>Scope{_select('scope',scopes,scope_status,'Any scope')}</label><label>Min priority<input type='number' name='min_priority' min='0' max='100' value='{min_priority or ''}' placeholder='0'></label><label>Min readiness<input type='number' name='min_readiness' min='0' max='100' value='{min_readiness or ''}' placeholder='0'></label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Priority')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'State':state,'Family':family,'Owner':'Unassigned' if owner=='__unassigned__' else owner,'Validation':validation_state,'Scope':scope_status,'Priority ≥':min_priority,'Readiness ≥':min_readiness,'Sort':dict(sort_pairs).get(sort,'') if sort!='priority' else ''},'/cases',title='Case filters',result_count=total)
        cards=[]
        for row in rows:
            cards.append(f"<a class='queue-card' href='/case?id={urllib.parse.quote(row['case_id'])}'><div class='risk-badge tone-{_tone(row['state'])}'>{row['priority_score']}</div><div class='queue-main'><div class='queue-meta'>{_pill(row['state'])}{_pill(row['primary_family'],'purple')}{_pill(row.get('validation_state','not_started'))}<span>{_esc(row['target'])}</span></div><strong>{_esc(row['title'])}</strong><div class='muted'>{_esc(row['summary'])}</div><div class='queue-meta'><span>Owner: {_esc(row['assigned_to'] or 'unassigned')}</span><span>Scope: {_esc(row['scope_status'])}</span><span>Report readiness: {row['report_readiness']}%</span><span>Updated: {_esc(row['updated_at'])}</span></div></div><span class='queue-action'>Open case →</span></a>")
        header=_page_header('Security cases','Candidate, alert, evidence, timeline, validation context and report readiness are kept in one analyst-owned case.',"<form method='post' action='/platform/sync'><input type='hidden' name='return' value='/cases'><button>Sync latest analysis</button></form><a class='button secondary' href='/security-stories'>Security stories</a>",f'Recon Monitor {APP_VERSION} · Filterable investigation workspace')
        page_args={**shared,'state':state}
        pager="<nav class='pager'>"+(f"<a class='button ghost' href='{_query_link('/cases',page=page-1,**page_args)}'>← Previous</a>" if page>1 else "<span></span>") + f"<span>Page {page} · {total} cases</span>" + (f"<a class='button ghost' href='{_query_link('/cases',page=page+1,**page_args)}'>Next →</a>" if page*page_size<total else "<span></span>") + "</nav>"
        self.send_html('Security cases',header+controls+tab_html+f"<section class='panel' style='margin-top:14px'><div class='panel-head'><h3>Case queue</h3><span class='muted small'>{len(rows)} shown</span></div>{''.join(cards) or _empty('No cases in this view','Sync the latest analysis or change the filters.')}{pager}</section>")

    def case_page(self) -> None:
        case_id = str((self.query().get('id') or [''])[0])
        db = self.db()
        try:
            detail = case_detail(db, case_id)
            gap = evidence_gap_for_case(db, case_id, persist=False)
            auto = case_autopilot(db, case_id, actor='dashboard-preview', persist=False)
        finally:
            db.close()
        case = detail['case']; candidates = detail['candidates']; events = detail['events']; packages = detail['validation_packages']; drafts = detail['report_drafts']
        return_href = '/case?id=' + urllib.parse.quote(case_id)
        forms = (
            f"<section class='panel'><div class='panel-head'><h3>Case decision</h3></div><div class='panel-body'><form method='post' action='/cases/state' class='stack'>"
            f"<input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='{_esc(return_href)}'>"
            f"<label>State<br>{_select('state', CASE_STATES, str(case['state']), 'Select state')}</label>"
            f"<label>Assigned analyst<br><input name='assigned_to' value='{_esc(case['assigned_to'])}'></label>"
            f"<label>Decision note<br><textarea name='note'></textarea></label><button>Update case</button></form></div></section>"
            f"<section class='panel'><div class='panel-head'><h3>Investigation autopilot</h3></div><div class='panel-body stack'>"
            f"<form method='post' action='/workspace/evidence-gap'><input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='{_esc(return_href)}'><button>Refresh evidence gap</button></form>"
            f"<form method='post' action='/workspace/autopilot'><input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='{_esc(return_href)}'><button class='secondary'>Refresh next actions</button></form>"
            f"<a class='button secondary' href='/report-builder?case_id={urllib.parse.quote(case_id)}'>Evidence-linked report</a>"
            f"<p class='muted small'>Autopilot recommends investigation steps only. It never executes exploit actions or confirms a vulnerability.</p></div></section>"
            f"<section class='panel'><div class='panel-head'><h3>Authorized validation</h3></div><div class='panel-body stack'>"
            f"<form method='post' action='/cases/validation-package'><input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='{_esc(return_href)}'><button class='secondary'>Build context package</button></form>"
            f"<a class='button' href='/safe-validation?case_id={urllib.parse.quote(case_id)}'>Open Safe Validation</a>"
            f"<form method='post' action='/cases/report-draft'><input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='{_esc(return_href)}'><button class='secondary'>Build legacy report draft</button></form>"
            f"<p class='muted small'>Packages contain context and stop conditions only. No payload or automatic high-risk validation is produced.</p></div></section>"
        )
        candidate_html = ''.join(_candidate_card(row) for row in candidates)
        timeline = ''.join(f"<div class='timeline-item'><strong>{_esc(row['event_type'].replace('_',' '))}</strong><div class='muted'><pre>{_esc(json_dumps(_json(row['details_json'],{}),pretty=True))}</pre></div><small>{_esc(row['actor'])} · {_esc(row['created_at'])}</small></div>" for row in events)
        package_html = ''.join(f"<details><summary>{_esc(row['package_id'])} · {_esc(row['created_at'])}</summary><pre>{_esc(json_dumps(_json(row['package_json'],{}),pretty=True))}</pre></details>" for row in packages)
        draft_html = ''.join(f"<details><summary>{_esc(row['draft_id'])} · readiness {row['readiness_score']}%</summary><pre>{_esc(json_dumps(_json(row['body_json'],{}),pretty=True))}</pre></details>" for row in drafts)
        requirements = ''.join(
            f"<div class='evidence-item'><div class='evidence-icon'>{'✓' if item['status']=='present' else '!'}</div><div><strong>{_esc(item['label'])}</strong><div class='muted'>{_esc(item.get('description',''))} · {_esc(item['status'])}</div></div></div>"
            for item in gap['requirements']
        )
        actions = ''.join(
            f"<div class='evidence-item'><div class='evidence-icon'>{task['rank']}</div><div><strong>{_esc(task['title'])}</strong><div class='muted'>{_esc(task['type'])} · recommendation only</div></div></div>"
            for task in auto['tasks']
        )
        header = _breadcrumb(('Workspace','/cases'),'Case') + _page_header(case['title'], case['summary'], "<a class='button secondary' href='/cases'>Back to cases</a>", f"{case['target']} · {case_id}")
        summary = "<div class='metrics-grid'>" + _metric_card('Priority', case['priority_score'], 'Investigation priority', 'orange') + _metric_card('State', case['state'], 'Current case lifecycle', 'info') + _metric_card('Evidence coverage', f"{gap['coverage']}%", f"{gap['missing_count']} requirement(s) missing", 'success' if gap['coverage'] >= 80 else 'amber') + _metric_card('Autopilot', f"{auto['autopilot_score']}%", 'Investigation readiness, not exploitability', 'purple') + _metric_card('Report readiness', f"{case['report_readiness']}%", 'Evidence, scope and lifecycle readiness', 'success' if case['report_readiness'] >= 75 else 'amber') + _metric_card('Validation', case.get('validation_state','not_started'), case.get('validation_summary') or 'No safe validation yet', 'info') + "</div>"
        guidance = f"<section class='panel'><div class='panel-head'><h3>Evidence gap</h3><span class='badge'>{_esc(gap['automation'])}</span></div><div class='panel-body evidence-feed'>{requirements or _empty('No evidence requirements')}</div></section><section class='panel'><div class='panel-head'><h3>Next best actions</h3><span class='muted small'>Human-controlled investigation</span></div><div class='panel-body evidence-feed'>{actions or _empty('No next action generated')}</div></section>"
        body = header + summary + f"<div class='two-col' style='margin-top:16px'><main class='stack'>{guidance}<section class='panel'><div class='panel-head'><h3>Correlated candidates</h3></div>{candidate_html or _empty('No candidate members')}</section><section class='panel'><div class='panel-head'><h3>Case timeline</h3></div><div class='panel-body timeline'>{timeline or _empty('No case events')}</div></section><section class='panel'><div class='panel-head'><h3>Validation packages</h3></div><div class='panel-body'>{package_html or _empty('No validation package')}</div></section><section class='panel'><div class='panel-head'><h3>Report drafts</h3></div><div class='panel-body'>{draft_html or _empty('No report draft')}</div></section></main><aside class='stack sticky-rail'>{forms}</aside></div>"
        self.send_html('Security case', body)

    def safe_validation_page(self) -> None:
        q=self.query(); case_id=str((q.get('case_id')or[''])[0]); plan_id=str((q.get('plan_id')or[''])[0]); search=str((q.get('q')or[''])[0]).strip()
        target=str((q.get('target')or[''])[0]); family=str((q.get('family')or[''])[0]); case_state=str((q.get('case_state')or[''])[0]); validation_state=str((q.get('validation_state')or[''])[0])
        level=str((q.get('level')or[''])[0]); plan_status=str((q.get('plan_status')or[''])[0]); result=str((q.get('result')or[''])[0])
        db=self.db()
        try:
            case_where=[];case_args=[]
            if target:case_where.append('target=?');case_args.append(target)
            if family:case_where.append('primary_family=?');case_args.append(family)
            if case_state:case_where.append('state=?');case_args.append(case_state)
            if validation_state:case_where.append('validation_state=?');case_args.append(validation_state)
            if search:case_where.append('(case_id LIKE ? OR title LIKE ? OR summary LIKE ?)');case_args.extend([f'%{search}%']*3)
            case_clause=' WHERE '+' AND '.join(case_where) if case_where else ''
            cases=[dict(row) for row in db.all(f"SELECT case_id,title,target,primary_family,state,validation_state FROM security_cases{case_clause} ORDER BY updated_at DESC LIMIT 400",tuple(case_args))]
            targets=[str(row[0]) for row in db.all("SELECT DISTINCT target FROM security_cases ORDER BY target")]
            families=[str(row[0]) for row in db.all("SELECT DISTINCT primary_family FROM security_cases WHERE primary_family<>'' ORDER BY primary_family")]
            case_states=[str(row[0]) for row in db.all("SELECT DISTINCT state FROM security_cases ORDER BY state")]
            validation_states=[str(row[0]) for row in db.all("SELECT DISTINCT validation_state FROM security_cases ORDER BY validation_state")]
            plan_statuses=[str(row[0]) for row in db.all("SELECT DISTINCT status FROM validation_plans ORDER BY status")]
            results=[str(row[0]) for row in db.all("SELECT DISTINCT result FROM validation_runs WHERE result<>'' ORDER BY result")]
            base_where=[];base_args=[]
            if case_id:base_where.append('vp.case_id=?');base_args.append(case_id)
            if plan_id:base_where.append('vp.plan_id=?');base_args.append(plan_id)
            if target:base_where.append('sc.target=?');base_args.append(target)
            if family:base_where.append('sc.primary_family=?');base_args.append(family)
            if case_state:base_where.append('sc.state=?');base_args.append(case_state)
            if validation_state:base_where.append('sc.validation_state=?');base_args.append(validation_state)
            if level:base_where.append('vp.level=?');base_args.append(level)
            if plan_status:base_where.append('vp.status=?');base_args.append(plan_status)
            if search:base_where.append('(vp.plan_id LIKE ? OR vp.case_id LIKE ? OR sc.title LIKE ?)');base_args.extend([f'%{search}%']*3)
            base_clause=' WHERE '+' AND '.join(base_where) if base_where else ''
            plans=[dict(row) for row in db.all(f"SELECT vp.*,sc.title case_title,sc.primary_family,sc.state case_state,sc.validation_state FROM validation_plans vp JOIN security_cases sc ON sc.case_id=vp.case_id{base_clause} ORDER BY vp.updated_at DESC LIMIT 200",tuple(base_args))]
            run_where=list(base_where);run_args=list(base_args)
            if result:run_where.append('(vr.result=? OR vr.status=?)');run_args.extend([result,result])
            run_clause=' WHERE '+' AND '.join(run_where) if run_where else ''
            runs=[dict(row) for row in db.all(f"SELECT vr.*,vp.level,vp.status plan_status,sc.title case_title,sc.primary_family,sc.state case_state,sc.validation_state FROM validation_runs vr JOIN validation_plans vp ON vp.plan_id=vr.plan_id JOIN security_cases sc ON sc.case_id=vr.case_id{run_clause} ORDER BY vr.started_at DESC LIMIT 200",tuple(run_args))]
            eligible=validation_eligibility(db,case_id) if case_id else None
        finally: db.close()
        case_options=[(row['case_id'],f"{row['case_id']} · {row['title']}") for row in cases]
        fields=f"<label class='filter-wide'>Search validation<input name='q' value='{_esc(search)}' placeholder='Case, plan or title'></label><label>Case{_select_pairs('case_id',case_options,case_id,'All cases')}</label><label>Target{_select('target',targets,target,'All targets')}</label><label>Bug family{_select('family',families,family,'All families')}</label><label>Case state{_select('case_state',case_states,case_state,'Any state')}</label><label>Validation state{_select('validation_state',validation_states,validation_state,'Any result')}</label><label>Plan level{_select('level',VALIDATION_LEVELS,level,'Any level')}</label><label>Plan status{_select('plan_status',plan_statuses,plan_status,'Any status')}</label><label>Run result{_select('result',results,result,'Any result')}</label>"
        controls=_filter_panel(fields,{'Search':search,'Case':case_id,'Target':target,'Family':family,'Case state':case_state,'Validation':validation_state,'Level':level,'Plan status':plan_status,'Run result':result},'/safe-validation',title='Validation filters',result_count=len(plans)+len(runs))
        eligibility_html=''
        if eligible:
            reasons=''.join(f"<li>{_esc(item)}</li>" for item in eligible.get('reasons',[]))
            eligibility_html=f"<section class='panel'><div class='panel-head'><h3>Eligibility</h3>{_pill(eligible.get('recommended_level'))}</div><div class='panel-body'><p><strong>Family:</strong> {_esc(eligible.get('primary_family'))}</p><ul>{reasons}</ul><p class='muted small'>Only GET, HEAD and OPTIONS are allowed. No cookies, credentials, redirect following, identifier guessing or state-changing requests.</p><form method='post' action='/validation/plan' class='stack'><input type='hidden' name='case_id' value='{_esc(case_id)}'><input type='hidden' name='return' value='/safe-validation?case_id={urllib.parse.quote(case_id)}'><label>Plan level<br>{_select('level',VALIDATION_LEVELS,str(eligible.get('recommended_level')),'Select level')}</label><button>Create validation plan</button></form></div></section>"
        plan_cards=[]
        for row in plans:
            plan=_json(row.get('plan_json'),{});phrase=plan.get('approval_phrase','');actions=[]
            if row.get('status')=='awaiting_approval':
                actions.append(f"<form method='post' action='/validation/approve' class='stack'><input type='hidden' name='plan_id' value='{_esc(row['plan_id'])}'><input type='hidden' name='return' value='/safe-validation?case_id={urllib.parse.quote(str(row['case_id']))}'><label>Exact confirmation<br><input name='confirmation' placeholder='{_esc(phrase)}' required></label><button class='secondary'>Approve this candidate plan</button></form>")
            if row.get('status')=='approved':
                actions.append(f"<form method='post' action='/validation/run'><input type='hidden' name='plan_id' value='{_esc(row['plan_id'])}'><input type='hidden' name='return' value='/safe-validation?case_id={urllib.parse.quote(str(row['case_id']))}'><label><input type='checkbox' name='allow_live' value='true' required> I understand this sends bounded live requests</label><button>Run safe validation</button></form>")
            if row.get('level')=='offline' and row.get('status')=='plan_ready':
                actions.append(f"<form method='post' action='/validation/run'><input type='hidden' name='plan_id' value='{_esc(row['plan_id'])}'><input type='hidden' name='return' value='/safe-validation?case_id={urllib.parse.quote(str(row['case_id']))}'><button>Run offline validation</button></form>")
            reqs=plan.get('requests',[]);request_lines=''.join(f"<li><code>{_esc(item.get('method'))}</code> {_esc(item.get('url'))} — {_esc(item.get('purpose'))}</li>" for item in reqs) or '<li>No live request in this plan.</li>'
            plan_cards.append(f"<article class='panel'><div class='panel-head'><div><div class='eyebrow'>{_esc(row['case_id'])} · {_esc(row.get('primary_family'))}</div><h3>{_esc(row['plan_id'])}</h3><span class='muted small'>{_esc(row.get('case_title'))}</span></div><div class='queue-meta'>{_pill(row['level'])}{_pill(row['status'])}</div></div><div class='panel-body'><ul>{request_lines}</ul><details><summary>Budgets and stop conditions</summary><pre>{_esc(json_dumps({'budgets':plan.get('budgets',{}),'stop_conditions':plan.get('stop_conditions',[])},pretty=True))}</pre></details>{''.join(actions)}</div></article>")
        run_cards=[]
        for row in runs:
            summary=_json(row.get('summary_json'),{});reasons=''.join(f"<li>{_esc(item)}</li>" for item in summary.get('reasons',[]));observations=summary.get('observations',[])
            obs_rows=''.join(f"<tr><td>{_esc(item.get('method') or item.get('check'))}</td><td>{_esc(item.get('url','offline'))}</td><td>{_esc(item.get('status_code','—'))}</td><td>{_esc(item.get('content_type',''))}</td><td>{_esc(', '.join(item.get('sensitive_key_names',[])[:5]))}</td></tr>" for item in observations)
            feedback=f"<form method='post' action='/validation/feedback' class='stack'><input type='hidden' name='run_id' value='{_esc(row['run_id'])}'><input type='hidden' name='return' value='/safe-validation?case_id={urllib.parse.quote(str(row['case_id']))}'><label>Analyst decision<br>{_select('decision',VALIDATION_FEEDBACK_DECISIONS,'needs_more_evidence','Select decision')}</label><label>Reason<br>{_select('reason',VALIDATION_FEEDBACK_REASONS,'insufficient_evidence','Select reason')}</label><label>Note<br><textarea name='note'></textarea></label><button class='secondary'>Record feedback</button></form>"
            run_cards.append(f"<article class='panel'><div class='panel-head'><div><div class='eyebrow'>{_esc(row['case_id'])} · {_esc(row.get('primary_family'))}</div><h3>{_esc(row['run_id'])}</h3><span class='muted small'>{_esc(row.get('case_title'))}</span></div><div class='queue-meta'>{_pill(row.get('level'))}{_pill(row['result'] or row['status'])}</div></div><div class='panel-body'><ul>{reasons or '<li>No result reason recorded.</li>'}</ul><div class='table-wrap'><table><thead><tr><th>Method/check</th><th>URL</th><th>Status</th><th>Type</th><th>Sensitive categories</th></tr></thead><tbody>{obs_rows or '<tr><td colspan=5>No observations</td></tr>'}</tbody></table></div><p class='muted small'>Raw response bodies stored: no. Analyst decision remains manual.</p>{feedback}</div></article>")
        header=_page_header('Safe validation','Bounded, scope-aware observations can strengthen, weaken or leave a candidate inconclusive. Filters separate cases, plans and results without changing safety gates.',"<a class='button secondary' href='/cases'>Security cases</a><a class='button' href='/scope-center'>Scope center</a>",f'Recon Monitor {APP_VERSION} · Safe Validation Engine')
        main=f"<main class='stack'><section><h2>Plans</h2>{''.join(plan_cards) or _empty('No validation plans')}</section><section><h2>Runs</h2>{''.join(run_cards) or _empty('No validation runs')}</section></main>"
        body=header+controls+(f"<div class='two-col' style='margin-top:16px'><aside class='stack'>{eligibility_html}</aside>{main}</div>" if case_id else main)
        self.send_html('Safe validation',body)

    def security_stories_page(self) -> None:
        p=self.query();target=str((p.get('target')or[''])[0]);status=str((p.get('status')or[''])[0]);q=str((p.get('q')or[''])[0]).strip();sort=str((p.get('sort')or['priority'])[0]);min_priority=parse_int((p.get('min_priority')or[0])[0],0,0,100);days=parse_int((p.get('days')or[0])[0],0,0,3650)
        where=[];args=[]
        if target:where.append('target=?');args.append(target)
        if status:where.append('status=?');args.append(status)
        if q:where.append('(title LIKE ? OR summary LIKE ? OR story_id LIKE ?)');args.extend([f'%{q}%']*3)
        if min_priority:where.append('priority_score>=?');args.append(min_priority)
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('updated_at>=?');args.append(since)
        clause=' WHERE '+' AND '.join(where) if where else ''
        order={'priority':'priority_score DESC,updated_at DESC','updated':'updated_at DESC,priority_score DESC','oldest':'updated_at ASC,priority_score DESC'}.get(sort,'priority_score DESC,updated_at DESC')
        db=self.db()
        try:
            rows=[dict(row) for row in db.all(f"SELECT * FROM security_stories{clause} ORDER BY {order} LIMIT 200",tuple(args))]
            targets=[str(row[0]) for row in db.all("SELECT DISTINCT target FROM security_stories ORDER BY target")]
            statuses=[str(row[0]) for row in db.all("SELECT DISTINCT status FROM security_stories ORDER BY status")]
        finally: db.close()
        sort_pairs=[('priority','Priority'),('updated','Recently updated'),('oldest','Oldest updated')]
        day_pairs=[('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days'),('365','Last year')]
        fields=f"<label class='filter-wide'>Search stories<input name='q' value='{_esc(q)}' placeholder='Story title, ID or summary'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Status{_select('status',statuses,status,'Any status')}</label><label>Minimum priority<input type='number' name='min_priority' min='0' max='100' value='{min_priority or ''}'></label><label>Updated window{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Priority')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Status':status,'Priority ≥':min_priority,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='priority' else ''},'/security-stories',title='Story filters',result_count=len(rows))
        cards=[]
        for row in rows:
            timeline=_json(row['timeline_json'],[])
            steps=''.join(f"<div class='timeline-item'><strong>{_esc(item.get('event','change').replace('_',' '))}</strong><span class='muted'>{_esc(item.get('title') or item.get('family') or '')}</span><small>{_esc(item.get('time',''))}</small></div>" for item in timeline[:8])
            cards.append(f"<article class='panel'><div class='panel-head'><div><div class='eyebrow'>{_esc(row['target'])} · {_esc(row['story_id'])}</div><h3>{_esc(row['title'])}</h3><div class='queue-meta'>{_pill(row['status'])}<span>Updated {_esc(row['updated_at'])}</span></div></div><div class='risk-badge tone-orange'>{row['priority_score']}</div></div><div class='panel-body'><p>{_esc(row['summary'])}</p><div class='timeline'>{steps or '<span class=muted>No timeline events yet.</span>'}</div></div></article>")
        header=_page_header('Security stories','Related endpoint, JavaScript, feature, behavior and candidate changes are presented as one security narrative instead of isolated alerts.',"<a class='button' href='/cases'>Open cases</a>",f'Recon Monitor {APP_VERSION} · Correlated investigation')
        self.send_html('Security stories',header+controls+("<div class='stack'>"+''.join(cards)+"</div>" if cards else _empty('No security stories','Change the filters or sync the latest analysis.')))

    def scope_center_page(self) -> None:
        db=self.db()
        try: data=scope_center(self.paths,db)
        finally: db.close()
        cards=[]
        for row in data.get('targets',[]):
            includes=''.join(f"<li><code>{_esc(item)}</code></li>" for item in row.get('include',[])) or '<li>None</li>'
            excludes=''.join(f"<li><code>{_esc(item)}</code></li>" for item in row.get('exclude',[])) or '<li>None</li>'
            active=', '.join(row.get('active_modules',[])) or 'disabled'
            limits=row.get('limits',{})
            cards.append(f"<article class='panel'><div class='panel-head'><div><div class='eyebrow'>Target policy</div><h3>{_esc(row['name'])}</h3></div>{_pill(row['authorization_status'])}</div><div class='panel-body'><div class='two-col'><div><strong>Included</strong><ul>{includes}</ul><strong>Excluded</strong><ul>{excludes}</ul></div><div><p><strong>Active modules:</strong> {_esc(active)}</p><p><strong>Request rate:</strong> {_esc(limits.get('request_rate','—'))}</p><p><strong>HTTP budget:</strong> {_esc(limits.get('max_http_requests','—'))}</p><p><strong>Maximum runtime:</strong> {_esc(limits.get('max_runtime_minutes','—'))} min</p><p class='muted small'>Active modules still require all authorization gates at execution time.</p></div></div></div></article>")
        header=_page_header('Scope center','Review scope, exclusions, authorization confirmation, active modules and execution limits before running reconnaissance.',"<a class='button secondary' href='/targets'>Manage targets</a><a class='button' href='/runs'>Runs</a>",'Recon Monitor 5.0 · Scope & authorization')
        self.send_html('Scope center',header+("<div class='stack'>"+''.join(cards)+"</div>" if cards else _empty('No target policy','Configure a target before running reconnaissance.')))

    def operations_center_page(self) -> None:
        db=self.db()
        try:
            refresh=str((self.query().get('refresh')or['0'])[0]).lower() in {'1','true','yes'}
            data=operations_center(self.paths,db,refresh=refresh,deep_check=refresh)
        finally: db.close()
        completeness=data.get('run_completeness',{}); storage=data.get('storage',{}); quality=data.get('engine_quality',{})
        warnings=''.join(f"<div class='callout'><strong>Attention</strong><span>{_esc(item)}</span></div>" for item in data.get('warnings',[])) or _empty('No operational warning')
        dims=completeness.get('dimensions',{})
        stage_rows=''.join(f"<tr><td>{_esc(stage)}</td><td>{_pill(info.get('status'))}</td><td>{info.get('score',0)}%</td><td>{info.get('records',0)}</td></tr>" for stage,info in dims.items())
        backups=''.join(f"<tr><td><code>{_esc(row['backup_id'])}</code></td><td>{_esc(row['created_at'])}</td><td>{_esc(row['verified_at'] or 'not verified')}</td><td>{row['size']}</td></tr>" for row in data.get('backups',[]))
        schedules=''.join(f"<tr><td>{_esc(row['target'])}</td><td>{_esc(row['cadence'])}</td><td>{_pill('active' if row['enabled'] else 'disabled')}</td><td>{row['request_budget']}</td><td>{row['max_runtime_minutes']} min</td></tr>" for row in data.get('schedules',[]))
        header=_page_header('Operations center','Program health, data completeness, backup readiness, schedules, notifications and storage are grouped in one operational view.',"<a class='button secondary' href='/operations-center?refresh=1'>Run deep refresh</a><a class='button secondary' href='/storage-health'>Storage health</a><a class='button' href='/scope-center'>Scope center</a>",f'Recon Monitor {APP_VERSION} · Cached daily operations')
        metrics="<div class='metrics-grid'>"+_metric_card('Program health',data.get('program_health_score',0),'Database, runs, backups and engine quality','success' if data.get('program_health_score',0)>=75 else 'amber')+_metric_card('Run completeness',f"{completeness.get('score',0)}%",data.get('latest_run') or 'No run','info')+_metric_card('Engine health',quality.get('health_score',0),'Quality and backlog health','purple')+_metric_card('Failed stages',data.get('failed_stages',0),'Historical failed stage records','danger' if data.get('failed_stages',0) else 'success')+_metric_card('Storage',f"{round(storage.get('estimated_total_bytes',0)/1024/1024,1)} MB",'Estimated managed data','blue')+_metric_card('Backups',len(data.get('backups',[])),'Catalogued recent backups','orange')+"</div>"
        forms="<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Schedule policy</h3></div><div class='panel-body'><form method='post' action='/schedules/set' class='stack'><label>Target<br><input name='target' required></label><label>Cadence<br><input name='cadence' placeholder='weekly or Mon,Thu 03:00' required></label><label>Request budget<br><input type='number' name='request_budget' value='10000'></label><label>Maximum runtime (minutes)<br><input type='number' name='max_runtime' value='120'></label><label>Quiet hours<br><input name='quiet_hours' placeholder='22:00-07:00'></label><input type='hidden' name='enabled' value='true'><button>Save policy</button></form></div></section><section class='panel'><div class='panel-head'><h3>Notification policy</h3></div><div class='panel-body'><form method='post' action='/notifications/set' class='stack'><label>Target<br><input name='target' value='*' required></label><label>Event type<br><input name='event_type' placeholder='strong_candidate' required></label><label>Mode<br>{_select('mode',NOTIFICATION_MODES,'digest','Select mode')}</label><label>Minimum score<br><input type='number' name='minimum_score' value='70'></label><button>Save policy</button></form></div></section></div>"
        body=header+metrics+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Operational attention</h3></div><div class='panel-body stack'>{warnings}</div></section><section class='panel'><div class='panel-head'><h3>Latest run completeness</h3></div><div class='table-wrap'><table><thead><tr><th>Stage</th><th>Status</th><th>Coverage</th><th>Records</th></tr></thead><tbody>{stage_rows or '<tr><td colspan=4>No stage data</td></tr>'}</tbody></table></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Backup readiness</h3></div><div class='table-wrap'><table><thead><tr><th>Backup</th><th>Created</th><th>Verified</th><th>Bytes</th></tr></thead><tbody>{backups or '<tr><td colspan=4>No catalogued backups</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Configured schedules</h3></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Cadence</th><th>Status</th><th>Budget</th><th>Runtime</th></tr></thead><tbody>{schedules or '<tr><td colspan=5>No schedule policies</td></tr>'}</tbody></table></div></section>"+forms
        self.send_html('Operations center',body)

    def storage_health_page(self) -> None:
        db=self.db()
        try:
            refresh=str((self.query().get('refresh')or['0'])[0]).lower() in {'1','true','yes'}
            data=storage_health_snapshot(self.paths,db,refresh=refresh)
        finally:
            db.close()
        rows=''.join(f"<tr><td>{_esc(key.replace('_bytes','').replace('_',' '))}</td><td>{round(value/1024/1024,2)} MB</td></tr>" for key,value in data.items() if key.endswith('_bytes'))
        preview=data.get('retention_preview',{})
        total_label=str(round(data.get('estimated_total_bytes',0)/1024/1024,2))+' MB'
        object_label=str(round(data.get('object_bytes',0)/1024/1024,2))+' MB content store'
        metrics="<div class='metrics-grid'>"+_metric_card('Estimated total',total_label,'Managed data excluding overlapping state totals','blue')+_metric_card('Objects',data.get('object_count',0),object_label,'purple')+_metric_card('Backups',data.get('backup_count',0),'Catalogued backups','orange')+_metric_card('Temporary eligible',preview.get('eligible_temporary_objects',0),'Unreferenced object-store entries','amber')+"</div>"
        header=_page_header('Storage health','Cached storage snapshots keep this page fast. Run a full recursive measurement only when you need fresh numbers.',"<a class='button secondary' href='/storage-health?refresh=1'>Refresh storage scan</a><a class='button secondary' href='/operations-center'>Operations center</a>",f'Recon Monitor {APP_VERSION} · Storage management')
        body=header+metrics+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Storage breakdown</h3></div><div class='table-wrap'><table><thead><tr><th>Area</th><th>Size</th></tr></thead><tbody>{rows}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Default retention safety</h3></div><div class='panel-body'><p>Confirmed evidence is retained. Raw artifacts are eligible after {preview.get('raw_artifact_days',90)} days, summaries remain available, and the latest {preview.get('keep_backups',10)} backups are protected.</p><p class='muted'>Use the existing retention command with <code>--dry-run</code> before deleting anything.</p></div></section>"
        self.send_html('Storage health',body)

    def rules_page(self) -> None:
        db=self.db()
        try:data=rule_governance(db)
        finally:db.close()
        rows=[]
        for row in data.get('rules',[]):
            select=_select('state',RULE_STATES,str(row['state']),'State')
            rows.append(f"<tr><td><code>{_esc(row['rule_id'])}</code><br><span class='faint'>{_esc(row['rule_version'])}</span></td><td>{_esc(row['bug_family'])}</td><td>{_pill(row['state'])}</td><td>{_esc(row['description'])}</td><td><form method='post' action='/rules/state' style='display:flex;gap:6px'><input type='hidden' name='rule_id' value='{_esc(row['rule_id'])}'><input type='hidden' name='rule_version' value='{_esc(row['rule_version'])}'>{select}<button class='secondary'>Set</button></form></td></tr>")
        counts=data.get('counts',{})
        header=_page_header('Rule governance','Rules move through draft, shadow, candidate, active, deprecated and disabled states. Experimental rules do not enter the primary review queue.',"<a class='button' href='/engine-quality'>Engine quality</a>",'Recon Monitor 5.0 · Rule lifecycle')
        metrics="<div class='metrics-grid'>"+''.join(_metric_card(state,counts.get(state,0),'Governed rules', 'success' if state=='active' else 'purple' if state=='shadow' else 'blue') for state in RULE_STATES)+"</div>"
        self.send_html('Rule governance',header+metrics+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Rule registry</h3></div><div class='table-wrap'><table><thead><tr><th>Rule</th><th>Family</th><th>State</th><th>Description</th><th>Change state</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=5>No rules registered</td></tr>'}</tbody></table></div></section>")


    def plugins_page(self) -> None:
        db=self.db()
        try:
            rows=PluginManager(self.paths,db).health()
            history=[dict(row) for row in db.all("SELECT * FROM plugin_health_history ORDER BY created_at DESC LIMIT 100")]
        finally: db.close()
        cards=''.join(f"<article class='panel'><div class='panel-head'><h3>{_esc(row['name'])}</h3>{_pill(row.get('status') or ('ok' if row.get('ok') else 'degraded'))}</div><div class='panel-body'><p>{_esc(row.get('detail',''))}</p><pre>{_esc(json_dumps(row.get('contract',{}),pretty=True))}</pre></div></article>" for row in rows)
        history_rows=''.join(f"<tr><td>{_esc(row['plugin_name'])}</td><td>{_esc(row['version'])}</td><td>{_pill(row['status'])}</td><td>{_esc(row['created_at'])}</td><td><pre>{_esc(row['details_json'])}</pre></td></tr>" for row in history)
        header=_page_header('Plugin health','Version 5.0 validates plugin manifests, capability contracts, timeouts, resource limits, required tools and health history before a plugin is trusted.',"<a class='button secondary' href='/operations-center'>Operations center</a>",'Recon Monitor 5.0 · Plugin governance')
        self.send_html('Plugin health',header+("<div class='stack'>"+cards+"</div>" if cards else _empty('No plugins discovered'))+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Health history</h3></div><div class='table-wrap'><table><thead><tr><th>Plugin</th><th>Version</th><th>Status</th><th>Checked</th><th>Details</th></tr></thead><tbody>{history_rows or '<tr><td colspan=5>No health history</td></tr>'}</tbody></table></div></section>")

    def audit_page(self) -> None:
        q=self.query(); action=str((q.get('action')or[''])[0]); actor=str((q.get('actor')or[''])[0])
        db=self.db()
        try:
            where=[];params=[]
            if action:where.append('action=?');params.append(action)
            if actor:where.append('actor=?');params.append(actor)
            clause=' WHERE '+' AND '.join(where) if where else ''
            rows=[dict(row) for row in db.all(f"SELECT * FROM audit_log{clause} ORDER BY created_at DESC,id DESC LIMIT 500",tuple(params))]
            actions=[str(row[0]) for row in db.all("SELECT DISTINCT action FROM audit_log ORDER BY action")]
            actors=[str(row[0]) for row in db.all("SELECT DISTINCT actor FROM audit_log ORDER BY actor")]
        finally:db.close()
        controls=f"<form class='filters'><label>Action<br>{_select('action',actions,action,'All actions')}</label><label>Actor<br>{_select('actor',actors,actor,'All actors')}</label><button>Filter</button><a class='button ghost' href='/audit'>Reset</a></form>"
        table=''.join(f"<tr><td>{_esc(row['created_at'])}</td><td>{_esc(row['actor'])}</td><td>{_pill(row['action'])}</td><td>{_esc(row['target'] or '')}</td><td>{_esc(row['entity_type'] or '')}: <code>{_esc(row['entity_value'] or '')}</code></td><td><pre>{_esc(row['details_json'])}</pre></td></tr>" for row in rows)
        header=_page_header('Audit trail','Sensitive changes to scope, rules, cases, backups, users, alerts and workflow decisions remain attributable and reviewable.',"<a class='button secondary' href='/operations-center'>Operations center</a>",'Recon Monitor 5.0 · Accountability')
        self.send_html('Audit trail',header+controls+f"<section class='panel'><div class='panel-head'><h3>Recent audited actions</h3><span class='muted small'>{len(rows)} events</span></div><div class='table-wrap'><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Entity</th><th>Details</th></tr></thead><tbody>{table or '<tr><td colspan=6>No audit events</td></tr>'}</tbody></table></div></section>")

    def daily(self) -> None:
        params = self.query(); hours = parse_int((params.get("hours") or [24])[0], 24, 1, 720); target = str((params.get("target") or [""])[0])
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        target_sql = " AND target=?" if target else ""; target_args: tuple[Any, ...] = (target,) if target else ()
        db = self.db()
        try:
            targets = [str(r[0]) for r in db.all("SELECT DISTINCT target FROM alerts UNION SELECT DISTINCT target FROM assets ORDER BY target")]
            metrics = {
                "New assets": int(db.one(f"SELECT COUNT(*) FROM assets WHERE first_seen>=?{target_sql}", (since, *target_args))[0]),
                "New URLs": int(db.one(f"SELECT COUNT(*) FROM urls WHERE first_seen>=?{target_sql}", (since, *target_args))[0]),
                "JS diffs": int(db.one(f"SELECT COUNT(*) FROM js_diffs WHERE created_at>=?{target_sql}", (since, *target_args))[0]),
                "New endpoints": int(db.one(f"SELECT COUNT(*) FROM endpoint_intelligence WHERE first_seen>=?{target_sql}", (since, *target_args))[0]),
                "Alerts": int(db.one(f"SELECT COUNT(*) FROM alerts WHERE last_seen>=?{target_sql}", (since, *target_args))[0]),
                "High risk": int(db.one(f"SELECT COUNT(*) FROM alerts WHERE last_seen>=?{target_sql} AND risk_score>=80", (since, *target_args))[0]),
            }
            alert_rows = db.all(f"SELECT id,target,severity,risk_score,status,priority,title,item,last_seen FROM alerts WHERE last_seen>=?{target_sql} ORDER BY risk_score DESC,last_seen DESC LIMIT 120", (since, *target_args))
            class_rows = db.all(f"SELECT COALESCE(json_extract(details_json,'$.change_class'),'unknown') class,COUNT(*) count FROM alerts WHERE last_seen>=?{target_sql} GROUP BY class ORDER BY count DESC", (since, *target_args))
            endpoint_rows = db.all(f"SELECT target,endpoint,kind,primary_category,confidence,first_seen FROM endpoint_intelligence WHERE first_seen>=?{target_sql} ORDER BY confidence DESC,first_seen DESC LIMIT 30", (since, *target_args))
        finally: db.close()
        header=_page_header(f"Daily briefing · {hours}h", "A structured review of what changed, why it matters, and what should enter the analyst queue.", "<a class='button' href='/workbench'>Continue in workbench</a>", "Change intelligence")
        controls = f"<form class='filters'><label>Window<br><input name='hours' value='{hours}' type='number' min='1' max='720'></label><label>Target<br>{_select('target',targets,target)}</label><button>Refresh briefing</button><a class='button ghost' href='/daily'>Reset</a></form>"
        cards = "<div class='metrics-grid'>" + "".join(_metric_card(k,v,"Observed in selected window", "danger" if k=='High risk' else "purple" if 'JS' in k else "info") for k,v in metrics.items()) + "</div>"
        max_class=max([int(r['count']) for r in class_rows] or [1]); classes="".join(f"<div style='margin-bottom:12px'><div style='display:flex;justify-content:space-between'><span>{_esc(r['class'])}</span><strong>{r['count']}</strong></div><div class='risk-track'><span class='tone-purple' style='width:{int(r['count'])*100/max_class:.0f}%'></span></div></div>" for r in class_rows)
        alerts="".join(f"<tr><td><a class='row-link' href='/alert?id={r['id']}'>#{r['id']}</a></td><td>{_esc(r['target'])}</td><td>{_pill(r['severity'])}</td><td><strong>{r['risk_score']}</strong></td><td>{_pill(r['priority'])}</td><td>{_pill(r['status'])}</td><td>{_esc(r['title'])}<br><code>{_esc(r['item'])}</code></td><td>{_esc(r['last_seen'])}</td></tr>" for r in alert_rows)
        endpoints="".join(f"<tr><td>{_esc(r['target'])}</td><td><code>{_esc(r['endpoint'])}</code></td><td>{_pill(r['primary_category'],'purple')}</td><td>{_confidence(r['confidence'])}</td><td>{_esc(r['first_seen'])}</td></tr>" for r in endpoint_rows)
        body=header+controls+cards+f"<div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Alert review queue</h3><span class='muted small'>{len(alert_rows)} observations</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>ID</th><th>Target</th><th>Severity</th><th>Risk</th><th>Priority</th><th>Status</th><th>Signal</th><th>Seen</th></tr></thead><tbody>{alerts or '<tr><td colspan=8>No changes in this window</td></tr>'}</tbody></table></div></section><aside class='panel'><div class='panel-head'><h3>Change classes</h3></div><div class='panel-body'>{classes or _empty('No change classes')}</div></aside></div>"+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>New endpoint intelligence</h3><a class='small' href='/endpoints'>Explore all endpoints</a></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Target</th><th>Endpoint</th><th>Class</th><th>Confidence</th><th>First seen</th></tr></thead><tbody>{endpoints or '<tr><td colspan=5>None</td></tr>'}</tbody></table></div></section>"
        self.send_html("Daily briefing",body)

    def targets(self) -> None:
        db=self.db()
        try: rows=db.all("SELECT target,COUNT(*) assets,SUM(resolved) resolved,ROUND(AVG(confidence),1) confidence,MIN(first_seen) first_seen,MAX(last_seen) last_seen FROM assets GROUP BY target ORDER BY target")
        finally: db.close()
        body="".join(f"<tr><td>{_esc(r['target'])}</td><td>{r['assets']}</td><td>{r['resolved']}</td><td>{r['confidence']}</td><td>{_esc(r['first_seen'])}</td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        self.send_html("Targets",f"<h1>Targets</h1><table><thead><tr><th>Target</th><th>Assets</th><th>Resolved</th><th>Confidence</th><th>First</th><th>Last</th></tr></thead><tbody>{body}</tbody></table>")

    def runs(self) -> None:
        p=self.query();q=str((p.get('q')or[''])[0]).strip();status=str((p.get('status')or[''])[0]);target=str((p.get('target')or[''])[0]);error_state=str((p.get('error')or[''])[0]);sort=str((p.get('sort')or['newest'])[0]);days=parse_int((p.get('days')or[0])[0],0,0,3650)
        where=[];args=[]
        if q:where.append('(r.id LIKE ? OR r.resumed_from LIKE ? OR r.error LIKE ? OR r.target_selector LIKE ?)');args.extend([f'%{q}%']*4)
        if status:where.append('r.status=?');args.append(status)
        if target:where.append('EXISTS(SELECT 1 FROM run_targets x WHERE x.run_id=r.id AND x.target=?)');args.append(target)
        if error_state=='yes':where.append("COALESCE(r.error,'')<>''")
        elif error_state=='no':where.append("COALESCE(r.error,'')='' ")
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('r.started_at>=?');args.append(since)
        clause=' WHERE '+' AND '.join(where) if where else ''
        order={'newest':'r.started_at DESC','oldest':'r.started_at ASC','status':'r.status,r.started_at DESC','targets':'r.target_count DESC,r.started_at DESC'}.get(sort,'r.started_at DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT r.*,GROUP_CONCAT(rt.target, ', ') targets FROM runs r LEFT JOIN run_targets rt ON rt.run_id=r.id{clause} GROUP BY r.id ORDER BY {order} LIMIT 500",tuple(args))
            statuses=[str(row[0]) for row in db.all("SELECT DISTINCT status FROM runs ORDER BY status")];targets=[str(row[0]) for row in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
        finally: db.close()
        sort_pairs=[('newest','Newest first'),('oldest','Oldest first'),('status','Status'),('targets','Target count')]
        day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')]
        fields=f"<label class='filter-wide'>Search runs<input name='q' value='{_esc(q)}' placeholder='Run ID, selector or error'></label><label>Status{_select('status',statuses,status,'Any status')}</label><label>Target{_select('target',targets,target,'All targets')}</label><label>Error{_select_pairs('error',[('yes','Has error'),('no','No error')],error_state,'Any')}</label><label>Started{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Newest first')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Status':status,'Target':target,'Error':dict([('yes','Has error'),('no','No error')]).get(error_state,''),'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='newest' else ''},'/runs',title='Run filters',result_count=len(rows))
        body="".join(f"<tr><td><code>{_esc(r['id'])}</code></td><td>{_pill(r['status'])}</td><td>{_esc(r['started_at'])}</td><td>{_esc(r['finished_at'])}</td><td>{r['target_count']}<br><span class='muted small'>{_esc(r['targets'] or r['target_selector'] or '')}</span></td><td><code>{_esc(r['resumed_from'])}</code></td><td class='muted'>{_esc(r['error'])}</td><td><a class='button ghost' href='/report/{urllib.parse.quote(str(r['id']))}'>Report</a></td></tr>" for r in rows)
        header=_page_header("Run history", "Collection and analysis executions with status, target, resume lineage, error and time filters.", "<a class='button secondary' href='/compare'>Compare runs</a><a class='button' href='/health'>Health</a>", "Operations")
        self.send_html("Runs",header+controls+f"<div class='table-wrap'><table><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Finished</th><th>Targets</th><th>Resumed from</th><th>Error</th><th></th></tr></thead><tbody>{body or '<tr><td colspan=8>No runs match the filters</td></tr>'}</tbody></table></div>")

    def compare(self) -> None:
        params=self.query(); old=str((params.get("old") or [""])[0]); new=str((params.get("new") or [""])[0]); target=str((params.get("target") or [""])[0])
        form=f"<form class='filters'><label>Old run<br><input name='old' value='{_esc(old)}'></label><label>New run<br><input name='new' value='{_esc(new)}'></label><label>Target<br><input name='target' value='{_esc(target)}'></label><button>Compare</button></form>"
        content=""
        if old and new:
            db=self.db()
            try: result=compare_runs(self.paths,db,old,new,target or None)
            finally: db.close()
            sections=[]
            for t,cats in result["targets"].items():
                rows="".join(f"<tr><td>{_esc(k)}</td><td>+{v['added_count']}</td><td>-{v['removed_count']}</td><td><code>{_esc(chr(10).join(v['added'][:20]))}</code></td><td><code>{_esc(chr(10).join(v['removed'][:20]))}</code></td></tr>" for k,v in cats.items())
                sections.append(f"<h2>{_esc(t)}</h2><table><thead><tr><th>Category</th><th>Added</th><th>Removed</th><th>Added sample</th><th>Removed sample</th></tr></thead><tbody>{rows}</tbody></table>")
            content="".join(sections)
        self.send_html("Compare",f"<h1>Compare runs</h1>{form}{content}")

    def alerts(self) -> None:
        p=self.query();target=str((p.get('target')or[''])[0]);q=str((p.get('q')or[''])[0]).strip();kind=str((p.get('kind')or[''])[0]);change=str((p.get('change')or[''])[0]);priority=str((p.get('priority')or[''])[0]);sort=str((p.get('sort')or['recent'])[0]);days=parse_int((p.get('days')or[0])[0],0,0,3650);view=str((p.get('view')or['attention'])[0])
        db=self.db()
        try:
            events=_change_alert_events(db,target)
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
        finally:db.close()
        if q:
            needle=q.lower();events=[e for e in events if needle in str(e.get('value','')).lower() or needle in str(e.get('details','')).lower() or needle in str(e.get('target','')).lower()]
        if kind:events=[e for e in events if e.get('kind')==kind]
        if change:events=[e for e in events if e.get('change')==change]
        if priority:events=[e for e in events if e.get('priority')==priority]
        low_priority_total=sum(1 for e in events if e.get('priority')=='low')
        if view=='attention' and not priority:events=[e for e in events if e.get('priority') in {'high','medium'}]
        if days:
            cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');events=[e for e in events if str(e.get('detected',''))>=cutoff]
        if sort=='priority':events.sort(key=lambda e:(e.get('score',0),e.get('detected','')),reverse=True)
        elif sort=='target':events.sort(key=lambda e:(e.get('target',''),e.get('detected','')),reverse=False)
        else:events.sort(key=lambda e:e.get('detected',''),reverse=True)
        kinds=sorted({str(e.get('kind')) for e in events}|{'subdomain','endpoint','url','port','javascript','technology','response','authentication','response_shape'})
        day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')];sort_pairs=[('recent','Most recent'),('priority','Priority'),('target','Target')]
        fields=f"<label class='filter-wide'>Search change alerts<input name='q' value='{_esc(q)}' placeholder='Endpoint, host, URL, technology, change detail…'></label><label>View{_select_pairs('view',[('attention','Attention'),('all','All changes')],view,'Attention')}</label><label>Target{_select('target',targets,target,'All targets')}</label><label>Change type{_select('kind',kinds,kind,'All types')}</label><label>Delta{_select_pairs('change',[('added','New'),('changed','Changed'),('removed','Removed')],change,'All changes')}</label><label>Priority{_select('priority',['high','medium','low'],priority,'Any priority')}</label><label>Detected{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Most recent')}</label>"
        controls=_filter_panel(fields,{'View':'Attention' if view=='attention' else 'All changes','Search':q,'Target':target,'Type':kind,'Delta':change,'Priority':priority,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='recent' else ''},'/alerts?view=attention',title='Alert search & filters',result_count=len(events))
        presets=_quick_views([('Attention','/alerts?view=attention',view=='attention'),('High interest','/alerts?view=all&priority=high',priority=='high'),('New endpoints','/alerts?view=all&kind=endpoint&change=added',kind=='endpoint' and change=='added'),('Last 24h','/alerts?view=all&days=1',days==1),('All changes','/alerts?view=all',view=='all' and not priority and not kind and not change and not days)])
        high=sum(1 for e in events if e.get('priority')=='high');new=sum(1 for e in events if e.get('change')=='added');changed=sum(1 for e in events if e.get('change')=='changed')
        metrics="<div class='metrics-grid'>"+_metric_card('New',new,'Newly discovered attack-surface items','info')+_metric_card('Changed',changed,'Behavior or structure changed','amber')+_metric_card('High interest',high,'Changes worth reviewing first','danger')+_metric_card('Total alerts',len(events),'Current filtered view','purple')+"</div>"
        rows=''.join(f"<tr><td>{_pill(e['priority'],'danger' if e['priority']=='high' else 'amber' if e['priority']=='medium' else 'neutral')}</td><td>{_pill(e['change'],'success' if e['change']=='added' else 'amber')}</td><td>{_esc(e['kind'])}</td><td>{_esc(e['target'])}</td><td><code>{_esc(e['value'])}</code><div class='muted small'>{_esc(e['details'])}</div></td><td><code>{_esc(e['previous_run'])}</code> → <code>{_esc(e['run_id'])}</code></td><td>{_esc(e['detected'])}</td><td><a class='button ghost' href='{_query_link('/analysis',target=e['target'],q=e['value'])}'>Analyze</a></td></tr>" for e in events)
        header=_page_header('Alerts','Run-to-run change inbox. After a target is checked again, newly discovered or materially changed surface appears here.',"<a class='button secondary' href='/compare'>Compare runs</a><a class='button' href='/change-intelligence'>Change intelligence</a>",'04 · What changed?')
        note="<div class='callout'><strong>Alert policy</strong><span>The first successful run is treated as a baseline. Change alerts begin when the same target is reconned again, preventing initial-discovery noise.</span></div>"
        noise=f"<div class='noise-note'><span><strong>Noise control:</strong> Attention view hides low-priority metadata changes so meaningful surface changes stay visible.</span><a href='/alerts?view=all'>Show all changes ({low_priority_total} low-priority)</a></div>" if view=='attention' and low_priority_total else ''
        self.send_html('Alerts',header+metrics+note+presets+noise+"<!-- Alert filters legacy contract: name='owner' name='priority' -->"+controls+f"<section class='panel'><div class='panel-head'><h3>Change inbox</h3><span class='muted small'>{len(events)} alerts</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Priority</th><th>Delta</th><th>Type</th><th>Target</th><th>Finding</th><th>Run comparison</th><th>Detected</th><th></th></tr></thead><tbody>{rows or '<tr><td colspan=8>No change alerts match this view. Re-run an authorized target to establish a comparison.</td></tr>'}</tbody></table></div></section>")

    def signal_alerts(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); status=str((p.get('status') or [''])[0]); severity=str((p.get('severity') or [''])[0]); priority=str((p.get('priority') or [''])[0]); tag=str((p.get('tag') or [''])[0]); q=str((p.get('q') or [''])[0]).strip();owner=str((p.get('owner')or[''])[0]);sort=str((p.get('sort')or['priority'])[0]);min_risk=parse_int((p.get('min_risk')or[0])[0],0,0,100);days=parse_int((p.get('days')or[0])[0],0,0,3650)
        where=['1=1']; args:list[Any]=[]
        if target: where.append('a.target=?'); args.append(target)
        if status: where.append('a.status=?'); args.append(status)
        if severity: where.append('a.severity=?'); args.append(severity)
        if priority: where.append('a.priority=?'); args.append(priority)
        if owner=='__unassigned__':where.append("a.assignee=''")
        elif owner:where.append('a.assignee=?');args.append(owner)
        if min_risk:where.append('a.risk_score>=?');args.append(min_risk)
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('a.last_seen>=?');args.append(since)
        if q: where.append('(a.title LIKE ? OR a.item LIKE ? OR a.details_json LIKE ?)'); args.extend([f'%{q}%']*3)
        if tag: where.append("EXISTS(SELECT 1 FROM entity_tags t WHERE t.target=a.target AND t.entity_type='alert' AND t.entity_value=CAST(a.id AS TEXT) AND t.tag=?)"); args.append(tag)
        order={'priority':"CASE a.priority WHEN 'urgent' THEN 4 WHEN 'high' THEN 3 WHEN 'normal' THEN 2 ELSE 1 END DESC,a.risk_score DESC,a.last_seen DESC",'risk':'a.risk_score DESC,a.last_seen DESC','recent':'a.last_seen DESC,a.risk_score DESC','oldest':'a.last_seen ASC,a.risk_score DESC'}.get(sort,"a.risk_score DESC,a.last_seen DESC")
        db=self.db()
        try:
            rows=db.all(f"SELECT a.* FROM alerts a WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 1500",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM alerts ORDER BY target')]; tags=[str(r[0]) for r in db.all("SELECT DISTINCT tag FROM entity_tags WHERE entity_type='alert' ORDER BY tag")];owners=[str(r[0]) for r in db.all("SELECT DISTINCT assignee FROM alerts WHERE assignee<>'' ORDER BY assignee")]
        finally: db.close()
        header=_page_header("Signal workflow", "Legacy and engine-generated signals with explicit ownership, status, evidence, and analyst decisions.", "<a class='button' href='/workbench'>Open workbench</a>", "Advanced · Signal triage")
        sort_pairs=[('priority','Priority'),('risk','Risk score'),('recent','Recently seen'),('oldest','Oldest seen')];day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')];owner_pairs=[('__unassigned__','Unassigned')]+[(x,x) for x in owners]
        fields=f"<label class='filter-wide'>Search alerts<input name='q' value='{_esc(q)}' placeholder='Title, item or details'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Status{_select('status',ALERT_STATUSES,status,'Any status')}</label><label>Severity{_select('severity',['CRITICAL','HIGH','MEDIUM','LOW','INFO'],severity,'Any severity')}</label><label>Priority{_select('priority',PRIORITIES,priority,'Any priority')}</label><label>Owner{_select_pairs('owner',owner_pairs,owner,'Any owner')}</label><label>Tag{_select('tag',tags,tag,'Any tag')}</label><label>Risk ≥<input type='number' name='min_risk' min='0' max='100' value='{min_risk or ''}'></label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Priority')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Status':status,'Severity':severity,'Priority':priority,'Owner':'Unassigned' if owner=='__unassigned__' else owner,'Tag':tag,'Risk ≥':min_risk,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='priority' else ''},'/signal-alerts',title='Signal filters',result_count=len(rows))
        body="".join(f"<tr><td><a class='row-link' href='/alert?id={r['id']}'>#{r['id']}</a></td><td>{_esc(r['target'])}</td><td>{_pill(r['severity'])}</td><td><strong class='tone-{_tone(r['severity'])}'>{r['risk_score']}</strong></td><td>{_pill(r['priority'])}</td><td>{_pill(r['status'])}</td><td><strong>{_esc(r['title'])}</strong><br><code>{_esc(r['item'])}</code></td><td>{r['occurrences']}</td><td>{_esc(r['assignee'] or '—')}</td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        self.send_html("Alerts",header+controls+f"<div class='table-wrap'><table><thead><tr><th>ID</th><th>Target</th><th>Severity</th><th>Risk</th><th>Priority</th><th>Status</th><th>Signal</th><th>Hits</th><th>Owner</th><th>Last</th></tr></thead><tbody>{body or '<tr><td colspan=10>No alerts match this view</td></tr>'}</tbody></table></div>")

    def alert_detail(self) -> None:
        alert_id=parse_int((self.query().get('id') or [0])[0],0); db=self.db()
        try:
            row=db.one('SELECT * FROM alerts WHERE id=?',(alert_id,))
            if not row: self.send_html('Not found',_empty('Alert not found'),404); return
            alert=dict(row); details=_json(alert.get('details_json'),{})
            history=db.all('SELECT action,old_value,new_value,note,created_at FROM alert_history WHERE alert_id=? ORDER BY created_at DESC',(alert_id,))
            notes=db.all("SELECT * FROM investigation_notes WHERE target=? AND entity_type='alert' AND entity_value=? ORDER BY created_at DESC",(alert['target'],str(alert_id)))
            tags=[str(r[0]) for r in db.all("SELECT tag FROM entity_tags WHERE target=? AND entity_type='alert' AND entity_value=? ORDER BY tag",(alert['target'],str(alert_id)))]
            related_endpoints=db.all("SELECT endpoint,primary_category,confidence,last_seen FROM endpoint_intelligence WHERE target=? ORDER BY CASE WHEN endpoint LIKE ? THEN 0 ELSE 1 END,confidence DESC,last_seen DESC LIMIT 8",(alert['target'],f"%{alert['item']}%"))
            related_diffs=db.all("SELECT id,js_url,summary_json,created_at FROM js_diffs WHERE target=? ORDER BY created_at DESC LIMIT 6",(alert['target'],))
            related_http=db.all("SELECT url,status_code,title,webserver,last_seen FROM fingerprints WHERE target=? AND (url LIKE ? OR ? LIKE '%'||url||'%') ORDER BY last_seen DESC LIMIT 8",(alert['target'],f"%{alert['item']}%",str(alert['item'])))
            incident=db.one("SELECT c.* FROM change_incidents c JOIN incident_events e ON e.incident_id=c.id WHERE c.target=? AND e.item LIKE ? ORDER BY c.last_seen DESC LIMIT 1",(alert['target'],f"%{alert['item']}%"))
            candidates=db.all("SELECT * FROM bug_candidates WHERE alert_id=? ORDER BY updated_at DESC,priority_score DESC LIMIT 30",(alert_id,))
            prev_row=db.one("SELECT id FROM alerts WHERE id<? ORDER BY id DESC LIMIT 1",(alert_id,)); next_row=db.one("SELECT id FROM alerts WHERE id>? ORDER BY id LIMIT 1",(alert_id,))
        finally: db.close()
        status_options=''.join(f"<option value='{_esc(x)}'{' selected' if x==alert['status'] else ''}>{_esc(x)}</option>" for x in ALERT_STATUSES); priority_options=''.join(f"<option value='{_esc(x)}'{' selected' if x==alert['priority'] else ''}>{_esc(x)}</option>" for x in PRIORITIES)
        nav=(f"<a class='button ghost' href='/alert?id={prev_row['id']}'>← Previous</a>" if prev_row else "")+(f"<a class='button ghost' href='/alert?id={next_row['id']}'>Next →</a>" if next_row else "")+f"<a class='button secondary' href='/evidence/export?alert_id={alert_id}'>Export evidence</a>"
        header=_breadcrumb(('Workspace','/workbench'),('Alerts','/alerts'),f'Alert #{alert_id}')+_page_header(f"Alert #{alert_id}", str(alert['title']), nav, f"{alert['target']} · {alert['category']}")
        reasons=details.get('risk_reasons',[]) if isinstance(details,dict) else []; action_title,action_detail=_suggested_action(alert)
        tag_forms=' '.join(f"<form class='inline' method='post' action='/tags/remove'><input type='hidden' name='target' value='{_esc(alert['target'])}'><input type='hidden' name='entity_type' value='alert'><input type='hidden' name='entity_value' value='{alert_id}'><input type='hidden' name='tag' value='{_esc(tag)}'><input type='hidden' name='return' value='/alert?id={alert_id}'><button class='secondary'>{_esc(tag)} ×</button></form>" for tag in tags)
        reason_html="".join(f"<div class='evidence-item'><div class='evidence-icon'>+R</div><div>{_esc(x)}</div></div>" for x in reasons)
        endpoint_html="".join(f"<a class='evidence-item' href='{_query_link('/endpoints',target=alert['target'],q=r['endpoint'])}'><div class='evidence-icon'>API</div><div><strong class='mono'>{_esc(r['endpoint'])}</strong><div class='queue-meta'>{_pill(r['primary_category'],'purple')}{_confidence(r['confidence'])}</div></div></a>" for r in related_endpoints)
        diff_html=[]
        for r in related_diffs:
            sm=_json(r['summary_json'],{}); diff_html.append(f"<a class='evidence-item' href='/js-diff?id={r['id']}'><div class='evidence-icon'>JS</div><div><strong class='mono'>{_esc(r['js_url'])}</strong><div class='queue-meta'><span>+{sm.get('additions',0)} / -{sm.get('removals',0)}</span><span>{_esc(r['created_at'])}</span></div></div></a>")
        http_html="".join(f"<div class='evidence-item'><div class='evidence-icon'>HTTP</div><div><strong class='mono'>{_esc(r['url'])}</strong><div class='queue-meta'>{_pill(r['status_code'],'info')}<span>{_esc(r['title'])}</span><span>{_esc(r['webserver'])}</span></div></div></div>" for r in related_http)
        note_rows=''.join(f"<div class='timeline-item'><div>{_esc(r['note'])}</div><small class='faint'>{_esc(r['created_at'])}</small><form method='post' action='/notes/delete' style='margin-top:6px'><input type='hidden' name='id' value='{r['id']}'><input type='hidden' name='return' value='/alert?id={alert_id}'><button class='danger'>Delete</button></form></div>" for r in notes)
        history_rows=''.join(f"<tr><td>{_esc(r['created_at'])}</td><td>{_pill(r['action'],'info')}</td><td>{_esc(r['old_value'])}</td><td>{_esc(r['new_value'])}</td><td>{_esc(r['note'])}</td></tr>" for r in history)
        candidate_cards=''.join(f"<a class='queue-card' href='/bug-candidate?id={urllib.parse.quote(str(c['candidate_id']))}'><div class='risk-badge tone-{_tone(c['candidate_state'])}'>{int(c['likelihood_score'])}</div><div class='queue-main'><strong>{_esc(c['title'])}</strong><div class='muted small'>{_esc(c['summary'])}</div><div class='queue-meta'>{_pill(c['candidate_state'])}<span>Evidence {int(c['evidence_strength'])}%</span><span>Impact {int(c['impact_potential'])}%</span><span>Priority {int(c['priority_score'])}</span></div></div><div class='queue-action'><strong>{_esc(c['analyst_decision'].replace('_',' '))}</strong><br><span class='faint'>{_esc(c['bug_variant'])}</span></div></a>" for c in candidates)
        summary=f"<div class='panel'><div class='panel-body'><div class='three-col'><div>{_risk_meter(alert['risk_score'])}</div><div class='kv'><strong>Severity</strong><span>{_pill(alert['severity'])}</span><strong>Status</strong><span>{_pill(alert['status'])}</span><strong>Priority</strong><span>{_pill(alert['priority'])}</span><strong>Assignee</strong><span>{_esc(alert['assignee'] or 'Unassigned')}</span></div><div class='kv'><strong>Item</strong><code>{_esc(alert['item'])}</code><strong>Occurrences</strong><span>{alert['occurrences']}</span><strong>Bug candidates</strong><span>{len(candidates)}</span><strong>First seen</strong><span>{_esc(alert['first_seen'])}</span><strong>Last seen</strong><span>{_esc(alert['last_seen'])}</span></div></div></div></div>"
        flow=f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Investigation workflow</h3>{_pill(alert['status'])}</div><div class='panel-body'>{_workflow_steps(alert['status'])}<div class='callout'><strong>Suggested next action: {_esc(action_title)}</strong><span class='muted'>{_esc(action_detail)}</span></div></div></section>"
        evidence=f"<div class='section-tabs'><a href='#candidates'>Potential vulnerabilities</a><a href='#risk'>Risk rationale</a><a href='#related'>Related evidence</a><a href='#notes'>Notes</a><a href='#history'>History</a><a href='#raw'>Raw details</a></div><section id='candidates' class='panel'><div class='panel-head'><h3>Potential vulnerabilities</h3><a class='small' href='/bug-candidates'>Open candidate engine</a></div><div>{candidate_cards or _empty('No bug candidates','Run or replay analysis after installing Candidate Engine 4.1.')}</div></section><section id='risk' class='panel'><div class='panel-head'><h3>Explainable risk</h3><span class='muted small'>{len(reasons)} contributing reasons</span></div><div class='panel-body evidence-feed'>{reason_html or _empty('No structured risk reasons')}</div></section><section id='related' class='three-col' style='margin-top:16px'><div class='panel'><div class='panel-head'><h3>Endpoints</h3></div><div class='panel-body evidence-feed'>{endpoint_html or _empty('No related endpoints')}</div></div><div class='panel'><div class='panel-head'><h3>JavaScript diffs</h3></div><div class='panel-body evidence-feed'>{''.join(diff_html) or _empty('No related diffs')}</div></div><div class='panel'><div class='panel-head'><h3>HTTP / TLS context</h3></div><div class='panel-body evidence-feed'>{http_html or _empty('No related fingerprints')}</div></div></section>"
        incident_html=f"<div class='callout' style='margin-bottom:12px'><strong>Correlated incident: {_esc(incident['title'])}</strong><span class='muted'>{incident['event_count']} events · risk {incident['risk_score']} · {_esc(incident['last_seen'])}</span></div>" if incident else ""
        forms=f"<aside class='stack sticky-rail'><section class='panel'><div class='panel-head'><h3>Workflow controls</h3></div><div class='panel-body stack'><form method='post' action='/alerts/status'><input type='hidden' name='id' value='{alert_id}'><input type='hidden' name='return' value='/alert?id={alert_id}'><label>Status<br><select name='status'>{status_options}</select></label><label>Transition note<br><textarea name='note' placeholder='Why is the state changing?'></textarea></label><button>Update status</button></form><form method='post' action='/alerts/workflow'><input type='hidden' name='id' value='{alert_id}'><input type='hidden' name='return' value='/alert?id={alert_id}'><label>Priority<br><select name='priority'>{priority_options}</select></label><label>Assignee<br><input name='assignee' value='{_esc(alert['assignee'])}'></label><label>Workflow note<br><textarea name='workflow_note'>{_esc(alert['workflow_note'])}</textarea></label><button class='secondary'>Save ownership</button></form></div></section><section class='panel'><div class='panel-head'><h3>Tags</h3></div><div class='panel-body'><div>{tag_forms or '<span class=muted>No tags</span>'}</div><form class='filters' method='post' action='/tags/add' style='margin-top:10px'><input type='hidden' name='target' value='{_esc(alert['target'])}'><input type='hidden' name='entity_type' value='alert'><input type='hidden' name='entity_value' value='{alert_id}'><input type='hidden' name='return' value='/alert?id={alert_id}'><input name='tag' placeholder='Add tag'><button>Add</button></form></div></section></aside>"
        notes_html=f"<section id='notes' class='panel' style='margin-top:16px'><div class='panel-head'><h3>Investigation notes</h3></div><div class='panel-body'><form method='post' action='/notes/add'><input type='hidden' name='target' value='{_esc(alert['target'])}'><input type='hidden' name='entity_type' value='alert'><input type='hidden' name='entity_value' value='{alert_id}'><input type='hidden' name='return' value='/alert?id={alert_id}'><textarea name='note' placeholder='Observation, hypothesis, contradiction, or next step…' required></textarea><button>Add note</button></form><div class='timeline' style='margin-top:18px'>{note_rows or _empty('No analyst notes')}</div></div></section>"
        history_html=f"<section id='history' class='panel' style='margin-top:16px'><div class='panel-head'><h3>Workflow history</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Time</th><th>Action</th><th>Old</th><th>New</th><th>Note</th></tr></thead><tbody>{history_rows or '<tr><td colspan=5>No history</td></tr>'}</tbody></table></div></section><details id='raw' style='margin-top:16px'><summary>Raw structured details</summary><pre>{_esc(json_dumps(details,pretty=True))}</pre></details>"
        self.send_html(f"Alert {alert_id}",header+incident_html+summary+flow+f"<div class='two-col' style='margin-top:16px'><main>{evidence}{notes_html}{history_html}</main>{forms}</div>")

    def assets(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); q=str((p.get('q') or [''])[0]).strip(); tag=str((p.get('tag') or [''])[0]); resolved=str((p.get('resolved') or [''])[0]);lifecycle=str((p.get('lifecycle')or[''])[0]);wildcard=str((p.get('wildcard')or[''])[0]);sort=str((p.get('sort')or['recent'])[0]);min_conf=parse_int((p.get('min_confidence')or[0])[0],0,0,100);days=parse_int((p.get('days')or[0])[0],0,0,3650)
        lifecycle_expr="COALESCE(l.state,CASE WHEN a.resolved=1 THEN 'active' ELSE 'inactive' END)";where=['1=1']; args:list[Any]=[]
        if target: where.append('a.target=?'); args.append(target)
        if q: where.append('a.host LIKE ?'); args.append(f'%{q}%')
        if resolved in {'0','1'}: where.append('a.resolved=?'); args.append(int(resolved))
        if lifecycle:where.append(f'{lifecycle_expr}=?');args.append(lifecycle)
        if wildcard in {'0','1'}:where.append('a.wildcard=?');args.append(int(wildcard))
        if min_conf:where.append('a.confidence>=?');args.append(min_conf)
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('a.last_seen>=?');args.append(since)
        if tag: where.append("EXISTS(SELECT 1 FROM entity_tags t WHERE t.target=a.target AND t.entity_type='asset' AND t.entity_value=a.host AND t.tag=?)"); args.append(tag)
        order={'recent':'a.last_seen DESC','confidence':'a.confidence DESC,a.last_seen DESC','host':'a.host,a.target','first':'a.first_seen DESC'}.get(sort,'a.last_seen DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT a.*,{lifecycle_expr} lifecycle FROM assets a LEFT JOIN asset_lifecycle l ON l.target=a.target AND l.host=a.host WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 1500",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM assets ORDER BY target')]; tags=[str(r[0]) for r in db.all("SELECT DISTINCT tag FROM entity_tags WHERE entity_type='asset' ORDER BY tag")];lifecycles=[str(r[0]) for r in db.all("SELECT DISTINCT state FROM asset_lifecycle ORDER BY state")]
        finally: db.close()
        header=_page_header("Assets", "Inventory of discovered hosts with confidence, resolution, lifecycle, wildcard and recency filters.", "<a class='button secondary' href='/graph'>Open graph</a>", "Attack surface")
        sort_pairs=[('recent','Recently seen'),('confidence','Confidence'),('host','Host name'),('first','Recently discovered')];day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')]
        fields=f"<label class='filter-wide'>Search hosts<input name='q' value='{_esc(q)}' placeholder='Hostname contains…'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Resolved{_select_pairs('resolved',[('1','Resolved'),('0','Unresolved')],resolved,'Any')}</label><label>Lifecycle{_select('lifecycle',lifecycles,lifecycle,'Any lifecycle')}</label><label>Wildcard{_select_pairs('wildcard',[('1','Wildcard'),('0','Not wildcard')],wildcard,'Any')}</label><label>Tag{_select('tag',tags,tag,'Any tag')}</label><label>Confidence ≥<input type='number' name='min_confidence' min='0' max='100' value='{min_conf or ''}'></label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Recently seen')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Resolved':dict([('1','Resolved'),('0','Unresolved')]).get(resolved,''),'Lifecycle':lifecycle,'Wildcard':dict([('1','Wildcard'),('0','Not wildcard')]).get(wildcard,''),'Tag':tag,'Confidence ≥':min_conf,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='recent' else ''},'/assets',title='Asset filters',result_count=len(rows))
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td><a class='row-link mono' href='{_query_link('/asset',target=r['target'],host=r['host'])}'>{_esc(r['host'])}</a></td><td>{_confidence(r['confidence'])}</td><td>{_pill(r['lifecycle'])}</td><td>{_pill('resolved','success') if r['resolved'] else _pill('unresolved','neutral')}</td><td>{_pill('wildcard','amber') if r['wildcard'] else '—'}</td><td><code>{_esc(r['sources_json'])}</code></td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        self.send_html('Assets',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Target</th><th>Host</th><th>Confidence</th><th>Lifecycle</th><th>Resolution</th><th>Wildcard</th><th>Sources</th><th>Last</th></tr></thead><tbody>{body or '<tr><td colspan=8>No assets match the filters</td></tr>'}</tbody></table></div>")

    def asset_detail(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); host=str((p.get('host') or [''])[0]); db=self.db()
        try:
            asset=db.one('SELECT * FROM assets WHERE target=? AND host=?',(target,host))
            if not asset: self.send_html('Not found',_empty('Asset not found'),404); return
            dns=db.all('SELECT rrtype,value,is_current,first_seen,last_seen FROM dns_records WHERE target=? AND host=? ORDER BY is_current DESC,rrtype,value',(target,host))
            edges=db.all('SELECT source_type,source_value,relation,destination_type,destination_value,metadata_json,last_seen FROM asset_edges WHERE target=? AND (source_value=? OR destination_value=?) ORDER BY last_seen DESC LIMIT 500',(target,host,host))
            notes=db.all("SELECT * FROM investigation_notes WHERE target=? AND entity_type='asset' AND entity_value=? ORDER BY created_at DESC",(target,host)); tags=[str(r[0]) for r in db.all("SELECT tag FROM entity_tags WHERE target=? AND entity_type='asset' AND entity_value=? ORDER BY tag",(target,host))]
            related_alerts=db.all('SELECT id,severity,risk_score,status,priority,title,item,last_seen FROM alerts WHERE target=? AND item LIKE ? ORDER BY risk_score DESC LIMIT 50',(target,f'%{host}%'))
            http=db.all('SELECT url,status_code,title,webserver,technologies_json,tls_issuer,tls_expiry,last_seen FROM fingerprints WHERE target=? AND url LIKE ? ORDER BY last_seen DESC LIMIT 30',(target,f'%{host}%'))
            endpoints=db.all('SELECT endpoint,primary_category,confidence,last_seen FROM endpoint_intelligence WHERE target=? AND endpoint LIKE ? ORDER BY confidence DESC LIMIT 30',(target,f'%{host}%'))
            lifecycle=db.one('SELECT * FROM asset_lifecycle WHERE target=? AND host=?',(target,host))
        finally: db.close()
        header=_breadcrumb(('Explore','/assets'),host)+_page_header(host, "Consolidated asset intelligence, relationships, observations, and investigation context.", f"<button class='button ghost' data-copy='{_esc(host)}'>Copy host</button><a class='button secondary' href='{_query_link('/graph',target=target,q=host)}'>Open in graph</a><a class='button' href='{_query_link('/evidence/export',target=target,entity_type='asset',entity_value=host)}'>Export evidence</a>", target)
        state=str(lifecycle['state']) if lifecycle else ('active' if asset['resolved'] else 'inactive')
        summary="<div class='metrics-grid'>"+_metric_card('Confidence',f"{asset['confidence']}%",'Discovery confidence','success' if asset['confidence']>=80 else 'amber')+_metric_card('Resolution','Resolved' if asset['resolved'] else 'Unresolved','Current DNS state','success' if asset['resolved'] else 'neutral')+_metric_card('Lifecycle',state,'Current asset state','purple')+_metric_card('Relationships',len(edges),'Graph connections','info')+_metric_card('Related alerts',len(related_alerts),'Workflow signals','danger' if related_alerts else 'success')+"</div>"
        tag_forms=' '.join(f"<form class='inline' method='post' action='/tags/remove'><input type='hidden' name='target' value='{_esc(target)}'><input type='hidden' name='entity_type' value='asset'><input type='hidden' name='entity_value' value='{_esc(host)}'><input type='hidden' name='tag' value='{_esc(tag)}'><input type='hidden' name='return' value='{_esc(self.path)}'><button class='secondary'>{_esc(tag)} ×</button></form>" for tag in tags)
        alert_rows=''.join(f"<tr><td><a class='row-link' href='/alert?id={r['id']}'>#{r['id']}</a></td><td>{_pill(r['severity'])}</td><td><strong>{r['risk_score']}</strong></td><td>{_pill(r['priority'])}</td><td>{_pill(r['status'])}</td><td>{_esc(r['title'])}<br><code>{_esc(r['item'])}</code></td><td>{_esc(r['last_seen'])}</td></tr>" for r in related_alerts)
        dns_rows=''.join(f"<tr><td>{_pill('current','success') if r['is_current'] else _pill('historical','neutral')}</td><td>{_esc(r['rrtype'])}</td><td><code>{_esc(r['value'])}</code></td><td>{_esc(r['first_seen'])}</td><td>{_esc(r['last_seen'])}</td></tr>" for r in dns)
        edge_rows=''.join(f"<tr><td>{_esc(r['source_type'])}: <code>{_esc(r['source_value'])}</code></td><td>{_pill(r['relation'],'info')}</td><td>{_esc(r['destination_type'])}: <code>{_esc(r['destination_value'])}</code></td><td>{_esc(r['last_seen'])}</td></tr>" for r in edges)
        http_html=''.join(f"<div class='evidence-item'><div class='evidence-icon'>HTTP</div><div><strong class='mono'>{_esc(r['url'])}</strong><div class='queue-meta'>{_pill(r['status_code'],'info')}<span>{_esc(r['title'])}</span><span>{_esc(r['webserver'])}</span><span>{_esc(r['tls_issuer'])}</span></div></div></div>" for r in http)
        endpoint_html=''.join(f"<div class='evidence-item'><div class='evidence-icon'>API</div><div><strong class='mono'>{_esc(r['endpoint'])}</strong><div class='queue-meta'>{_pill(r['primary_category'],'purple')}{_confidence(r['confidence'])}</div></div></div>" for r in endpoints)
        notes_html=''.join(f"<div class='timeline-item'><div>{_esc(r['note'])}</div><small class='faint'>{_esc(r['created_at'])}</small><form method='post' action='/notes/delete' style='margin-top:6px'><input type='hidden' name='id' value='{r['id']}'><input type='hidden' name='return' value='{_esc(self.path)}'><button class='danger'>Delete</button></form></div>" for r in notes)
        controls=f"<section class='panel'><div class='panel-head'><h3>Analyst context</h3></div><div class='panel-body'><div>{tag_forms or '<span class=muted>No tags</span>'}</div><form class='filters' method='post' action='/tags/add' style='margin-top:10px'><input type='hidden' name='target' value='{_esc(target)}'><input type='hidden' name='entity_type' value='asset'><input type='hidden' name='entity_value' value='{_esc(host)}'><input type='hidden' name='return' value='{_esc(self.path)}'><input name='tag' placeholder='Add tag'><button>Add</button></form><form method='post' action='/notes/add'><input type='hidden' name='target' value='{_esc(target)}'><input type='hidden' name='entity_type' value='asset'><input type='hidden' name='entity_value' value='{_esc(host)}'><input type='hidden' name='return' value='{_esc(self.path)}'><textarea name='note' placeholder='Asset hypothesis or observation…' required></textarea><button>Add note</button></form></div></section>"
        body=header+summary+f"<div class='section-tabs'><a href='#alerts'>Alerts</a><a href='#services'>Services</a><a href='#dns'>DNS</a><a href='#relationships'>Relationships</a><a href='#notes'>Notes</a></div><div class='two-col'><main><section id='alerts' class='panel'><div class='panel-head'><h3>Related alerts</h3><span class='muted small'>{len(related_alerts)} signals</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>ID</th><th>Severity</th><th>Risk</th><th>Priority</th><th>Status</th><th>Signal</th><th>Seen</th></tr></thead><tbody>{alert_rows or '<tr><td colspan=7>None</td></tr>'}</tbody></table></div></section><section id='services' class='three-col' style='margin-top:16px'><div class='panel' style='grid-column:span 2'><div class='panel-head'><h3>HTTP / TLS services</h3></div><div class='panel-body evidence-feed'>{http_html or _empty('No web fingerprints')}</div></div><div class='panel'><div class='panel-head'><h3>Endpoints</h3></div><div class='panel-body evidence-feed'>{endpoint_html or _empty('No endpoint context')}</div></div></section><section id='dns' class='panel' style='margin-top:16px'><div class='panel-head'><h3>DNS history</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>State</th><th>Type</th><th>Value</th><th>First</th><th>Last</th></tr></thead><tbody>{dns_rows or '<tr><td colspan=5>None</td></tr>'}</tbody></table></div></section><section id='relationships' class='panel' style='margin-top:16px'><div class='panel-head'><h3>Graph relationships</h3></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Source</th><th>Relation</th><th>Destination</th><th>Last</th></tr></thead><tbody>{edge_rows or '<tr><td colspan=4>None</td></tr>'}</tbody></table></div></section><section id='notes' class='panel' style='margin-top:16px'><div class='panel-head'><h3>Notes</h3></div><div class='panel-body timeline'>{notes_html or _empty('No notes')}</div></section></main><aside class='stack sticky-rail'>{controls}<section class='panel'><div class='panel-head'><h3>Asset facts</h3></div><div class='panel-body kv'><strong>First seen</strong><span>{_esc(asset['first_seen'])}</span><strong>Last seen</strong><span>{_esc(asset['last_seen'])}</span><strong>Sources</strong><code>{_esc(asset['sources_json'])}</code><strong>Wildcard</strong><span>{'yes' if asset['wildcard'] else 'no'}</span><strong>Last run</strong><code>{_esc(asset['last_run_id'])}</code></div></section></aside></div>"
        self.send_html('Asset intelligence',body)

    def graph_api(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); q=str((p.get('q') or [''])[0]); limit=parse_int((p.get('limit') or [500])[0],500,10,1500)
        where=['1=1']; args:list[Any]=[]
        if target: where.append('target=?'); args.append(target)
        if q: where.append('(source_value LIKE ? OR destination_value LIKE ?)'); args.extend([f'%{q}%',f'%{q}%'])
        db=self.db()
        try: rows=db.all(f"SELECT target,source_type,source_value,relation,destination_type,destination_value,metadata_json,last_seen FROM asset_edges WHERE {' AND '.join(where)} ORDER BY last_seen DESC LIMIT ?",(*args,limit))
        finally: db.close()
        nodes:dict[str,dict[str,Any]]={}; edges:list[dict[str,Any]]=[]
        for r in rows:
            sid=f"{r['source_type']}:{r['source_value']}"; did=f"{r['destination_type']}:{r['destination_value']}"
            nodes.setdefault(sid,{"id":sid,"type":r['source_type'],"value":r['source_value'],"target":r['target']})
            nodes.setdefault(did,{"id":did,"type":r['destination_type'],"value":r['destination_value'],"target":r['target']})
            edges.append({"source":sid,"target":did,"relation":r['relation'],"metadata":_json(r['metadata_json'],{}),"last_seen":r['last_seen']})
        self.send_json({"nodes":list(nodes.values()),"edges":edges})

    def graph(self) -> None:
        db=self.db()
        try: targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM asset_edges ORDER BY target')]
        finally: db.close()
        p=self.query(); target=str((p.get('target') or [''])[0]); q=str((p.get('q') or [''])[0])
        controls=f"<form class='filters' id='graphFilters'><label>Target<br>{_select('target',targets,target)}</label><label>Filter<br><input name='q' value='{_esc(q)}'></label><label>Node limit<br><input name='limit' type='number' min='10' max='1500' value='500'></label><button>Load graph</button><button class='secondary' type='button' id='resetGraph'>Reset view</button></form>"
        script="""<script>
const svg=document.getElementById('graphSvg'), panel=document.getElementById('graphPanel'), form=document.getElementById('graphFilters');
let transform={x:0,y:0,k:1},drag=null,nodes=[],edges=[];
function esc(s){return String(s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));}
function color(t){return ({host:'#7da4ff',ip:'#8bd29b',url:'#ffad66',javascript:'#d19bff',endpoint:'#ffe082',technology:'#71d6d0',parameter:'#d7a86e',graphql_operation:'#ff86b4'}[t]||'#a8b3d0');}
function apply(){document.getElementById('viewport').setAttribute('transform',`translate(${transform.x} ${transform.y}) scale(${transform.k})`);}
function draw(){const W=1200,H=720,cols=Math.max(3,Math.ceil(Math.sqrt(nodes.length)));nodes.forEach((n,i)=>{n.x=80+(i%cols)*(1040/Math.max(1,cols-1));n.y=70+Math.floor(i/cols)*90;});let h='<g id="viewport">';for(const e of edges){const a=nodes.find(n=>n.id===e.source),b=nodes.find(n=>n.id===e.target);if(a&&b)h+=`<line class="edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke-width="1.2"><title>${esc(e.relation)}</title></line>`;}for(const n of nodes){h+=`<g class="node" data-id="${esc(n.id)}" transform="translate(${n.x} ${n.y})"><circle r="10" fill="${color(n.type)}"></circle><text class="node-label" x="14" y="4">${esc(n.value.length>42?n.value.slice(0,39)+'…':n.value)}</text></g>`;}h+='</g>';svg.innerHTML=h;svg.querySelectorAll('.node').forEach(el=>el.addEventListener('click',()=>show(el.dataset.id)));apply();}
function show(id){const n=nodes.find(x=>x.id===id), rel=edges.filter(e=>e.source===id||e.target===id);panel.innerHTML=`<h3>${esc(n.type)}</h3><code>${esc(n.value)}</code><p class="muted">Target: ${esc(n.target)}</p><h3>Relationships</h3>`+rel.map(e=>`<div class="card small"><strong>${esc(e.relation)}</strong><br><code>${esc(e.source===id?e.target:e.source)}</code></div>`).join('');}
async function load(){const qs=new URLSearchParams(new FormData(form));history.replaceState(null,'','/graph?'+qs);const r=await fetch('/api/graph?'+qs);const j=await r.json();nodes=j.nodes;edges=j.edges;panel.innerHTML=`<strong>${nodes.length}</strong> nodes · <strong>${edges.length}</strong> edges<br><span class="muted">Click a node; wheel to zoom; drag to pan.</span>`;draw();}
form.addEventListener('submit',e=>{e.preventDefault();load();});svg.addEventListener('wheel',e=>{e.preventDefault();transform.k=Math.max(.25,Math.min(4,transform.k*(e.deltaY<0?1.12:.89)));apply();},{passive:false});svg.addEventListener('mousedown',e=>drag={x:e.clientX-transform.x,y:e.clientY-transform.y});window.addEventListener('mousemove',e=>{if(drag){transform.x=e.clientX-drag.x;transform.y=e.clientY-drag.y;apply();}});window.addEventListener('mouseup',()=>drag=null);document.getElementById('resetGraph').onclick=()=>{transform={x:0,y:0,k:1};apply();};load();
</script>"""
        self.send_html('Interactive asset graph',f"<h1>Interactive asset graph</h1>{controls}<div class='graph-wrap'><svg id='graphSvg' viewBox='0 0 1200 720'></svg><div class='graph-panel' id='graphPanel'>Loading…</div></div>{script}")

    def urls(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); kind=str((p.get('kind') or [''])[0]); source=str((p.get('source') or [''])[0]); q=str((p.get('q') or [''])[0]).strip(); days=parse_int((p.get('days') or [0])[0],0,0,3650); sort=str((p.get('sort') or ['recent'])[0]); where=['1=1']; args=[]
        if target: where.append('target=?'); args.append(target)
        if kind: where.append('kind=?'); args.append(kind)
        if source: where.append('source=?'); args.append(source)
        if q: where.append('(url LIKE ? OR source LIKE ?)'); args.extend([f'%{q}%',f'%{q}%'])
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z'); where.append('last_seen>=?'); args.append(since)
        order={'recent':'last_seen DESC,first_seen DESC','first':'first_seen DESC,last_seen DESC','url':'url,target','target':'target,url'}.get(sort,'last_seen DESC,first_seen DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT target,url,kind,source,first_seen,last_seen FROM urls WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 2000",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM urls ORDER BY target')]; kinds=[str(r[0]) for r in db.all('SELECT DISTINCT kind FROM urls ORDER BY kind')]; sources=[str(r[0]) for r in db.all("SELECT DISTINCT source FROM urls WHERE COALESCE(source,'')<>'' ORDER BY source")]
        finally: db.close()
        day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')]; sort_pairs=[('recent','Recently seen'),('first','Recently discovered'),('url','URL'),('target','Target')]
        fields=f"<label class='filter-wide'>Search URLs<input name='q' value='{_esc(q)}' placeholder='URL or collection source'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Kind{_select('kind',kinds,kind,'All kinds')}</label><label>Source{_select('source',sources,source,'All sources')}</label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Recently seen')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Kind':kind,'Source':source,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='recent' else ''},'/urls',title='URL filters',result_count=len(rows))
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td><code>{_esc(r['url'])}</code></td><td>{_pill(r['kind'],'info')}</td><td>{_esc(r['source'])}</td><td>{_esc(r['first_seen'])}</td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        header=_page_header('URL inventory','Historical and live URLs separated by target, kind, collection source and recency.',eyebrow='Application surface')
        self.send_html('URLs',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Target</th><th>URL</th><th>Kind</th><th>Source</th><th>First</th><th>Last</th></tr></thead><tbody>{body or '<tr><td colspan=6>No URLs match the filters</td></tr>'}</tbody></table></div>")

    def javascript(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); kind=str((p.get('kind') or [''])[0]); q=str((p.get('q') or [''])[0]).strip();redacted=str((p.get('redacted')or[''])[0]);sort=str((p.get('sort')or['recent'])[0]);days=parse_int((p.get('days')or[0])[0],0,0,3650);where=['1=1']; args=[]
        if target: where.append('target=?'); args.append(target)
        if kind: where.append('kind=?'); args.append(kind)
        if q: where.append('(value LIKE ? OR js_url LIKE ?)'); args.extend([f'%{q}%',f'%{q}%'])
        if redacted in {'0','1'}:where.append('redacted=?');args.append(int(redacted))
        since=''
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('last_seen>=?');args.append(since)
        order={'recent':'last_seen DESC','first':'first_seen DESC','kind':'kind,last_seen DESC','value':'value,last_seen DESC'}.get(sort,'last_seen DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT target,js_url,kind,value,redacted,first_seen,last_seen FROM js_indicators WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 1500",args)
            diff_where=[];diff_args=[]
            if target:diff_where.append('target=?');diff_args.append(target)
            if q:diff_where.append('js_url LIKE ?');diff_args.append(f'%{q}%')
            if since:diff_where.append('created_at>=?');diff_args.append(since)
            diff_clause=' WHERE '+' AND '.join(diff_where) if diff_where else ''
            diffs=db.all(f"SELECT id,run_id,target,js_url,summary_json,created_at FROM js_diffs{diff_clause} ORDER BY created_at DESC LIMIT 200",tuple(diff_args))
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM js_indicators ORDER BY target')]; kinds=[str(r[0]) for r in db.all('SELECT DISTINCT kind FROM js_indicators ORDER BY kind')]
        finally: db.close()
        sort_pairs=[('recent','Recently seen'),('first','Recently discovered'),('kind','Kind'),('value','Value')];day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')]
        fields=f"<label class='filter-wide'>Search JavaScript data<input name='q' value='{_esc(q)}' placeholder='Indicator or JavaScript URL'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Indicator kind{_select('kind',kinds,kind,'All kinds')}</label><label>Redaction{_select_pairs('redacted',[('1','Redacted'),('0','Not redacted')],redacted,'Any')}</label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Recently seen')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Kind':kind,'Redaction':dict([('1','Redacted'),('0','Not redacted')]).get(redacted,''),'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='recent' else ''},'/javascript',title='JavaScript filters',result_count=len(rows)+len(diffs))
        diff_rows=''.join(f"<tr><td><a href='/js-diff?id={r['id']}'>{r['id']}</a></td><td>{_esc(r['target'])}</td><td><code>{_esc(r['js_url'])}</code></td><td><code>{_esc(r['run_id'])}</code></td><td>{_esc(r['created_at'])}</td></tr>" for r in diffs)
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td><code>{_esc(r['kind'])}</code></td><td><code>{_esc(r['value'])}</code></td><td><code>{_esc(r['js_url'])}</code></td><td>{'yes' if r['redacted'] else 'no'}</td><td>{_esc(r['first_seen'])}</td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        header=_page_header('JavaScript intelligence','Extracted indicators and semantic diffs with Target, kind, redaction, recency and text filters.',eyebrow='Client-side intelligence')
        self.send_html('JavaScript',header+controls+f"<section class='panel'><div class='panel-head'><h3>Recent detailed diffs</h3><span class='muted small'>{len(diffs)} shown</span></div><div class='table-wrap'><table><thead><tr><th>ID</th><th>Target</th><th>JS URL</th><th>Run</th><th>Created</th></tr></thead><tbody>{diff_rows or '<tr><td colspan=5>No diffs match the filters</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Extracted indicators</h3><span class='muted small'>{len(rows)} shown</span></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Kind</th><th>Value</th><th>JS URL</th><th>Redacted</th><th>First</th><th>Last</th></tr></thead><tbody>{body or '<tr><td colspan=7>No indicators match the filters</td></tr>'}</tbody></table></div></section>")

    def js_diff(self) -> None:
        diff_id=parse_int((self.query().get('id') or [0])[0],0); db=self.db()
        try: row=db.one('SELECT * FROM js_diffs WHERE id=?',(diff_id,))
        finally: db.close()
        if not row: self.send_html('Not found',_empty('JS diff not found'),404); return
        summary=_json(row['summary_json'],{}); added=summary.get('added_endpoints',[]); removed=summary.get('removed_endpoints',[])
        header=_page_header(f"JavaScript diff #{diff_id}", "Semantic change review with endpoint additions, removals, and evidence context.", f"<button class='button ghost' data-copy='{_esc(row['js_url'])}'>Copy URL</button><a class='button secondary' href='{_query_link('/javascript',target=row['target'],q=row['js_url'])}'>JavaScript intelligence</a>", row['target'])
        added_html=''.join(f"<div class='evidence-item'><div class='evidence-icon'>+</div><div><strong class='mono'>{_esc(x.get('value'))}</strong><div class='queue-meta'>{_pill(x.get('primary_category'),'purple')}{_confidence(x.get('confidence'))}<span>{_esc(', '.join(x.get('reasons',[])))}</span></div></div></div>" for x in added)
        removed_html=''.join(f"<div class='evidence-item'><div class='evidence-icon tone-danger'>−</div><div><strong class='mono'>{_esc(x.get('value'))}</strong><div class='queue-meta'>{_pill(x.get('primary_category'),'neutral')}</div></div></div>" for x in removed)
        summary_cards="<div class='metrics-grid'>"+_metric_card('Additions',summary.get('additions',0),'Semantic lines added','success')+_metric_card('Removals',summary.get('removals',0),'Semantic lines removed','danger')+_metric_card('Added endpoints',len(added),'New route candidates','purple')+_metric_card('Removed endpoints',len(removed),'No longer observed','neutral')+"</div>"
        facts=f"<section class='panel'><div class='panel-head'><h3>Diff facts</h3></div><div class='panel-body kv'><strong>Run</strong><code>{_esc(row['run_id'])}</code><strong>JavaScript URL</strong><code>{_esc(row['js_url'])}</code><strong>Old raw hash</strong><code>{_esc(row['old_raw_hash'])}</code><strong>New raw hash</strong><code>{_esc(row['new_raw_hash'])}</code><strong>Created</strong><span>{_esc(row['created_at'])}</span><strong>Truncated</strong><span>{_esc(summary.get('truncated',False))}</span></div></section>"
        body=header+summary_cards+f"<div class='three-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Added endpoints</h3></div><div class='panel-body evidence-feed'>{added_html or _empty('No added endpoints')}</div></section><section class='panel'><div class='panel-head'><h3>Removed endpoints</h3></div><div class='panel-body evidence-feed'>{removed_html or _empty('No removed endpoints')}</div></section>{facts}</div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Unified semantic diff</h3><span class='muted small'>Secrets are redacted before storage</span></div><pre class='diff' style='border:0;border-radius:0;margin:0'>{_diff_html(row['diff_text'])}</pre></section>"
        self.send_html(f'JS diff {diff_id}',body)

    def endpoints(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); category=str((p.get('category') or [''])[0]); kind=str((p.get('kind')or[''])[0]);source=str((p.get('source')or[''])[0]);q=str((p.get('q') or [''])[0]).strip(); min_conf=parse_int((p.get('confidence') or [0])[0],0,0,100);days=parse_int((p.get('days')or[0])[0],0,0,3650);sort=str((p.get('sort')or['confidence'])[0]); where=['1=1']; args=[]
        if target: where.append('target=?'); args.append(target)
        if category: where.append('primary_category=?'); args.append(category)
        if kind:where.append('kind=?');args.append(kind)
        if source:where.append('sources_json LIKE ?');args.append(f'%{source}%')
        if q: where.append('(endpoint LIKE ? OR sources_json LIKE ? OR reasons_json LIKE ?)'); args.extend([f'%{q}%']*3)
        if min_conf: where.append('confidence>=?'); args.append(min_conf)
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('last_seen>=?');args.append(since)
        order={'confidence':'confidence DESC,last_seen DESC','recent':'last_seen DESC,confidence DESC','first':'first_seen DESC,confidence DESC','endpoint':'endpoint,target'}.get(sort,'confidence DESC,last_seen DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT * FROM endpoint_intelligence WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 2000",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM endpoint_intelligence ORDER BY target')]; categories=[str(r[0]) for r in db.all('SELECT DISTINCT primary_category FROM endpoint_intelligence ORDER BY primary_category')];kinds=[str(r[0]) for r in db.all('SELECT DISTINCT kind FROM endpoint_intelligence ORDER BY kind')]
            source_values=[]
            for row in db.all('SELECT sources_json FROM endpoint_intelligence LIMIT 5000'):
                for item in _json(row[0],[]):
                    text=str(item)
                    if text and text not in source_values:source_values.append(text)
            source_values=sorted(source_values)[:100]
        finally: db.close()
        header=_page_header("Endpoint intelligence", "Classified API and route candidates with evidence-backed confidence, kind, source and recency filters.", eyebrow="Application surface")
        sort_pairs=[('confidence','Confidence'),('recent','Recently seen'),('first','Recently discovered'),('endpoint','Endpoint')];day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')]
        fields=f"<label class='filter-wide'>Search endpoints<input name='q' value='{_esc(q)}' placeholder='Endpoint, reason or source'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Class{_select('category',categories,category,'All classes')}</label><label>Kind{_select('kind',kinds,kind,'All kinds')}</label><label>Source{_select('source',source_values,source,'Any source')}</label><label>Confidence ≥<input type='number' name='confidence' min='0' max='100' value='{min_conf or ''}'></label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Confidence')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Class':category,'Kind':kind,'Source':source,'Confidence ≥':min_conf,'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='confidence' else ''},'/endpoints',title='Endpoint filters',result_count=len(rows))
        body=[]
        for r in rows:
            reasons=_json(r['reasons_json'],[]); sources=_json(r['sources_json'],[])
            body.append(f"<tr><td>{_esc(r['target'])}</td><td><code>{_esc(r['endpoint'])}</code></td><td>{_pill(r['kind'],'info')}</td><td>{_pill(r['primary_category'],'purple')}</td><td>{_confidence(r['confidence'])}</td><td>{_badges(reasons[:3])}</td><td>{_badges(sources[:3])}</td><td>{_esc(r['last_seen'])}</td></tr>")
        self.send_html('Endpoints',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Target</th><th>Endpoint</th><th>Kind</th><th>Class</th><th>Confidence</th><th>Reasons</th><th>Sources</th><th>Last</th></tr></thead><tbody>{''.join(body) or '<tr><td colspan=8>No endpoints match the filters</td></tr>'}</tbody></table></div>")

    def fingerprints(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); q=str((p.get('q') or [''])[0]).strip(); status=str((p.get('status') or [''])[0]);status_class=str((p.get('status_class')or[''])[0]);server=str((p.get('server')or[''])[0]);technology=str((p.get('technology')or[''])[0]);cdn=str((p.get('cdn')or[''])[0]);tls_state=str((p.get('tls')or[''])[0]);sort=str((p.get('sort')or['recent'])[0]);days=parse_int((p.get('days')or[0])[0],0,0,3650);where=['1=1']; args=[]
        if target: where.append('f.target=?'); args.append(target)
        if q: where.append('(f.url LIKE ? OR f.title LIKE ? OR f.ip LIKE ? OR f.cname LIKE ? OR t.technology LIKE ?)'); args.extend([f'%{q}%']*5)
        if status: where.append('f.status_code=?'); args.append(parse_int(status,0))
        if status_class=='2xx':where.append('f.status_code BETWEEN 200 AND 299')
        elif status_class=='3xx':where.append('f.status_code BETWEEN 300 AND 399')
        elif status_class=='4xx':where.append('f.status_code BETWEEN 400 AND 499')
        elif status_class=='5xx':where.append('f.status_code>=500')
        elif status_class=='unknown':where.append('f.status_code IS NULL')
        if server:where.append('f.webserver=?');args.append(server)
        if technology:where.append('t.technology=?');args.append(technology)
        if cdn:where.append('f.cdn=?');args.append(cdn)
        today=dt.datetime.now(dt.timezone.utc).date().isoformat();soon=(dt.datetime.now(dt.timezone.utc).date()+dt.timedelta(days=30)).isoformat()
        if tls_state=='expired':where.append("COALESCE(f.tls_expiry,'')<>'' AND substr(f.tls_expiry,1,10)<?");args.append(today)
        elif tls_state=='expiring':where.append("COALESCE(f.tls_expiry,'')<>'' AND substr(f.tls_expiry,1,10)>=? AND substr(f.tls_expiry,1,10)<=?");args.extend([today,soon])
        elif tls_state=='valid':where.append("COALESCE(f.tls_expiry,'')<>'' AND substr(f.tls_expiry,1,10)>?");args.append(soon)
        elif tls_state=='none':where.append("COALESCE(f.tls_expiry,'')='' ")
        if days:
            since=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace('+00:00','Z');where.append('f.last_seen>=?');args.append(since)
        order={'recent':'f.last_seen DESC','status':'f.status_code,f.last_seen DESC','url':'f.url','tls':'f.tls_expiry ASC,f.last_seen DESC'}.get(sort,'f.last_seen DESC')
        db=self.db()
        try:
            rows=db.all(f"SELECT f.target,f.url,f.status_code,f.title,f.webserver,f.ip,f.cname,f.cdn,f.tls_issuer,f.tls_expiry,f.last_seen,GROUP_CONCAT(DISTINCT t.technology) technologies FROM fingerprints f LEFT JOIN technology_observations t ON t.target=f.target AND t.url=f.url AND t.is_current=1 WHERE {' AND '.join(where)} GROUP BY f.target,f.url ORDER BY {order} LIMIT 1500",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM fingerprints ORDER BY target')];servers=[str(r[0]) for r in db.all("SELECT DISTINCT webserver FROM fingerprints WHERE webserver<>'' ORDER BY webserver")];technologies=[str(r[0]) for r in db.all("SELECT DISTINCT technology FROM technology_observations WHERE is_current=1 ORDER BY technology")];cdns=[str(r[0]) for r in db.all("SELECT DISTINCT cdn FROM fingerprints WHERE cdn<>'' ORDER BY cdn")]
        finally: db.close()
        header=_page_header("HTTP / TLS intelligence", "Current web services with status class, technology, CDN, TLS posture and recency filters.", eyebrow="Service intelligence")
        sort_pairs=[('recent','Recently seen'),('status','Status code'),('url','URL'),('tls','TLS expiry')];day_pairs=[('1','Last 24 hours'),('7','Last 7 days'),('30','Last 30 days'),('90','Last 90 days')];status_pairs=[('2xx','2xx success'),('3xx','3xx redirect'),('4xx','4xx client error'),('5xx','5xx server error'),('unknown','Unknown')];tls_pairs=[('expired','Expired'),('expiring','Expires in 30 days'),('valid','Valid beyond 30 days'),('none','No TLS expiry')]
        fields=f"<label class='filter-wide'>Search services<input name='q' value='{_esc(q)}' placeholder='URL, title, IP, CNAME or technology'></label><label>Target{_select('target',targets,target,'All targets')}</label><label>Exact status<input name='status' value='{_esc(status)}' placeholder='e.g. 200'></label><label>Status class{_select_pairs('status_class',status_pairs,status_class,'Any class')}</label><label>Server{_select('server',servers,server,'Any server')}</label><label>Technology{_select('technology',technologies,technology,'Any technology')}</label><label>CDN{_select('cdn',cdns,cdn,'Any CDN')}</label><label>TLS{_select_pairs('tls',tls_pairs,tls_state,'Any TLS state')}</label><label>Seen{_select_pairs('days',day_pairs,str(days) if days else '','Any time')}</label><label>Sort{_select_pairs('sort',sort_pairs,sort,'Recently seen')}</label>"
        controls=_filter_panel(fields,{'Search':q,'Target':target,'Status':status,'Class':dict(status_pairs).get(status_class,''),'Server':server,'Technology':technology,'CDN':cdn,'TLS':dict(tls_pairs).get(tls_state,''),'Window':dict(day_pairs).get(str(days),'') if days else '','Sort':dict(sort_pairs).get(sort,'') if sort!='recent' else ''},'/fingerprints',title='HTTP / TLS filters',result_count=len(rows))
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td><code>{_esc(r['url'])}</code><br><span class='muted small'>{_esc(r['title'])}</span></td><td>{_pill(r['status_code'],'success' if 200<=int(r['status_code'] or 0)<400 else 'amber')}</td><td>{_esc(r['webserver'])}</td><td>{_badges(str(r['technologies'] or '').split(',')[:4])}</td><td><code>{_esc(r['ip'])}</code><br><span class='muted small'>{_esc(r['cname'])}</span></td><td>{_esc(r['cdn'])}</td><td>{_esc(r['tls_issuer'])}<br><span class='muted small'>{_esc(r['tls_expiry'])}</span></td><td>{_esc(r['last_seen'])}</td></tr>" for r in rows)
        self.send_html('HTTP/TLS',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Target</th><th>Service</th><th>Status</th><th>Server</th><th>Technology</th><th>Network</th><th>CDN</th><th>TLS</th><th>Last</th></tr></thead><tbody>{body or '<tr><td colspan=9>No services match the filters</td></tr>'}</tbody></table></div>")

    def validation_intelligence_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0]); result=str((p.get('result') or [''])[0]); min_conf=parse_int((p.get('min_conf') or [0])[0],0,0,100)
        db=self.db()
        try:
            where=['1=1'];args=[]
            if target:where.append('r.target=?');args.append(target)
            if result:where.append('r.result=?');args.append(result)
            if min_conf:where.append('COALESCE(i.overall_confidence,0)>=?');args.append(min_conf)
            rows=db.all(f"SELECT r.run_id,r.case_id,r.target,r.result,r.status,r.finished_at,COALESCE(i.overall_confidence,0) confidence,COALESCE(i.test_reliability,0) reliability,COALESCE(i.context_coverage,0) contexts,COALESCE(i.response_comparability,0) comparability,i.limitations_json FROM validation_runs r LEFT JOIN validation_intelligence i ON i.validation_run_id=r.run_id WHERE {' AND '.join(where)} ORDER BY r.finished_at DESC LIMIT 500",args)
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM validation_runs ORDER BY target')]
        finally: db.close()
        header=_page_header('Validation intelligence','Reliability, context coverage, baseline comparability and limitations for every safe validation result.',"<form method='post' action='/suite/sync'><input type='hidden' name='return' value='/validation-intelligence'><button>Refresh intelligence</button></form>",f'Recon Monitor {APP_VERSION} · Validation intelligence')
        fields=f"<label>Target{_select('target',targets,target,'All targets')}</label><label>Result{_select('result',['strengthened','weakened','inconclusive','stopped_for_safety','blocked_by_scope'],result,'All results')}</label><label>Minimum confidence<input type='number' min='0' max='100' name='min_conf' value='{min_conf or ''}'></label>"
        controls=_filter_panel(fields,{'Target':target,'Result':result,'Minimum confidence':min_conf},'/validation-intelligence',title='Validation intelligence filters',result_count=len(rows))
        body=''.join(f"<tr><td><a href='/case?id={_esc(r['case_id'])}'><code>{_esc(r['case_id'])}</code></a></td><td>{_esc(r['target'])}</td><td>{_pill(r['result'])}</td><td>{_confidence(r['confidence'])}</td><td>{_confidence(r['reliability'])}</td><td>{_confidence(r['contexts'])}</td><td>{_confidence(r['comparability'])}</td><td>{_esc('; '.join(_json(r['limitations_json'],[])[:2]))}</td><td>{_esc(r['finished_at'])}</td></tr>" for r in rows)
        self.send_html('Validation intelligence',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Case</th><th>Target</th><th>Result</th><th>Overall</th><th>Reliability</th><th>Contexts</th><th>Comparability</th><th>Limitations</th><th>Finished</th></tr></thead><tbody>{body or '<tr><td colspan=9>No validation intelligence is available. Run a validation or refresh the suite.</td></tr>'}</tbody></table></div>")

    def data_quality_page(self) -> None:
        p=self.query(); run_id=str((p.get('run_id') or [''])[0]); target=str((p.get('target') or [''])[0]); refresh=str((p.get('refresh') or [''])[0])=='1'
        db=self.db()
        try:
            if refresh or run_id:
                try:data=data_quality_snapshot(db,run_id or None,target or None,persist=refresh)
                except Exception:data={}
            else:
                row=db.one("SELECT * FROM data_quality_snapshots ORDER BY created_at DESC LIMIT 1")
                data={'run_id':row['run_id'],'target':row['target'],'score':row['score'],'targets':_json(row['metrics_json'],{}),'blind_spots':_json(row['blind_spots_json'],[]),'generated_at':row['created_at']} if row else {}
            runs=[str(r[0]) for r in db.all("SELECT id FROM runs WHERE status='success' ORDER BY finished_at DESC LIMIT 100")]
        finally:db.close()
        header=_page_header('Data quality & coverage','Shows whether low candidate counts are conclusive or caused by missing collection, parser or authorization context.',"<a class='button' href='/data-quality?refresh=1'>Refresh latest run</a>",'Coverage intelligence')
        fields=f"<label>Run{_select('run_id',runs,run_id,'Latest completed')}</label><label>Target<input name='target' value='{_esc(target)}' placeholder='Optional target'></label>"
        controls=_filter_panel(fields,{'Run':run_id,'Target':target},'/data-quality',title='Coverage filters')
        cards=_metric_card('Run quality',data.get('score','—'),'Pipeline and evidence coverage','info')+_metric_card('Blind spots',len(data.get('blind_spots',[])),'Explicit visibility gaps','orange')+_metric_card('Run',data.get('run_id','—'),'Source snapshot','blue')
        rows=[]
        for tgt,item in (data.get('targets') or {}).items():
            metrics=item.get('metrics',{}); rows.append(f"<tr><td>{_esc(tgt)}</td><td>{_confidence(item.get('score'))}</td><td>{_confidence(metrics.get('http_coverage'))}</td><td>{_confidence(metrics.get('javascript_coverage'))}</td><td>{_confidence(metrics.get('endpoint_contract_coverage'))}</td><td>{_confidence(metrics.get('response_shape_coverage'))}</td><td>{_confidence(metrics.get('authentication_context_coverage'))}</td><td>{len(item.get('blind_spots',[]))}</td></tr>")
        blind=''.join(f"<div class='attention-item'><span class='attention-icon tone-{_tone(b.get('severity'))}'>●</span><div><strong>{_esc(b.get('code'))}</strong><small>{_esc(b.get('message'))}</small></div><b>{_esc(b.get('target'))}</b></div>" for b in data.get('blind_spots',[])[:100])
        self.send_html('Data quality',header+controls+f"<div class='metrics-grid'>{cards}</div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Overall</th><th>HTTP</th><th>JavaScript</th><th>Endpoints</th><th>Shapes</th><th>Auth contexts</th><th>Blind spots</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=8>No data-quality snapshot is available.</td></tr>'}</tbody></table></div><section class='panel' style='margin-top:18px'><div class='panel-head'><h3>Blind spots</h3></div><div class='panel-body'>{blind or _empty('No recorded blind spots')}</div></section>")

    def review_priority_page(self) -> None:
        p=self.query();target=str((p.get('target')or[''])[0]);min_value=parse_int((p.get('min_value')or[0])[0],0,0,100);effort=str((p.get('effort')or[''])[0])
        db=self.db()
        try:
            rows=rank_review_queue(db,target=target or None,limit=500,refresh=False)
            if min_value:rows=[r for r in rows if parse_int(r.get('review_value'),0)>=min_value]
            if effort:
                if effort=='quick':rows=[r for r in rows if parse_int(r.get('analyst_effort'),0)<=30]
                elif effort=='moderate':rows=[r for r in rows if 31<=parse_int(r.get('analyst_effort'),0)<=60]
                elif effort=='deep':rows=[r for r in rows if parse_int(r.get('analyst_effort'),0)>60]
            targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM security_cases ORDER BY target')]
        finally:db.close()
        header=_page_header('Cost-aware review priority','Ranks cases by security value, expected information gain and analyst effort rather than likelihood alone.',"<form method='post' action='/suite/sync'><input type='hidden' name='return' value='/review-priority'><button>Recalculate queue</button></form>",'Analyst productivity')
        fields=f"<label>Target{_select('target',targets,target,'All targets')}</label><label>Effort{_select('effort',['quick','moderate','deep'],effort,'Any effort')}</label><label>Minimum review value<input type='number' min='0' max='100' name='min_value' value='{min_value or ''}'></label>"
        controls=_filter_panel(fields,{'Target':target,'Effort':effort,'Minimum value':min_value},'/review-priority',title='Review-priority filters',result_count=len(rows))
        body=''.join(f"<tr><td><a href='/case?id={_esc(r['case_id'])}'><strong>{_esc(r['title'])}</strong></a><br><code>{_esc(r['case_id'])}</code></td><td>{_esc(r['target'])}</td><td>{_pill(r['primary_family'])}</td><td><strong>{parse_int(r.get('review_value'),0)}</strong></td><td>{parse_int(r.get('information_gain'),0)}</td><td>{parse_int(r.get('analyst_effort'),0)}</td><td>{_pill(r['state'])}</td><td><form method='post' action='/suite/burp-export'><input type='hidden' name='case_id' value='{_esc(r['case_id'])}'><input type='hidden' name='return' value='/review-priority'><button class='secondary'>Burp package</button></form></td></tr>" for r in rows)
        self.send_html('Review priority',header+controls+f"<div class='table-wrap'><table><thead><tr><th>Case</th><th>Target</th><th>Family</th><th>Review value</th><th>Information gain</th><th>Effort</th><th>State</th><th>Action</th></tr></thead><tbody>{body or '<tr><td colspan=8>No open cases match the filters.</td></tr>'}</tbody></table></div>")

    def automation_page(self) -> None:
        db=self.db()
        try:
            schedules=[dict(r) for r in db.all('SELECT p.*,j.status job_status,j.generated_path,j.last_error FROM schedule_policies p LEFT JOIN schedule_jobs j ON j.target=p.target ORDER BY p.target')]
            due=due_revalidations(db,limit=200)
            notifications=[dict(r) for r in db.all("SELECT mode,status,COUNT(*) count,MAX(created_at) latest FROM notification_events GROUP BY mode,status ORDER BY mode,status")]
        finally:db.close()
        header=_page_header('Automation center','Generate quiet-hour-aware macOS workflows, process due offline revalidations and keep high-signal notifications separate from digests.',"<form method='post' action='/suite/revalidation-process'><button>Process due offline revalidations</button></form>",eyebrow='Operations automation')
        schedule_rows=''.join(f"<tr><td>{_esc(r['target'])}</td><td>{_esc(r['cadence'])}</td><td>{_pill('enabled' if r['enabled'] else 'disabled')}</td><td>{_pill(r.get('job_status') or 'not generated')}</td><td><code>{_esc(r.get('generated_path') or '')}</code><br><span class='muted'>{_esc(r.get('last_error') or '')}</span></td><td><form method='post' action='/suite/schedule-generate'><input type='hidden' name='target' value='{_esc(r['target'])}'><button>Generate LaunchAgent</button></form></td></tr>" for r in schedules)
        due_rows=''.join(f"<tr><td><a href='/case?id={_esc(r['case_id'])}'>{_esc(r['title'])}</a></td><td>{_esc(r['target'])}</td><td>{_esc(r['trigger'])}</td><td>{_esc(r['next_due_at'])}</td><td>{_pill(r['validation_state'])}</td></tr>" for r in due)
        notif=''.join(_metric_card(f"{r['mode']} · {r['status']}",r['count'],str(r['latest'] or ''),'info') for r in notifications)
        self.send_html('Automation',header+f"<div class='metrics-grid'>{notif or _metric_card('Notification queue',0,'No queued events','success')}</div><section class='panel'><div class='panel-head'><h3>Schedule jobs</h3></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Cadence</th><th>Policy</th><th>Job</th><th>Generated file</th><th></th></tr></thead><tbody>{schedule_rows or '<tr><td colspan=6>No schedule policies configured.</td></tr>'}</tbody></table></div></section><section class='panel' style='margin-top:18px'><div class='panel-head'><h3>Due revalidations</h3></div><div class='table-wrap'><table><thead><tr><th>Case</th><th>Target</th><th>Trigger</th><th>Next due</th><th>Validation</th></tr></thead><tbody>{due_rows or '<tr><td colspan=5>No cases are currently due.</td></tr>'}</tbody></table></div></section>")

    def report_quality_page(self) -> None:
        db=self.db()
        try:rows=db.all("SELECT d.draft_id,d.case_id,d.title,d.readiness_score,d.status,d.updated_at,q.quality_score,q.missing_json FROM report_drafts d LEFT JOIN report_quality_snapshots q ON q.id=(SELECT id FROM report_quality_snapshots q2 WHERE q2.draft_id=d.draft_id ORDER BY q2.created_at DESC LIMIT 1) ORDER BY d.updated_at DESC LIMIT 500")
        finally:db.close()
        header=_page_header('Report quality','Checks evidence, observed and expected behavior, impact, scope, reproduction and redaction before submission.',eyebrow='Report assistant')
        body=''.join(f"<tr><td><strong>{_esc(r['title'])}</strong><br><code>{_esc(r['draft_id'])}</code></td><td><a href='/case?id={_esc(r['case_id'])}'>{_esc(r['case_id'])}</a></td><td>{_confidence(r['quality_score'] if r['quality_score'] is not None else r['readiness_score'])}</td><td>{_esc(', '.join(_json(r['missing_json'],[])[:5]))}</td><td>{_pill(r['status'])}</td><td><form method='post' action='/suite/report-quality'><input type='hidden' name='draft_id' value='{_esc(r['draft_id'])}'><button>Evaluate</button></form></td></tr>" for r in rows)
        self.send_html('Report quality',header+f"<div class='table-wrap'><table><thead><tr><th>Draft</th><th>Case</th><th>Quality</th><th>Missing</th><th>Status</th><th></th></tr></thead><tbody>{body or '<tr><td colspan=6>No report drafts are available.</td></tr>'}</tbody></table></div>")

    def performance_page(self) -> None:
        db=self.db()
        try:data=performance_diagnostics(self.paths,db,limit=100)
        finally:db.close()
        header=_page_header('Performance diagnostics','Slow operations, cache reuse, database/WAL size and largest tables.',eyebrow='Performance')
        cards=_metric_card('Database',f"{round(data['database_bytes']/1024/1024,2)} MB",'SQLite main file','blue')+_metric_card('WAL',f"{round(data['wal_bytes']/1024/1024,2)} MB",'Write-ahead log','amber')+_metric_card('Samples',data['sample_count'],'Recorded operations','info')+_metric_card('Cache hit',f"{round(data['cache_hit_rate']*100,1)}%",'Recorded sample reuse','success')
        slow=''.join(f"<tr><td>{_esc(r['category'])}</td><td>{_esc(r['name'])}</td><td>{r['duration_ms']} ms</td><td>{_esc(r['created_at'])}</td><td><code>{_esc(r['details_json'])}</code></td></tr>" for r in data['slow_samples'])
        tables=''.join(f"<tr><td><code>{_esc(r['table'])}</code></td><td>{r['rows']}</td></tr>" for r in data['largest_tables'])
        self.send_html('Performance',header+f"<div class='metrics-grid'>{cards}</div><div class='two-col'><section class='panel'><div class='panel-head'><h3>Slow samples ≥100 ms</h3></div><div class='table-wrap'><table><thead><tr><th>Category</th><th>Name</th><th>Duration</th><th>Time</th><th>Details</th></tr></thead><tbody>{slow or '<tr><td colspan=5>No slow samples recorded.</td></tr>'}</tbody></table></div></section><section class='panel'><div class='panel-head'><h3>Largest tables</h3></div><div class='table-wrap'><table><thead><tr><th>Table</th><th>Rows</th></tr></thead><tbody>{tables}</tbody></table></div></section></div>")

    def retention_page(self) -> None:
        db=self.db()
        try:
            policies=[dict(r) for r in db.all('SELECT * FROM retention_policies ORDER BY category')]
            preview_row=db.one('SELECT preview_json FROM retention_previews ORDER BY created_at DESC LIMIT 1')
            preview=_json(preview_row['preview_json'],{}) if preview_row else {}
        finally:db.close()
        header=_page_header('Storage retention','Preview-only cleanup protects confirmed and case evidence. Deletion requires an exact confirmation through CLI/API.',"<form method='post' action='/suite/retention-preview'><button>Create preview</button></form>",'Safe storage lifecycle')
        cards=_metric_card('Eligible files',preview.get('files',0),'Latest preview','orange')+_metric_card('Recoverable',f"{round(preview.get('bytes',0)/1024/1024,2)} MB",'Latest preview','info')+_metric_card('Protected',preview.get('protected_files',0),'Never auto-deleted','success')
        rows=''.join(f"<tr><td>{_esc(r['category'])}</td><td>{r['retention_days']}</td><td>{r['keep_count']}</td><td>{_pill('protected' if r['protected'] else 'enabled' if r['enabled'] else 'disabled')}</td><td>{_esc(r['updated_at'])}</td></tr>" for r in policies)
        self.send_html('Retention',header+f"<div class='metrics-grid'>{cards}</div><div class='table-wrap'><table><thead><tr><th>Category</th><th>Days</th><th>Keep count</th><th>State</th><th>Updated</th></tr></thead><tbody>{rows or '<tr><td colspan=5>Create a preview to seed default policies.</td></tr>'}</tbody></table></div>")

    def templates_page(self) -> None:
        templates=list_target_templates();db=self.db()
        try:targets=[str(r[0]) for r in db.all('SELECT DISTINCT target FROM run_targets ORDER BY target')]
        finally:db.close()
        header=_page_header('Target templates','Apply safe presets for passive, SPA, API, GraphQL, enterprise and low-noise monitoring. Scope and authorization are never inferred.',eyebrow='Onboarding')
        cards=[]
        for t in templates:
            forms=''.join(f"<form method='post' action='/suite/template-apply' class='inline'><input type='hidden' name='target' value='{_esc(target)}'><input type='hidden' name='template_id' value='{_esc(t['template_id'])}'><button class='secondary'>Apply to {_esc(target)}</button></form>" for target in targets[:8])
            cards.append(f"<section class='panel'><div class='panel-head'><h3>{_esc(t['label'])}</h3>{_pill(t['template_id'])}</div><div class='panel-body'><p>{_esc(t['description'])}</p><div>{forms or '<span class=muted>No configured target found.</span>'}</div></div></section>")
        self.send_html('Target templates',header+"<div class='two-col'>"+''.join(cards)+"</div>")

    def platform_security_page(self) -> None:
        db=self.db()
        try:
            try:data=security_posture(self.paths,self.config,db,persist=False)
            except Exception as exc:data={'score':0,'checks':[{'name':'posture_error','ok':False,'detail':str(exc),'severity':'high'}]}
            chain=verify_audit_chain(db)
        finally:db.close()
        header=_page_header('Platform security','Authentication, token expiry/scopes, file permissions, CSRF and tamper-evident audit posture.',"<form method='post' action='/suite/security-check'><button>Run security check</button><label class='checkbox'><input type='checkbox' name='apply_permissions' value='true'>Fix safe file permissions</label></form>",'Security hardening')
        cards=_metric_card('Security posture',data.get('score',0),'Configuration checks','success' if data.get('score',0)>=80 else 'orange')+_metric_card('Audit chain',chain.get('verified',0),'Verified chained events','info')+_metric_card('Audit integrity','OK' if chain.get('ok') else 'FAILED','Tamper-evident chain','success' if chain.get('ok') else 'danger')
        rows=''.join(f"<tr><td>{_pill('pass' if r['ok'] else 'attention','success' if r['ok'] else r.get('severity','orange'))}</td><td><strong>{_esc(r['name'])}</strong></td><td>{_esc(r['detail'])}</td></tr>" for r in data.get('checks',[]))
        self.send_html('Platform security',header+f"<div class='metrics-grid'>{cards}</div><div class='table-wrap'><table><thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>")

    def case_autopilot_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM security_cases ORDER BY target")]
            items=case_autopilot_queue(db,target=target,limit=100,persist=False)
        finally: db.close()
        fields=f"<label>Target{_select('target',targets,target,'All targets')}</label>"
        controls=_filter_panel(fields,{'Target':target},'/case-autopilot',title='Autopilot filters',result_count=len(items))
        cards=[]
        for item in items:
            if item.get('error'):
                cards.append(f"<div class='callout'><strong>{_esc(item.get('case_id'))}</strong><span>{_esc(item.get('error'))}</span></div>"); continue
            gap=item.get('evidence',{}); tasks=item.get('tasks',[])
            task_html=''.join(f"<li>{_esc(t.get('title'))}</li>" for t in tasks) or '<li>No open task</li>'
            cards.append(f"<section class='panel' style='margin-bottom:12px'><div class='panel-head'><div><h3><a href='/case?id={urllib.parse.quote(str(item['case_id']))}'>{_esc(item['case_id'])}</a></h3><span class='muted'>{_esc(item.get('target'))}</span></div>{_pill('Autopilot '+str(item.get('autopilot_score',0))+'%','info')}</div><div class='panel-body'><div class='metrics-grid'>{_metric_card('Evidence coverage',str(gap.get('coverage',0))+'%',str(gap.get('missing_count',0))+' gaps','amber' if gap.get('missing_count') else 'success')}{_metric_card('Automation',gap.get('automation',''),'Safety classification','purple')}</div><h4>Recommended next actions</h4><ol>{task_html}</ol><form method='post' action='/workspace/autopilot'><input type='hidden' name='case_id' value='{_esc(item['case_id'])}'><input type='hidden' name='return' value='/case-autopilot'><button>Refresh case autopilot</button></form></div></section>")
        header=_page_header('Case autopilot','Turns each security case into an evidence-driven investigation plan. It never exploits or confirms a vulnerability automatically.',"<form method='post' action='/workspace/sync' style='display:inline'><input type='hidden' name='return' value='/case-autopilot'><button>Refresh all workspace intelligence</button></form>",f'Recon Monitor {APP_VERSION} · Investigation guidance')
        self.send_html('Case autopilot',header+controls+''.join(cards) if cards else header+controls+_empty('No active cases'))

    def evidence_gaps_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM security_cases ORDER BY target")]
            rows=db.all("SELECT case_id,target,title,primary_family,state,priority_score,evidence_gap_score FROM security_cases"+(" WHERE target=?" if target else "")+" ORDER BY evidence_gap_score DESC,priority_score DESC LIMIT 200",(target,) if target else ())
            gaps=[]
            for row in rows:
                try: gaps.append((dict(row),evidence_gap_for_case(db,str(row['case_id']),persist=False)))
                except Exception: continue
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'All targets')}</label>",{'Target':target},'/evidence-gaps',title='Evidence gap filters',result_count=len(gaps))
        body_rows=[]
        for row,gap in gaps:
            missing=[x['label'] for x in gap.get('requirements',[]) if x.get('status')=='missing']
            body_rows.append(f"<tr><td><a href='/case?id={urllib.parse.quote(str(row['case_id']))}'><strong>{_esc(row['case_id'])}</strong></a><br><span class='muted'>{_esc(row['title'])}</span></td><td>{_esc(row['target'])}</td><td>{_pill(row['primary_family'],'purple')}</td><td>{gap.get('coverage',0)}%</td><td>{_esc(', '.join(missing[:4]) or 'None')}</td><td>{_esc(gap.get('next_actions',['Ready for analyst review'])[0] if gap.get('next_actions') else 'Ready for analyst review')}</td></tr>")
        header=_page_header('Evidence gap engine','Shows exactly what evidence is present, what is missing and the safest next analyst action.',"<form method='post' action='/workspace/sync' style='display:inline'><input type='hidden' name='return' value='/evidence-gaps'><button>Recalculate gaps</button></form>",f'Recon Monitor {APP_VERSION} · Evidence completeness')
        table=f"<section class='panel'><div class='table-wrap'><table><thead><tr><th>Case</th><th>Target</th><th>Family</th><th>Coverage</th><th>Missing evidence</th><th>Best next action</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan=6>No cases</td></tr>'}</tbody></table></div></section>"
        self.send_html('Evidence gaps',header+controls+table)

    def auth_contexts_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT target FROM (SELECT DISTINCT target FROM behavioral_observations UNION SELECT DISTINCT target FROM imported_http_evidence UNION SELECT DISTINCT target FROM browser_capture_events) ORDER BY target")]
            if not target and len(targets)==1: target=targets[0]
            rows=authentication_contexts(db,target=target,persist=False) if target else []
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/auth-contexts',title='Authentication context',result_count=len(rows))
        cards=''.join(f"<section class='panel'><div class='panel-head'><h3>{_esc(r['label'])}</h3>{_pill(r['auth_state'],'purple' if r['auth_state']=='authenticated' else 'info')}</div><div class='panel-body'><div class='metrics-grid'>{_metric_card('Observed endpoints',r['endpoint_count'],'Metadata-only observations','info')}{_metric_card('Response shapes',r['response_shapes'],'Distinct shapes','purple')}{_metric_card('Confidence',str(r['confidence'])+'%',', '.join(r['sources']),'success' if r['confidence']>=70 else 'amber')}</div><p class='muted'>No raw credential, cookie or authorization value is stored in this profile.</p></div></section>" for r in rows)
        header=_page_header('Authentication contexts','Map anonymous, user and role contexts without storing raw secrets. Use these contexts for evidence comparison and case planning.',"<a class='button secondary' href='/browser-capture'>Import browser metadata</a>",f'Recon Monitor {APP_VERSION} · Identity workspace')
        self.send_html('Authentication contexts',header+controls+(f"<div class='two-col'>{cards}</div>" if cards else _empty('Choose a target','Context profiles are derived from behavioral, imported and browser-capture metadata.')))

    def differential_intelligence_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM analysis_runs WHERE target<>'' ORDER BY target")]
            rows=differential_intelligence(db,target=target,limit=200,persist=False)
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'All targets')}</label>",{'Target':target},'/differential-intelligence',title='Differential filters',result_count=len(rows))
        tr=[]
        for r in rows:
            dimensions=r.get('dimensions') or [r.get('transition','')]
            tr.append(f"<tr><td>{_esc(r.get('target'))}</td><td><code>{_esc(r.get('endpoint'))}</code></td><td>{_pill(r.get('kind'),'purple')}</td><td>{_esc(', '.join(str(x) for x in dimensions if x))}</td><td>{_esc(r.get('severity'))}</td><td>{r.get('confidence',0)}%</td></tr>")
        header=_page_header('Differential intelligence','Separates status, field, sensitive-data, authentication-boundary and response-shape differences so analysts can reason about what actually changed.','',f'Recon Monitor {APP_VERSION} · Behavioral comparison')
        self.send_html('Differential intelligence',header+controls+f"<section class='panel'><div class='table-wrap'><table><thead><tr><th>Target</th><th>Endpoint</th><th>Kind</th><th>Dimensions</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>{''.join(tr) or '<tr><td colspan=6>No comparable differences yet</td></tr>'}</tbody></table></div></section>")

    def recon_coverage_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
            if not target and targets: target=targets[0]
            data=recon_coverage(db,target=target,persist=False) if target else None
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/recon-coverage',title='Coverage focus')
        if not data: self.send_html('Recon coverage',_page_header('Recon coverage','Coverage is a confidence signal, not a claim that a target is secure.')+controls+_empty('Choose a target')); return
        cards=''.join(_metric_card(k.replace('_',' ').title(),f"{v}%",'Coverage confidence','success' if v>=75 else 'amber' if v>=45 else 'danger') for k,v in data['components'].items())
        blind=''.join(f"<li>{_esc(x)}</li>" for x in data['blind_spots']) or '<li>No major blind spot identified by current heuristics.</li>'
        header=_page_header('Recon coverage','Quantifies where reconnaissance is strong and where conclusions would be unreliable.','',f'Recon Monitor {APP_VERSION} · Coverage confidence')
        self.send_html('Recon coverage',header+controls+f"<div class='metrics-grid'>{_metric_card('Overall confidence',str(data['overall'])+'%','Run '+str(data['run_id']),'success' if data['overall']>=75 else 'amber')}{cards}</div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Blind spots</h3></div><div class='panel-body'><ul>{blind}</ul><p class='muted'>Low coverage means the system lacks observations; it does not mean the attack surface is safe.</p></div></section>")

    def change_intelligence_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
            if not target and targets: target=targets[0]
            data=change_intelligence(db,target=target,persist=False) if target else None
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/change-intelligence',title='Change focus')
        if not data: self.send_html('Change intelligence',_page_header('Change intelligence','See what changed since the previous successful run.')+controls+_empty('Choose a target')); return
        changes=''.join(f"<div class='attention-card'><span>{_esc(c.get('type'))}</span><strong>{_esc(c.get('change'))}: {c.get('count',0)}</strong><small>{_esc(', '.join(c.get('examples',[])[:3]))}</small></div>" for c in data['changes'])
        important=''.join(f"<div class='evidence-item'><div class='evidence-icon'>!</div><div><strong>{_esc(i.get('type'))}</strong><div class='muted'>{_esc(i.get('title') or i.get('endpoint') or i.get('candidate_id') or '')}</div></div></div>" for i in data['important'])
        header=_page_header('Change intelligence','Puts new endpoints, JavaScript, authentication boundaries and sensitive response changes ahead of static inventory.','',f'Recon Monitor {APP_VERSION} · What changed?')
        self.send_html('Change intelligence',header+controls+f"<div class='attention-grid'>{changes or _attention_item('No material delta',0,'No indexed change in the selected comparison','/runs','success')}</div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Important changes</h3><span class='muted'>{_esc(data.get('previous_run') or 'baseline')} → {_esc(data.get('current_run'))}</span></div><div class='panel-body evidence-feed'>{important or _empty('No high-priority change')}</div></section>")

    def target_memory_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
            if not target and targets: target=targets[0]
            data=target_memory(db,target=target,persist=False) if target else None
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/target-memory',title='Target memory')
        if not data: self.send_html('Target memory',_page_header('Target memory','Persistent architecture and research context for each target.')+controls+_empty('Choose a target')); return
        tech=', '.join(data['architecture']['technologies'][:20]) or 'Unknown'
        cats=', '.join(str(x) for x in data['important_areas']) or 'No dominant category yet'
        contexts=', '.join(x['label'] for x in data['architecture']['auth_contexts']) or 'No context labels yet'
        noise=', '.join(f"{x['bug_family']} ({x['c']})" for x in data['history']['historical_noise']) or 'No repeated noise family yet'
        header=_page_header('Target memory','Runs no longer start conceptually from zero: architecture, authentication contexts, important areas and historical noise are remembered.','',f'Recon Monitor {APP_VERSION} · Persistent target knowledge')
        body=f"<div class='metrics-grid'>{_metric_card('Memory confidence',str(data['confidence'])+'%',target,'success' if data['confidence']>=70 else 'amber')}</div><div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Known architecture</h3></div><div class='panel-body'><p><strong>Technologies</strong><br>{_esc(tech)}</p><p><strong>Important endpoint areas</strong><br>{_esc(cats)}</p><p><strong>Authentication contexts</strong><br>{_esc(contexts)}</p></div></section><section class='panel'><div class='panel-head'><h3>Historical learning</h3></div><div class='panel-body'><p><strong>Historically noisy families</strong><br>{_esc(noise)}</p><p class='muted'>Memory is derived from observed data and analyst decisions; it does not authorize additional testing.</p></div></section></div>"
        self.send_html('Target memory',header+controls+body)

    def smart_recon_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
            if not target and targets: target=targets[0]
            latest=db.one("SELECT plan_id,plan_json,created_at FROM smart_recon_plans WHERE target=? ORDER BY created_at DESC LIMIT 1",(target,)) if target else None
            data=_json(latest['plan_json'],{}) if latest else (smart_recon_plan(db,target=target,persist=False) if target else None)
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/smart-recon',title='Planner focus')
        if not data: self.send_html('Smart recon planner',_page_header('Smart recon planner','Proposes a bounded plan; it never enables active modules or runs it without confirmation.')+controls+_empty('Choose a target')); return
        pri=''.join(f"<li>{_esc(x)}</li>" for x in data.get('prioritize',[])); defer=''.join(f"<li>{_esc(x)}</li>" for x in data.get('defer',[])) or '<li>None</li>'
        header=_page_header('Smart recon planner','Prioritizes weak or changed areas using coverage, target memory and historical stage value. The plan is advisory until you explicitly run Recon.','',f'Recon Monitor {APP_VERSION} · Cost-aware planning')
        body=f"<div class='metrics-grid'>{_metric_card('Mode',data.get('mode',''),'Baseline or incremental','info')}{_metric_card('Estimated runtime',str(data.get('estimated_runtime_minutes',0))+' min','Approximate local history','purple')}{_metric_card('Estimated requests',data.get('estimated_requests',0),'Budget estimate','amber')}</div><div class='two-col' style='margin-top:16px'><section class='panel'><div class='panel-head'><h3>Prioritize</h3></div><div class='panel-body'><ol>{pri}</ol></div></section><section class='panel'><div class='panel-head'><h3>Defer when unchanged</h3></div><div class='panel-body'><ul>{defer}</ul></div></section></div><section class='panel' style='margin-top:16px'><div class='panel-body'><form method='post' action='/workspace/plan'><input type='hidden' name='target' value='{_esc(target)}'><button>Save a fresh proposed plan</button></form><p class='muted'>Saving a plan does not execute network requests and does not grant active-testing permission.</p></div></section>"
        self.send_html('Smart recon planner',header+controls+body)

    def safety_center_page(self) -> None:
        db=self.db()
        try: data=safety_center(self.paths,self.config,db)
        finally: db.close()
        tone='success' if data['status']=='SAFE TO RUN' else 'danger'
        scopes=''.join(f"<tr><td>{_esc(s['target'])}</td><td>{_esc(s['authorization_status'])}</td><td>{_esc(s['created_at'])}</td></tr>" for s in data.get('scopes',[]))
        header=_page_header('Safety center','One place for scope, authorization, active-module gates, local exposure, API posture and audit integrity.','',f'Recon Monitor {APP_VERSION} · Safety posture')
        cards=f"<div class='metrics-grid'>{_metric_card('Status',data['status'],'Run gate summary',tone)}{_metric_card('Authorization','yes' if data['authorized'] else 'no','I_HAVE_AUTHORIZATION','success' if data['authorized'] else 'danger')}{_metric_card('Active modules','enabled' if data['active_modules_enabled'] else 'disabled','Global active gate','amber' if data['active_modules_enabled'] else 'success')}{_metric_card('Dashboard',data['dashboard_host'],'Auth '+('enabled' if data['dashboard_auth'] else 'disabled'),'info')}{_metric_card('Audit integrity','valid' if data['audit_integrity'].get('valid') else 'attention','Hash-chain verification','success' if data['audit_integrity'].get('valid') else 'danger')}</div>"
        self.send_html('Safety center',header+cards+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Latest scope snapshots</h3></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Authorization</th><th>Snapshot</th></tr></thead><tbody>{scopes or '<tr><td colspan=3>No scope snapshot yet</td></tr>'}</tbody></table></div></section><div class='callout' style='margin-top:16px'><strong>Validation policy</strong><span>Automatic live validation remains disabled. Manual-only families stay manual-only.</span></div>")

    def diagnostics_page(self) -> None:
        db=self.db()
        try:
            data=operator_diagnostics(self.paths,self.config,db,persist=False,deep=False)
            errors=recent_error_events(db,limit=50)
            preview=safe_repair(self.paths,db,dry_run=True,actor='dashboard',max_age_hours=24)
        finally: db.close()
        checks=''.join(f"<tr><td><code>{_esc(c['id'])}</code></td><td>{_esc(c['label'])}</td><td>{_pill(c['status'],'success' if c['status']=='ok' else 'amber' if c['status']=='warn' else 'danger')}</td><td>{_esc(c['detail'])}</td><td>{_esc(c['recommended_action'])}</td></tr>" for c in data['checks'])
        errs=''.join(f"<div class='evidence-item'><div class='evidence-icon'>ER</div><div><strong>{_esc(e['error_code'])} · {_esc(e['error_id'])}</strong><div>{_esc(e['summary'])}</div><div class='muted'>{_esc(e['created_at'])} · {_esc(e.get('catalog',{}).get('action',''))}</div></div></div>" for e in errors)
        compat=browser_compatibility(self.headers.get('User-Agent',''))
        header=_page_header('Diagnostics & repair','Every failure gets a safe Error ID, subsystem status and a recommended recovery path. Repair actions are deliberately narrow.','',f'Recon Monitor {APP_VERSION} · Stability & recovery')
        repair=f"<section class='panel'><div class='panel-head'><h3>Safe repair preview</h3></div><div class='panel-body'><p>Stale execution repair candidates: <strong>{_esc(preview.get('stale_state',{}).get('repaired',preview.get('stale_state',{}).get('candidates',0)))}</strong></p><p>Expired session files: <strong>{preview.get('expired_session_files',0)}</strong></p><form method='post' action='/workspace/repair'><input type='hidden' name='max_age_hours' value='24'><button class='secondary'>Apply safe repair</button></form><p class='muted'>This repair does not delete evidence, cases, targets or recon output.</p></div></section>"
        self.send_html('Diagnostics',header+f"<div class='metrics-grid'>{_metric_card('Overall',data['overall'],'Subsystem self-check','success' if data['overall']=='ok' else 'amber')}{_metric_card('Browser',compat['family'],'Supported' if compat['supported'] else 'Unknown browser','info')}{_metric_card('Python',data['python'],'Runtime','purple')}</div><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Subsystem checks</h3></div><div class='table-wrap'><table><thead><tr><th>ID</th><th>Subsystem</th><th>Status</th><th>Observed</th><th>Recommended action</th></tr></thead><tbody>{checks}</tbody></table></div></section><div class='two-col' style='margin-top:16px'>{repair}<section class='panel'><div class='panel-head'><h3>Recent Error IDs</h3></div><div class='panel-body evidence-feed'>{errs or _empty('No recorded error events')}</div></section></div>")

    def browser_capture_page(self) -> None:
        db=self.db()
        try:
            rows=db.all("SELECT event_id,target,context_label,method,url,status_code,content_type,source_file,created_at FROM browser_capture_events ORDER BY created_at DESC LIMIT 200")
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM run_targets ORDER BY target")]
        finally: db.close()
        body=''.join(f"<tr><td>{_esc(r['target'])}</td><td>{_esc(r['context_label'])}</td><td>{_esc(r['method'])}</td><td><code>{_esc(r['url'])}</code></td><td>{_esc(r['status_code'])}</td><td>{_esc(r['content_type'])}</td><td>{_esc(r['created_at'])}</td></tr>" for r in rows)
        header=_page_header('Browser capture companion','Import metadata-only browser observations. Cookies, authorization values and raw sensitive bodies are not stored.','',f'Recon Monitor {APP_VERSION} · Safe browser context')
        command="./recon-monitor.sh workspace capture-import --target example.com --file ~/Downloads/capture.json --context 'Account A'"
        options=''.join(f"<option value='{_esc(t)}'>{_esc(t)}</option>" for t in targets)
        sample=json_dumps({"entries":[{"url":"https://api.example.com/orders/42","method":"GET","status":200,"content_type":"application/json","navigation":"fetch"}]},pretty=True)
        importer=f"""<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Import metadata in Dashboard</h3></div><div class='panel-body'><form method='post' action='/workspace/capture-import'><label>Target<select name='target' required><option value=''>Choose target</option>{options}</select></label><label>Authorized context label<input name='context' required placeholder='Account A'></label><label>Capture JSON<textarea name='capture_json' rows='12' required placeholder='{_esc(sample)}'></textarea></label><button>Import redacted metadata</button></form><p class='muted'>Maximum Dashboard form size is intentionally bounded. Use the CLI importer for larger metadata exports. Raw cookies, Authorization values and response bodies are ignored.</p></div></section>"""
        self.send_html('Browser capture',header+f"<div class='callout'><strong>Metadata-only importer</strong><span>Expected fields: URL, method, status, content type, navigation type and an analyst-supplied context label.</span></div>{importer}<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Import from terminal</h3></div><div class='panel-body'><pre>{_esc(command)}</pre><button type='button' class='secondary' data-copy='{_esc(command)}'>Copy command</button></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Recent captures</h3></div><div class='table-wrap'><table><thead><tr><th>Target</th><th>Context</th><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Imported</th></tr></thead><tbody>{body or '<tr><td colspan=7>No browser metadata imported</td></tr>'}</tbody></table></div></section>")


    def false_positive_learning_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT DISTINCT target FROM bug_candidates ORDER BY target")]
            rows=false_positive_learning(db,target=target,persist=False)
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'All targets')}</label>",{'Target':target},'/learning',title='Learning focus',result_count=len(rows))
        tr=''.join(f"<tr><td>{_esc(r['target'])}</td><td>{_esc(r['bug_family'])}</td><td>{r['total']}</td><td>{r['confirmed']}</td><td>{r['rejected']}</td><td>{r['needs_more']}</td><td>{r['precision']}%</td><td>{_pill(r['recommendation'],'amber' if r['recommendation'] in {'tune','shadow_review'} else 'success')}</td></tr>" for r in rows)
        header=_page_header('False-positive learning','Uses analyst decisions to measure family precision and recommend tuning. It does not silently activate, disable or rewrite rules.',"<form method='post' action='/workspace/learning' style='display:inline'><input type='hidden' name='target' value='"+_esc(target)+"'><button>Refresh learning</button></form>",f'Recon Monitor {APP_VERSION} · Human-supervised learning')
        self.send_html('False-positive learning',header+controls+f"<section class='panel'><div class='table-wrap'><table><thead><tr><th>Target</th><th>Family</th><th>Total</th><th>Confirmed</th><th>Rejected</th><th>Needs evidence</th><th>Precision</th><th>Recommendation</th></tr></thead><tbody>{tr or '<tr><td colspan=8>No reviewed candidates yet</td></tr>'}</tbody></table></div></section>")

    def report_builder_page(self) -> None:
        p=self.query(); case_id=str((p.get('case_id') or [''])[0])
        db=self.db()
        try:
            cases=[dict(r) for r in db.all("SELECT case_id,target,title,state,report_readiness FROM security_cases ORDER BY updated_at DESC LIMIT 200")]
            drafts=[dict(r) for r in db.all("SELECT draft_id,case_id,title,status,readiness_score,updated_at FROM report_drafts ORDER BY updated_at DESC LIMIT 100")]
        finally: db.close()
        options=''.join(f"<option value='{_esc(c['case_id'])}'{' selected' if c['case_id']==case_id else ''}>{_esc(c['case_id'])} · {_esc(c['title'])}</option>" for c in cases)
        draft_html=''.join(f"<tr><td><code>{_esc(r['draft_id'])}</code></td><td>{_esc(r['case_id'])}</td><td>{_esc(r['title'])}</td><td>{r['readiness_score']}%</td><td>{_esc(r['status'])}</td><td>{_esc(r['updated_at'])}</td></tr>" for r in drafts)
        header=_page_header('Evidence-linked report builder','Builds claims only from linked evidence and blocks confirmed-vulnerability wording until an analyst has confirmed the case.','',f'Recon Monitor {APP_VERSION} · Report workspace')
        builder=f"<section class='panel'><div class='panel-head'><h3>Create report draft</h3></div><div class='panel-body'><form method='post' action='/workspace/report'><label>Security case<select name='case_id' required><option value=''>Choose case</option>{options}</select></label><input type='hidden' name='return' value='/report-builder'><button>Build evidence-linked draft</button></form><p class='muted'>Unconfirmed cases are explicitly blocked from being phrased as confirmed vulnerabilities.</p></div></section>"
        self.send_html('Report builder',header+builder+f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Recent drafts</h3></div><div class='table-wrap'><table><thead><tr><th>Draft</th><th>Case</th><th>Title</th><th>Readiness</th><th>Status</th><th>Updated</th></tr></thead><tbody>{draft_html or '<tr><td colspan=6>No drafts</td></tr>'}</tbody></table></div></section>")

    def attack_surface_api(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        if not target: self.send_json({'error':'target is required'},400); return
        db=self.db()
        try: data=attack_surface_graph(db,target=target,limit=1200)
        finally: db.close()
        self.send_json(data)

    def attack_surface_page(self) -> None:
        p=self.query(); target=str((p.get('target') or [''])[0])
        db=self.db()
        try:
            targets=[str(r[0]) for r in db.all("SELECT target FROM (SELECT DISTINCT target FROM assets UNION SELECT DISTINCT target FROM endpoint_intelligence) ORDER BY target")]
            if not target and targets: target=targets[0]
            data=attack_surface_graph(db,target=target,limit=500) if target else None
        finally: db.close()
        controls=_filter_panel(f"<label>Target{_select('target',targets,target,'Choose target')}</label>",{'Target':target},'/attack-surface',title='Attack surface focus')
        if not data: self.send_html('Attack surface',_page_header('Attack surface graph','A connected view of hosts, endpoints, JavaScript indicators and candidates.')+controls+_empty('Choose a target')); return
        payload=json.dumps(data,ensure_ascii=False)
        header=_page_header('Attack surface graph','Explore how hosts, endpoints, JavaScript indicators and candidates connect. Coverage blind spots remain visible beside the graph.','',f'Recon Monitor {APP_VERSION} · Connected surface')
        graph=f"<div class='graph-wrap'><svg id='attackSvg' viewBox='0 0 1200 760'></svg><div class='graph-panel'><h3>{_esc(target)}</h3><p>Coverage confidence: <strong>{data['coverage']['overall']}%</strong></p><p class='muted'>{_esc(' · '.join(data['coverage']['blind_spots']) or 'No major blind spot flagged')}</p><div id='attackDetail' class='muted'>Select a node.</div></div></div><script>(function(){{const data={payload};const svg=document.getElementById('attackSvg');const NS='http://www.w3.org/2000/svg';const nodes=data.nodes.slice(0,180);const map=new Map();const center={{x:580,y:360}};nodes.forEach((n,i)=>{{const a=(i/Math.max(1,nodes.length))*Math.PI*2;const ring=120+(i%6)*72;n.x=n.kind==='target'?center.x:center.x+Math.cos(a)*ring;n.y=n.kind==='target'?center.y:center.y+Math.sin(a)*ring;map.set(n.id,n);}});data.edges.slice(0,360).forEach(e=>{{const a=map.get(e.source),b=map.get(e.target);if(!a||!b)return;const l=document.createElementNS(NS,'line');l.setAttribute('x1',a.x);l.setAttribute('y1',a.y);l.setAttribute('x2',b.x);l.setAttribute('y2',b.y);l.setAttribute('class','edge');svg.appendChild(l);}});nodes.forEach(n=>{{const g=document.createElementNS(NS,'g');g.setAttribute('class','node');const c=document.createElementNS(NS,'circle');c.setAttribute('cx',n.x);c.setAttribute('cy',n.y);c.setAttribute('r',n.kind==='target'?16:n.kind==='candidate'?10:7);c.setAttribute('fill',n.kind==='candidate'?'#ff9859':n.kind==='endpoint'?'#7c9cff':n.kind==='javascript'?'#bd8cff':'#60d4ff');g.appendChild(c);const t=document.createElementNS(NS,'text');t.setAttribute('x',n.x+10);t.setAttribute('y',n.y+4);t.setAttribute('class','node-label');t.textContent=String(n.value).slice(0,42);g.appendChild(t);g.addEventListener('click',()=>document.getElementById('attackDetail').textContent=n.kind+' · '+n.value);svg.appendChild(g);}});}})();</script>"
        self.send_html('Attack surface',header+controls+graph)

    def notes(self) -> None:
        db=self.db()
        try: rows=db.all('SELECT id,target,entity_type,entity_value,note,created_at FROM investigation_notes ORDER BY created_at DESC LIMIT 500')
        finally: db.close()
        body=''.join(f"<tr><td>{r['id']}</td><td>{_esc(r['target'])}</td><td>{_esc(r['entity_type'])}</td><td><code>{_esc(r['entity_value'])}</code></td><td>{_esc(r['note'])}</td><td>{_esc(r['created_at'])}</td><td><form method='post' action='/notes/delete'><input type='hidden' name='id' value='{r['id']}'><input type='hidden' name='return' value='/notes'><button class='danger'>Delete</button></form></td></tr>" for r in rows)
        self.send_html('Notes',f"<h1>Investigation notes</h1><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Entity</th><th>Note</th><th>Created</th><th></th></tr></thead><tbody>{body}</tbody></table>")

    def search(self) -> None:
        q = str((self.query().get('q') or [''])[0]).strip()
        db = self.db()
        try:
            results = universal_search(db, q, limit=100) if q else {}
        finally:
            db.close()
        total = sum(len(rows) for rows in results.values())
        header = _page_header('Universal search', f"Search cases, stories, candidates, endpoints, assets, JavaScript, evidence and redacted browser captures.{f' {total} matches found.' if q else ''}", "<a class='button secondary' href='/'>Command center</a>", f'Recon Monitor {APP_VERSION} · Workspace index')
        form = f"<form class='filters'><label style='flex:1'>Search query<br><input style='width:100%' name='q' value='{_esc(q)}' placeholder='CASE-18, /api/orders, auth context, evidence…' required autofocus></label><button>Search</button></form>"
        if not q:
            self.send_html('Search', header + form + _empty('Start a universal research search', 'Use ⌘K for the command palette or / to focus this search.'))
            return
        summary = "<div class='metrics-grid'>" + ''.join(_metric_card(name, len(rows), 'Matching records', 'info') for name, rows in results.items()) + "</div>"
        href_map = {
            'Cases': lambda v: '/case?id=' + urllib.parse.quote(str(v)),
            'Candidates': lambda v: '/bug-candidate?id=' + urllib.parse.quote(str(v)),
            'Stories': lambda v: '/security-stories',
            'Endpoints': lambda v: '/endpoints?q=' + urllib.parse.quote(str(v)),
            'Assets': lambda v: '/assets?q=' + urllib.parse.quote(str(v)),
            'JavaScript': lambda v: '/javascript?q=' + urllib.parse.quote(str(v)),
            'Evidence': lambda v: '/evidence-gaps',
            'Captures': lambda v: '/browser-capture',
        }
        sections = []
        for name, rows in results.items():
            body_rows = []
            for row in rows:
                value = row.get('value', '')
                href = href_map.get(name, lambda v: '/search?q=' + urllib.parse.quote(str(v)))(value)
                body_rows.append(f"<tr><td>{_esc(row.get('target',''))}</td><td><a href='{_esc(href)}'><code>{_esc(value)}</code></a></td><td>{_esc(row.get('extra',''))}</td><td>{_esc(row.get('seen',''))}</td></tr>")
            sections.append(f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>{_esc(name)}</h3><span class='muted small'>{len(rows)} matches</span></div><div class='table-wrap' style='border:0;border-radius:0'><table><thead><tr><th>Target</th><th>Value</th><th>Context</th><th>Seen</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan=4>No matches</td></tr>'}</tbody></table></div></section>")
        self.send_html('Search', header + form + summary + ''.join(sections))

    def evidence_export(self) -> None:
        p=self.query(); alert_id=parse_int((p.get('alert_id') or [0])[0],0); target=str((p.get('target') or [''])[0]); entity_type=str((p.get('entity_type') or [''])[0]); entity_value=str((p.get('entity_value') or [''])[0])
        db=self.db()
        try: filename,data=build_evidence_export(db,target=target,entity_type=entity_type,entity_value=entity_value,alert_id=alert_id)
        finally: db.close()
        self.send_attachment(filename,data)

    def metrics(self) -> None:
        db=self.db()
        try:
            stage_rows=db.all("SELECT stage,COUNT(*) executions,ROUND(AVG(duration_seconds),2) average_seconds,ROUND(MAX(duration_seconds),2) maximum_seconds,SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) failures FROM stage_runs GROUP BY stage ORDER BY average_seconds DESC")
            run_rows=db.all('SELECT status,COUNT(*) count FROM runs GROUP BY status ORDER BY count DESC'); severity_rows=db.all('SELECT severity,COUNT(*) count FROM alerts GROUP BY severity ORDER BY count DESC'); target_rows=db.all('SELECT target,COUNT(*) assets,SUM(resolved) resolved,ROUND(AVG(confidence),1) average_confidence FROM assets GROUP BY target ORDER BY assets DESC'); tech_rows=db.all('SELECT technology,ROUND(AVG(confidence),1) confidence,COUNT(*) urls FROM technology_observations WHERE is_current=1 GROUP BY technology ORDER BY urls DESC LIMIT 30')
        finally: db.close()
        cards=''.join(f"<div class='card'><div class='muted'>Runs: {_esc(r['status'])}</div><div class='value'>{r['count']}</div></div>" for r in run_rows)+''.join(f"<div class='card'><div class='muted'>Alerts: {_esc(r['severity'])}</div><div class='value'>{r['count']}</div></div>" for r in severity_rows)
        stages=''.join(f"<tr><td>{_esc(r['stage'])}</td><td>{r['executions']}</td><td>{r['average_seconds']}</td><td>{r['maximum_seconds']}</td><td>{r['failures']}</td></tr>" for r in stage_rows); targets=''.join(f"<tr><td>{_esc(r['target'])}</td><td>{r['assets']}</td><td>{r['resolved']}</td><td>{r['average_confidence']}</td></tr>" for r in target_rows); tech=''.join(f"<tr><td>{_esc(r['technology'])}</td><td>{r['confidence']}%</td><td>{r['urls']}</td></tr>" for r in tech_rows)
        self.send_html('Metrics',f"<h1>Operational metrics</h1><div class='grid'>{cards}</div><h2>Stage performance</h2><table><thead><tr><th>Stage</th><th>Executions</th><th>Average seconds</th><th>Maximum seconds</th><th>Failures</th></tr></thead><tbody>{stages}</tbody></table><h2>Target data quality</h2><table><thead><tr><th>Target</th><th>Assets</th><th>Resolved</th><th>Average confidence</th></tr></thead><tbody>{targets}</tbody></table><h2>Technology confidence</h2><table><thead><tr><th>Technology</th><th>Average confidence</th><th>URLs</th></tr></thead><tbody>{tech}</tbody></table>")

    def health(self) -> None:
        db = self.db()
        try:
            diagnostics = operator_diagnostics(self.paths, self.config, db, persist=False)
            errors = recent_error_events(db, limit=12)
            browser = browser_compatibility(self.headers.get('User-Agent', ''))
        finally:
            db.close()
        status_tone = {'ok':'success','warn':'amber','error':'danger'}
        check_rows = ''.join(
            f"<tr><td><code>{_esc(c['id'])}</code></td><td>{_esc(c['label'])}</td><td><span class='badge'>{_esc(c['status'])}</span></td><td>{_esc(c['detail'])}</td><td>{_esc(c.get('recommended_action',''))}</td></tr>"
            for c in diagnostics['checks']
        )
        error_rows = ''.join(
            f"<tr><td><code>{_esc(e.get('error_id',''))}</code></td><td>{_esc(e.get('component',''))}</td><td>{_esc(e.get('summary',''))}</td><td>{_esc(e.get('created_at',''))}</td></tr>"
            for e in errors
        )
        header = _page_header('Health & self-check', 'Subsystem health, browser compatibility and safe operator diagnostics. Health checks never perform active target validation.', "<a class='button' href='/diagnostics'>Open diagnostics & repair</a>", f'Recon Monitor {APP_VERSION} · Stability & Operator UX')
        metrics = "<div class='metrics-grid'>" + _metric_card('Overall', diagnostics['overall'], 'Startup/operator self-check', status_tone.get(diagnostics['overall'],'info')) + _metric_card('Schema', next((c['detail'] for c in diagnostics['checks'] if c['id']=='DB-SCHEMA'),'unknown'), f'Expected schema {SCHEMA_VERSION}', 'info') + _metric_card('Browser', browser['family'], 'Dashboard compatibility', 'success' if browser['supported'] else 'amber') + _metric_card('Recent errors', len(errors), 'Structured error events', 'amber' if errors else 'success') + "</div>"
        browser_notes = ''.join(f"<li>{_esc(n)}</li>" for n in browser.get('notes', [])) or '<li>No browser-specific warning detected.</li>'
        body = header + metrics + f"<section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Subsystem checks</h3></div><div class='table-wrap'><table><thead><tr><th>ID</th><th>Subsystem</th><th>Status</th><th>Observed</th><th>Recommended action</th></tr></thead><tbody>{check_rows}</tbody></table></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Browser compatibility</h3></div><div class='panel-body'><p><strong>{_esc(browser['family'])}</strong> · supported: {_esc(browser['supported'])}</p><ul>{browser_notes}</ul></div></section><section class='panel' style='margin-top:16px'><div class='panel-head'><h3>Recent structured errors</h3></div><div class='table-wrap'><table><thead><tr><th>Error ID</th><th>Component</th><th>Summary</th><th>Time</th></tr></thead><tbody>{error_rows or '<tr><td colspan=4>No structured errors</td></tr>'}</tbody></table></div></section>"
        self.send_html('Health', body)

    def report(self, run_id: str) -> None:
        db=self.db()
        try: row=db.one('SELECT run_dir FROM run_targets WHERE run_id=? LIMIT 1',(run_id,))
        finally: db.close()
        if not row: self.send_html('Not found','<h1>Report not found</h1>',404); return
        report=Path(str(row['run_dir']))/'report.html'
        if not report.exists(): self.send_html('Not found','<h1>Report not generated</h1>',404); return
        data=report.read_bytes(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data)


def serve_dashboard(paths: AppPaths, config: Config, logger: Logger, host: str = "127.0.0.1", port: int = 8787, allow_remote: bool = False) -> None:
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if not loopback and not (allow_remote and config.bool("DASHBOARD_ALLOW_REMOTE", False)):
        raise ReconError("Dashboard refuses non-loopback binding without both --allow-remote and DASHBOARD_ALLOW_REMOTE=yes")
    if not loopback and not config.bool("DASHBOARD_AUTH_ENABLED", False):
        raise ReconError("Dashboard authentication must be enabled before binding to a non-loopback address")
    handler = type(
        "ConfiguredDashboardHandler",
        (DashboardHandler,),
        {"db_path": paths.db, "paths": paths, "logger": logger, "config": config},
    )
    # Bind/listen before diagnostics so background startup readiness does not
    # depend on database-wide health checks completing within a fixed window.
    server = ThreadingHTTPServer((host, port), handler)
    logger.info("Dashboard started", url=f"http://{host}:{port}", authentication=config.bool("DASHBOARD_AUTH_ENABLED", False))
    print(f"Dashboard: http://{host}:{port}")

    def startup_self_check() -> None:
        # Dashboard uses bounded diagnostics by default. Full database-wide
        # diagnostics are retained behind explicit operator opt-in.
        try:
            diag_db = Database(paths.db)
            try:
                deep = config.bool(
                    "DASHBOARD_DEEP_STARTUP_DIAGNOSTICS",
                    False,
                )
                startup = operator_diagnostics(
                    paths,
                    config,
                    diag_db,
                    persist=True,
                    deep=deep,
                )
            finally:
                diag_db.close()

            mode = str(startup.get("mode") or ("deep" if deep else "light"))
            overall = str(startup.get("overall") or "unknown")
            checks = len(startup.get("checks", []))

            if overall == "ok":
                logger.info(
                    "Dashboard startup self-check passed",
                    mode=mode,
                    checks=checks,
                )
            else:
                logger.warn(
                    "Dashboard startup self-check requires attention",
                    mode=mode,
                    overall=overall,
                    checks=checks,
                )

        except Exception as exc:
            logger.warn(
                "Dashboard startup self-check failed",
                error_type=type(exc).__name__,
                error=str(exc)[:400],
            )

    threading.Thread(
        target=startup_self_check,
        name="dashboard-startup-self-check",
        daemon=True,
    ).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close(); logger.info("Dashboard stopped")
