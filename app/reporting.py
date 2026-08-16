from __future__ import annotations

import html
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

from core import (
    APP_VERSION,
    AppPaths,
    Config,
    Database,
    Logger,
    ReconError,
    TargetPolicy,
    TelegramNotifier,
    atomic_write_text,
    json_dumps,
    local_now,
    parse_int,
    read_jsonl,
    safe_json_loads,
    split_message,
    tool_path,
    utc_now,
)
from stages import StageContext
from analysis_engine import run_analysis

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _event_lines(events: Iterable[Mapping[str, Any]], limit: int = 20) -> list[str]:
    lines: list[str] = []
    for event in list(events)[:limit]:
        state = event.get("confirmation_state", "confirmed")
        change_class = event.get("change_class", event.get("category", "change"))
        lines.append(f"• [{event.get('severity','INFO')}] [{change_class}/{state}] {event.get('title')}: {event.get('item')}")
    return lines


def _notification_due(old: Mapping[str, Any] | None, cooldown_hours: int) -> bool:
    if not old or not old.get("last_notified"):
        return True
    import datetime as dt

    raw = str(old["last_notified"]).replace("Z", "+00:00")
    try:
        then = dt.datetime.fromisoformat(raw)
    except ValueError:
        return True
    return (dt.datetime.now(dt.timezone.utc) - then).total_seconds() >= cooldown_hours * 3600


def _send_notify_cli(config: Config, logger: Logger, message: str) -> bool:
    provider_config = config.get("NOTIFY_PROVIDER_CONFIG")
    if not provider_config or not tool_path("notify"):
        return False
    path = Path(provider_config).expanduser()
    if not path.exists():
        logger.warn("Notify provider config not found", path=str(path))
        return False
    try:
        proc = subprocess.run(
            ["notify", "-silent", "-bulk", "-char-limit", "3500", "-provider-config", str(path)],
            input=message,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warn("Notify CLI failed", error=str(exc))
        return False
    if proc.returncode != 0:
        logger.warn("Notify CLI returned an error", output=proc.stdout[-500:])
        return False
    return True



def _notification_policy(db: Database, target: str, event_type: str) -> dict[str, Any] | None:
    row = db.one(
        "SELECT * FROM notification_policies WHERE enabled=1 AND ((target=? AND event_type=?) OR (target=? AND event_type='*') OR (target='*' AND event_type=?) OR (target='*' AND event_type='*')) "
        "ORDER BY CASE WHEN target=? THEN 0 ELSE 1 END,CASE WHEN event_type=? THEN 0 ELSE 1 END LIMIT 1",
        (target, event_type, target, event_type, target, event_type),
    )
    return dict(row) if row else None

def create_alerts_and_notify(ctx: StageContext, baseline: bool) -> dict[str, Any]:
    events = list(read_jsonl(ctx.events_path))
    # The first successful scan establishes the target baseline.  Its change
    # events remain available in the run report and event-observation history,
    # but they must not enter the Alert lifecycle.  Otherwise every discovered
    # surface is mislabeled as a change alert and the second run cannot provide
    # the low-noise, time-sensitive delta feed that Alerts is intended for.
    if baseline:
        return {
            "events": len(events),
            "new_alerts": 0,
            "immediate": 0,
            "notified": False,
            "baseline_suppressed": bool(events),
            "baseline_alerts_created": False,
            "alerting_active": False,
            "confirmed_only": bool(
                ctx.policy.alert.get(
                    "confirmed_only",
                    ctx.config.bool("ALERT_CONFIRMED_ONLY", False),
                )
            ),
            "observed_unconfirmed": sum(
                1
                for event in events
                if event.get("confirmation_state") != "confirmed"
            ),
        }
    min_score = parse_int(ctx.policy.alert.get("minimum_score"), ctx.config.int("ALERT_MIN_SCORE", 70, 0, 100), 0, 100)
    cooldown = parse_int(ctx.policy.alert.get("cooldown_hours"), ctx.config.int("ALERT_COOLDOWN_HOURS", 24, 0, 720), 0, 720)
    max_items = ctx.config.int("ALERT_ITEM_LIMIT", 15, 1, 100)
    immediate: list[dict[str, Any]] = []
    new_alerts = 0
    confirmed_only = bool(ctx.policy.alert.get("confirmed_only", ctx.config.bool("ALERT_CONFIRMED_ONLY", False)))

    for event in events:
        alert_details = dict(event.get("details", {}))
        alert_details["change_class"] = event.get("change_class", "asset")
        alert_details["confirmation_state"] = event.get("confirmation_state", "confirmed")
        alert_details["observation_count"] = event.get("observation_count", 1)
        alert_details["risk_reasons"] = list(event.get("risk_reasons", []))
        alert_id, is_new, old = ctx.db.upsert_alert(
            ctx.policy.name,
            str(event["dedup_key"]),
            str(event["category"]),
            str(event["severity"]),
            int(event["risk_score"]),
            str(event["title"]),
            str(event["item"]),
            alert_details,
            ctx.run_id,
        )
        event["alert_id"] = alert_id
        if is_new:
            new_alerts += 1
            priority = "urgent" if str(event["severity"]) == "CRITICAL" else "high" if str(event["severity"]) == "HIGH" else "normal"
            ctx.db.update_alert_workflow(alert_id, priority=priority)
        old_dict = dict(old) if old else None
        ignored = old_dict and old_dict.get("status") in {"ignored", "false_positive"}
        confirmed = event.get("confirmation_state", "confirmed") == "confirmed"
        notification_policy = _notification_policy(ctx.db, ctx.policy.name, str(event.get("category") or "security_change"))
        policy_mode = str(notification_policy.get("mode")) if notification_policy else "legacy"
        effective_min = max(min_score, parse_int(notification_policy.get("minimum_score"), min_score, 0, 100)) if notification_policy else min_score
        immediate_allowed = policy_mode in {"legacy", "immediate"}
        if int(event["risk_score"]) >= effective_min and not ignored and _notification_due(old_dict, cooldown) and immediate_allowed:
            if not confirmed_only or confirmed:
                immediate.append(event)

    notified = False
    if immediate:
        immediate.sort(key=lambda x: int(x.get("risk_score", 0)), reverse=True)
        top = immediate[:max_items]
        message = "\n".join(
            [
                f"🚨 Recon Monitor {APP_VERSION}",
                f"Target: {ctx.policy.name}",
                f"Run: {ctx.run_id}",
                f"Time: {local_now()}",
                f"High-priority changes: {len(immediate)}",
                "",
                *_event_lines(top, max_items),
            ]
        )
        if len(immediate) > len(top):
            message += f"\n• … and {len(immediate) - len(top)} more"
        telegram = TelegramNotifier(ctx.config, ctx.logger)
        telegram_ok = False
        try:
            telegram_ok = telegram.send(message) if telegram.ready else False
        except ReconError as exc:
            ctx.logger.warn("Telegram notification failed", error=str(exc))
        notify_ok = _send_notify_cli(ctx.config, ctx.logger, message)
        notified = telegram_ok or notify_ok
        if notified:
            for event in immediate:
                ctx.db.mark_alert_notified(int(event["alert_id"]))

    return {
        "events": len(events),
        "new_alerts": new_alerts,
        "immediate": len(immediate),
        "notified": notified,
        "baseline_suppressed": False,
        "baseline_alerts_created": False,
        "alerting_active": True,
        "confirmed_only": confirmed_only,
        "observed_unconfirmed": sum(1 for event in events if event.get("confirmation_state") != "confirmed"),
    }


def _stage_metrics(ctx: StageContext) -> dict[str, Any]:
    rows = ctx.db.all(
        "SELECT stage,status,duration_seconds,attempt,metrics_json,error FROM stage_runs WHERE run_id=? AND target=? ORDER BY started_at",
        (ctx.run_id, ctx.policy.name),
    )
    result: dict[str, Any] = {}
    for row in rows:
        metrics = safe_json_loads(row["metrics_json"], {}, expected_type=dict)
        display_status = "success" if row["stage"] == "report" and row["status"] == "running" else row["status"]
        result[str(row["stage"])] = {
            "status": display_status,
            "duration_seconds": row["duration_seconds"],
            "attempt": row["attempt"],
            "metrics": metrics,
            "error": row["error"],
        }
    return result


def _current_counts(ctx: StageContext) -> dict[str, int]:
    queries = {
        "assets": "SELECT COUNT(*) FROM assets WHERE target=?",
        "resolved_assets": "SELECT COUNT(*) FROM assets WHERE target=? AND resolved=1",
        "dns_records": "SELECT COUNT(*) FROM dns_records WHERE target=? AND is_current=1",
        "urls": "SELECT COUNT(*) FROM urls WHERE target=?",
        "javascript_files": "SELECT COUNT(*) FROM js_files WHERE target=?",
        "javascript_indicators": "SELECT COUNT(*) FROM js_indicators WHERE target=?",
        "javascript_diffs": "SELECT COUNT(*) FROM js_diffs WHERE target=?",
        "classified_endpoints": "SELECT COUNT(*) FROM endpoint_intelligence WHERE target=?",
        "technology_observations": "SELECT COUNT(*) FROM technology_observations WHERE target=? AND is_current=1",
        "live_http": "SELECT COUNT(*) FROM fingerprints WHERE target=?",
        "open_ports": "SELECT COUNT(*) FROM ports WHERE target=? AND is_current=1",
        "findings": "SELECT COUNT(*) FROM findings WHERE target=?",
        "alerts": "SELECT COUNT(*) FROM alerts WHERE target=?",
        "asset_edges": "SELECT COUNT(*) FROM asset_edges WHERE target=?",
        "notes": "SELECT COUNT(*) FROM investigation_notes WHERE target=?",
        "tags": "SELECT COUNT(*) FROM entity_tags WHERE target=?",
        "incidents": "SELECT COUNT(*) FROM change_incidents WHERE target=?",
        "validated_endpoints": "SELECT COUNT(*) FROM endpoint_validations WHERE target=? AND reachable=1",
        "active_assets": "SELECT COUNT(*) FROM asset_lifecycle WHERE target=? AND state IN ('new','active','reappeared')",
    }
    counts: dict[str, int] = {}
    for key, sql in queries.items():
        row = ctx.db.one(sql, (ctx.policy.name,))
        counts[key] = int(row[0]) if row else 0
    return counts


def generate_report(ctx: StageContext, baseline: bool, notification: Mapping[str, Any]) -> dict[str, Any]:
    events = list(read_jsonl(ctx.events_path))
    events.sort(key=lambda x: int(x.get("risk_score", 0)), reverse=True)
    tools = [dict(row) for row in ctx.db.all("SELECT tool,version,path FROM tool_versions WHERE run_id=? ORDER BY tool", (ctx.run_id,))]
    js_diffs = [dict(row) for row in ctx.db.all(
        "SELECT id,js_url,summary_json,diff_path,created_at FROM js_diffs WHERE run_id=? AND target=? ORDER BY created_at DESC",
        (ctx.run_id, ctx.policy.name),
    )]
    for item in js_diffs:
        item["summary"] = safe_json_loads(item.pop("summary_json"), {}, expected_type=dict)
    endpoints = [dict(row) for row in ctx.db.all(
        "SELECT endpoint,kind,primary_category,confidence,reasons_json,sources_json,first_seen,last_seen FROM endpoint_intelligence WHERE target=? AND last_run_id=? ORDER BY confidence DESC LIMIT 500",
        (ctx.policy.name, ctx.run_id),
    )]
    technologies = [dict(row) for row in ctx.db.all(
        "SELECT url,technology,confidence,confidence_label,evidence_json FROM technology_observations WHERE target=? AND last_run_id=? AND is_current=1 ORDER BY confidence DESC,technology LIMIT 500",
        (ctx.policy.name, ctx.run_id),
    )]
    report = {
        "schema": 7,
        "recon_monitor_version": APP_VERSION,
        "generated_at": utc_now(),
        "run_id": ctx.run_id,
        "target": ctx.policy.name,
        "roots": ctx.policy.roots,
        "baseline": baseline,
        "policy_hash": ctx.policy.policy_hash(),
        "stages": _stage_metrics(ctx),
        "counts": _current_counts(ctx),
        "changes": {
            "total": len(events),
            "by_severity": {
                severity: sum(1 for event in events if event.get("severity") == severity)
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
            "events": events,
        },
        "notifications": dict(notification),
        "intelligence": {
            "javascript_diffs": js_diffs,
            "classified_endpoints": endpoints,
            "technology_confidence": technologies,
            "endpoint_validations": [dict(row) for row in ctx.db.all("SELECT * FROM endpoint_validations WHERE target=? AND last_run_id=? ORDER BY reachable DESC,confidence DESC LIMIT 500", (ctx.policy.name, ctx.run_id))],
            "incidents": [dict(row) for row in ctx.db.all("SELECT * FROM change_incidents WHERE target=? AND last_run_id=? ORDER BY risk_score DESC,last_seen DESC LIMIT 200", (ctx.policy.name, ctx.run_id))],
            "asset_lifecycle": [dict(row) for row in ctx.db.all("SELECT * FROM asset_lifecycle WHERE target=? ORDER BY last_seen DESC LIMIT 1000", (ctx.policy.name,))],
        },
        "budgets": {str(row["metric"]): {"used": int(row["used"]), "limit": int(row["limit_value"])} for row in ctx.db.all("SELECT metric,used,limit_value FROM run_budgets WHERE run_id=? AND target=?", (ctx.run_id,ctx.policy.name))},
        "tools": tools,
        "safety": {
            "active_modules_globally_enabled": ctx.config.active_globally_enabled,
            "target_active_confirmation": ctx.policy.active_confirmed,
            "active_cli_gate": ctx.allow_active,
            "ports_enabled": bool(ctx.policy.modules.get("ports")),
            "nuclei_enabled": bool(ctx.policy.modules.get("nuclei")),
        },
    }
    manifest = {
        "schema": 1,
        "run_id": ctx.run_id,
        "target": ctx.policy.name,
        "recon_monitor_version": APP_VERSION,
        "generated_at": report["generated_at"],
        "policy_hash": report["policy_hash"],
        "baseline": baseline,
        "tools": tools,
        "stages": report["stages"],
        "counts": report["counts"],
        "change_summary": {key: value for key, value in report["changes"].items() if key != "events"},
        "intelligence_summary": {
            "javascript_diffs": len(js_diffs),
            "classified_endpoints": len(endpoints),
            "technology_observations": len(technologies),
        },
        "outputs": {
            "report_json": str(ctx.run_dir / "report.json"),
            "report_html": str(ctx.run_dir / "report.html"),
            "events_jsonl": str(ctx.events_path),
            "current_dir": str(ctx.current),
            "changes_dir": str(ctx.changes),
        },
    }
    report["manifest"] = str(ctx.run_dir / "run-manifest.json")
    atomic_write_text(ctx.run_dir / "report.json", json_dumps(report, pretty=True) + "\n")
    atomic_write_text(ctx.run_dir / "run-manifest.json", json_dumps(manifest, pretty=True) + "\n")
    html_text = render_report_html(report)
    atomic_write_text(ctx.run_dir / "report.html", html_text)
    target_reports = ctx.paths.reports / ctx.policy.name
    target_reports.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target_reports / f"{ctx.run_id}.html", html_text)
    latest = target_reports / "latest.html"
    atomic_write_text(latest, html_text)
    return report


def render_report_html(report: Mapping[str, Any]) -> str:
    target = html.escape(str(report.get("target", "")))
    run_id = html.escape(str(report.get("run_id", "")))
    counts = report.get("counts", {})
    events = report.get("changes", {}).get("events", [])
    stage_rows = []
    for stage, value in report.get("stages", {}).items():
        metrics = html.escape(json_dumps(value.get("metrics", {})))
        stage_rows.append(
            f"<tr><td>{html.escape(stage)}</td><td>{html.escape(str(value.get('status')))}</td>"
            f"<td>{html.escape(str(value.get('duration_seconds') or 0))}</td><td><code>{metrics}</code></td></tr>"
        )
    event_rows = []
    for event in events:
        reasons = "\n".join(str(x) for x in event.get("risk_reasons", []))
        event_rows.append(
            "<tr>"
            f"<td><span class='sev {html.escape(str(event.get('severity','INFO')).lower())}'>{html.escape(str(event.get('severity','INFO')))}</span></td>"
            f"<td>{int(event.get('risk_score',0))}</td>"
            f"<td>{html.escape(str(event.get('change_class',event.get('category',''))))}</td>"
            f"<td>{html.escape(str(event.get('confirmation_state','confirmed')))}</td>"
            f"<td>{html.escape(str(event.get('title','')))}</td>"
            f"<td><code>{html.escape(str(event.get('item','')))}</code></td>"
            f"<td><code>{html.escape(reasons)}</code></td>"
            "</tr>"
        )
    count_cards = "".join(
        f"<div class='card'><div class='label'>{html.escape(str(key).replace('_',' ').title())}</div><div class='value'>{int(value)}</div></div>"
        for key, value in counts.items()
    )
    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Recon Monitor — {target}</title>
<style>
:root{{--bg:#0b1020;--panel:#131a2c;--text:#eef2ff;--muted:#9aa6c5;--border:#28324d;--accent:#7aa2ff}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,sans-serif}}
main{{max-width:1200px;margin:auto;padding:28px}} h1,h2{{margin:.2em 0 .6em}} .muted{{color:var(--muted)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px}} .label{{color:var(--muted)}} .value{{font-size:26px;margin-top:5px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border)}} th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--border);vertical-align:top}} code{{white-space:pre-wrap;word-break:break-word;color:#cbd5ff}}
.sev{{font-weight:700}} .critical{{color:#ff6b7a}} .high{{color:#ffad66}} .medium{{color:#ffe082}} .low{{color:#89d185}} .info{{color:#8ab4ff}}
section{{margin-top:28px}} .scroll{{overflow:auto}} a{{color:var(--accent)}}
</style>
</head>
<body><main>
<h1>Recon Monitor report</h1>
<p><strong>Target:</strong> {target}<br><strong>Run:</strong> {run_id}<br><strong>Generated:</strong> {html.escape(str(report.get('generated_at','')))}<br><strong>Baseline:</strong> {bool(report.get('baseline'))}</p>
<div class='grid'>{count_cards}</div>
<section><h2>Changes</h2><div class='scroll'><table><thead><tr><th>Severity</th><th>Score</th><th>Class</th><th>State</th><th>Title</th><th>Item</th><th>Risk reasons</th></tr></thead><tbody>{''.join(event_rows) or '<tr><td colspan=7>No changes</td></tr>'}</tbody></table></div></section>
<section><h2>Detailed JavaScript diffs</h2><div class='scroll'><table><thead><tr><th>ID</th><th>JavaScript URL</th><th>Additions</th><th>Removals</th><th>Added endpoints</th><th>Diff path</th></tr></thead><tbody>{''.join(f"<tr><td>{html.escape(str(item.get('id','')))}</td><td><code>{html.escape(str(item.get('js_url','')))}</code></td><td>{int(item.get('summary',{}).get('additions',0))}</td><td>{int(item.get('summary',{}).get('removals',0))}</td><td>{len(item.get('summary',{}).get('added_endpoints',[]))}</td><td><code>{html.escape(str(item.get('diff_path','')))}</code></td></tr>" for item in report.get('intelligence',{}).get('javascript_diffs',[])) or '<tr><td colspan=6>No JavaScript diffs</td></tr>'}</tbody></table></div></section>
<section><h2>Classified endpoints</h2><div class='scroll'><table><thead><tr><th>Endpoint</th><th>Kind</th><th>Class</th><th>Confidence</th><th>Reasons</th></tr></thead><tbody>{''.join(f"<tr><td><code>{html.escape(str(item.get('endpoint','')))}</code></td><td>{html.escape(str(item.get('kind','')))}</td><td>{html.escape(str(item.get('primary_category','')))}</td><td>{int(item.get('confidence',0))}%</td><td><code>{html.escape(str(item.get('reasons_json','')))}</code></td></tr>" for item in report.get('intelligence',{}).get('classified_endpoints',[])) or '<tr><td colspan=5>No classified endpoints</td></tr>'}</tbody></table></div></section>
<section><h2>Technology confidence</h2><div class='scroll'><table><thead><tr><th>URL</th><th>Technology</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{''.join(f"<tr><td><code>{html.escape(str(item.get('url','')))}</code></td><td>{html.escape(str(item.get('technology','')))}</td><td>{int(item.get('confidence',0))}% ({html.escape(str(item.get('confidence_label','')))})</td><td><code>{html.escape(str(item.get('evidence_json','')))}</code></td></tr>" for item in report.get('intelligence',{}).get('technology_confidence',[])) or '<tr><td colspan=4>No technology observations</td></tr>'}</tbody></table></div></section>
<section><h2>Stage execution</h2><div class='scroll'><table><thead><tr><th>Stage</th><th>Status</th><th>Seconds</th><th>Metrics</th></tr></thead><tbody>{''.join(stage_rows)}</tbody></table></div></section>
<p class='muted'>Generated by Recon Monitor {APP_VERSION}. Active modules are disabled unless all authorization gates are satisfied.</p>
</main></body></html>"""


def stage_report(ctx: StageContext, baseline: bool) -> dict[str, Any]:
    lifecycle = ctx.db.refresh_asset_lifecycle(ctx.policy.name, ctx.run_id) if ctx.policy.modules.get("subdomains", True) and ctx.db.stage_status(ctx.run_id, ctx.policy.name, "subdomains") == "success" else {}
    notification = create_alerts_and_notify(ctx, baseline)
    analysis_summary: dict[str, Any] = {}
    try:
        analysis_summary = run_analysis(ctx.paths, ctx.db, ctx.run_id, ctx.policy.name, mode="automatic")
    except Exception as exc:
        ctx.logger.warn("Analysis engine failed without blocking report generation", target=ctx.policy.name, run_id=ctx.run_id, error=str(exc))
        analysis_summary = {"status": "failed", "error": str(exc)}
    report = generate_report(ctx, baseline, notification)
    return {
        "events": report["changes"]["total"],
        "alerts": notification["new_alerts"],
        "notified": notification["notified"],
        "report": str(ctx.run_dir / "report.html"),
        "manifest": str(ctx.run_dir / "run-manifest.json"),
        "lifecycle": lifecycle,
        "analysis": analysis_summary,
    }


def send_daily_digest(paths: AppPaths, config: Config, db: Database, logger: Logger, hours: int = 24) -> dict[str, Any]:
    import datetime as dt

    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rows = db.all(
        """
        SELECT target,category,severity,risk_score,title,item,last_seen,occurrences
        FROM alerts WHERE last_seen>=? AND status NOT IN ('ignored','false_positive')
        ORDER BY risk_score DESC,last_seen DESC LIMIT 100
        """,
        (since,),
    )
    rows = [row for row in rows if (lambda policy: policy is None or str(policy.get("mode")) == "digest")(_notification_policy(db, str(row["target"]), str(row["category"] or "security_change")))]
    if not rows:
        return {"alerts": 0, "sent": False}
    lines = [f"📋 Recon Monitor digest — last {hours}h", f"Generated: {local_now()}", ""]
    for row in rows[:30]:
        lines.append(f"• [{row['severity']}] {row['target']} — {row['title']}: {row['item']}")
    if len(rows) > 30:
        lines.append(f"• … and {len(rows)-30} more")
    message = "\n".join(lines)
    telegram = TelegramNotifier(config, logger)
    sent = False
    if telegram.ready:
        sent = telegram.send(message)
    sent = _send_notify_cli(config, logger, message) or sent
    return {"alerts": len(rows), "sent": sent}
