"""Counted, paginated search over the local research workspace.

Identifiers come only from this allowlist. Credentials and authentication tables
are deliberately outside the research index. No network or database writes occur.
"""
from __future__ import annotations

import datetime as dt
import urllib.parse
from dataclasses import dataclass
from typing import Any

from core import AppPaths, Database
from dashboard_artifact_search import search_artifact_text
from dashboard_design import read_snapshot


@dataclass(frozen=True)
class SearchGroup:
    name: str
    table: str
    value: tuple[str, ...]
    context: tuple[str, ...]
    route: str
    selector: str = "q"
    fields: tuple[str, ...] = ()


# Preserve the original eight group names for CLI consumers, and index the raw
# observations and investigation records that used to be absent from search.
SEARCH_GROUPS = (
    SearchGroup("Cases", "security_cases", ("case_id",), ("title", "state", "primary_family"), "/case", "id"),
    SearchGroup("Stories", "security_stories", ("story_id",), ("title", "status"), "/security-stories"),
    SearchGroup("Candidates", "bug_candidates", ("candidate_id",), ("title", "bug_family", "candidate_state"), "/bug-candidate", "id"),
    SearchGroup("Endpoints", "endpoint_intelligence", ("endpoint",), ("primary_category", "confidence"), "/endpoints"),
    SearchGroup("Assets", "assets", ("host",), ("confidence", "resolved"), "/asset", "host"),
    SearchGroup("JavaScript", "js_indicators", ("value",), ("kind", "js_url"), "/javascript"),
    SearchGroup("Evidence", "evidence_records", ("evidence_id",), ("evidence_type", "polarity", "summary"), "/search", "record"),
    SearchGroup("Captures", "browser_capture_events", ("event_id",), ("context_label", "method", "url"), "/browser-capture"),
    SearchGroup("URLs", "urls", ("url",), ("kind", "source"), "/urls"),
    SearchGroup("Ports", "ports", ("host", "port", "protocol"), ("ip", "is_current"), "/recon"),
    SearchGroup("Fingerprints", "fingerprints", ("url",), ("status_code", "title", "webserver"), "/fingerprints"),
    SearchGroup("JavaScript files", "js_files", ("url",), ("content_length", "source_map_url", "blob_path"), "/recon"),
    SearchGroup("JavaScript diffs", "js_diffs", ("id",), ("js_url", "summary_json"), "/js-diff", "id"),
    SearchGroup("DNS records", "dns_records", ("host", "rrtype", "value"), ("is_current",), "/asset", "host"),
    SearchGroup("Runs", "runs", ("id",), ("status", "target_selector", "error"), "/run-review", "id"),
    SearchGroup("Stages", "stage_runs", ("run_id", "stage"), ("status", "error", "exit_code"), "/run-review", "id"),
    SearchGroup("Analyses", "analysis_runs", ("id",), ("status", "engine_version", "rule_version", "error"), "/analysis"),
    SearchGroup("Signal alerts", "alerts", ("id",), ("title", "category", "severity", "status", "item"), "/alert", "id"),
    SearchGroup("Findings", "findings", ("dedup_key",), ("name", "template_id", "severity", "matched_at"), "/search", "record"),
    SearchGroup("Notes", "investigation_notes", ("entity_value",), ("entity_type", "note"), "/notes"),
    SearchGroup("Tags", "entity_tags", ("entity_value",), ("entity_type", "tag"), "/search", "record"),
    SearchGroup("Hypotheses", "analysis_hypotheses", ("hypothesis_id",), ("bug_family", "state", "summary", "endpoint"), "/hypotheses"),
    SearchGroup("Clusters", "analysis_clusters", ("cluster_key",), ("member_count", "members_json"), "/clusters"),
    SearchGroup("Dataflows", "js_dataflows", ("js_url",), ("source_kind", "sink_kind", "snippet"), "/dataflows"),
    SearchGroup("Semantic units", "semantic_js_units", ("js_url", "unit_key"), ("unit_type", "value_json"), "/semantic-intelligence"),
    SearchGroup("Source maps", "source_map_intelligence", ("source_map_url",), ("js_url", "source_count", "evidence_json"), "/semantic-intelligence"),
    SearchGroup("GraphQL", "graphql_intelligence", ("operation_name",), ("operation_type", "js_url"), "/semantic-intelligence"),
    SearchGroup("Protocol findings", "protocol_findings", ("finding_id",), ("protocol", "entity", "kind", "summary"), "/semantic-intelligence"),
    SearchGroup("Endpoint contracts", "endpoint_contracts", ("endpoint",), ("method", "auth_boundary", "input_fields_json", "output_fields_json"), "/security-reasoning"),
    SearchGroup("Incidents", "change_incidents", ("id",), ("title", "severity", "status", "details_json"), "/incidents"),
    SearchGroup("Validation plans", "validation_plans", ("plan_id",), ("case_id", "level", "status", "plan_json"), "/safe-validation", "plan_id", ("plan_id", "case_id", "target", "level", "status", "plan_json", "created_by")),
    SearchGroup("Validation runs", "validation_runs", ("run_id",), ("case_id", "status", "result", "summary_json"), "/safe-validation", "case_id"),
    SearchGroup("Imported evidence", "imported_http_evidence", ("observation_id",), ("case_id", "source_type", "source_file", "observation_json"), "/case", "case_id"),
    SearchGroup("Errors", "error_events", ("error_id",), ("component", "error_code", "summary"), "/diagnostics"),
    SearchGroup("Authentication contexts", "auth_context_profiles", ("context_id",), ("label", "auth_state", "sources_json"), "/auth-contexts"),
    SearchGroup("Authentication boundaries", "authentication_boundaries", ("endpoint",), ("boundary", "confidence", "evidence_json"), "/auth-contexts"),
    SearchGroup("Authentication changes", "authentication_boundary_diffs", ("endpoint",), ("transition", "previous_boundary", "current_boundary"), "/differential-intelligence"),
    SearchGroup("Response shapes", "response_shape_fingerprints", ("endpoint",), ("status_code", "keys_json", "sensitive_keys_json"), "/differential-intelligence"),
    SearchGroup("Response changes", "response_shape_diffs", ("endpoint",), ("transition", "added_keys_json", "removed_keys_json", "sensitive_added_json"), "/differential-intelligence"),
    SearchGroup("Behavioral observations", "behavioral_observations", ("endpoint",), ("context", "auth_state", "status_code", "source_ref"), "/behavioral-intelligence"),
    SearchGroup("Differential findings", "differential_findings", ("diff_id",), ("endpoint", "diff_kind", "severity", "details_json"), "/differential-intelligence"),
    SearchGroup("Technologies", "technology_observations", ("url", "technology"), ("confidence_label", "evidence_json"), "/fingerprints"),
    SearchGroup("Candidate bundles", "candidate_bundles", ("bundle_id",), ("title", "summary", "primary_family"), "/candidate-bundles"),
    SearchGroup("Target memory", "target_memory", ("target",), ("confidence", "memory_json"), "/target-memory"),
    SearchGroup("Report drafts", "report_drafts", ("draft_id",), ("case_id", "title", "status", "body_json"), "/report-builder", "case_id"),
    SearchGroup("Report claims", "report_claims", ("claim_id",), ("case_id", "claim", "supported", "evidence_refs_json"), "/report-builder", "case_id"),
)

_EXCLUDED = {"approval_phrase_hash", "config_hash", "password_hash", "token_hash"}


def _quoted(name: str) -> str:
    # Called only with identifiers from SEARCH_GROUPS / PRAGMA table_info.
    return '"' + name.replace('"', '""') + '"'


def _text(columns: tuple[str, ...] | list[str], available: set[str], separator: str = " · ") -> str:
    parts = [f"COALESCE(CAST(s.{_quoted(col)} AS TEXT),'')" for col in columns if col in available]
    return (" || '" + separator + "' || ").join(parts) if parts else "''"


def _spec(db: Database, group: SearchGroup, query: str, target: str, run_id: str,
          since: str, record: str) -> tuple[str, list[Any]] | None:
    schema = db.all(f"PRAGMA table_info({_quoted(group.table)})")
    available = {str(row['name']) for row in schema}
    if not available:
        return None
    value = _text(group.value, available)
    context = _text(group.context, available)
    target_expr = "COALESCE(s.target,'')" if 'target' in available else ("COALESCE(s.target_selector,'')" if group.table == 'runs' else "''")
    if 'target' not in available and 'case_id' in available:
        target_expr = "COALESCE((SELECT c.target FROM security_cases c WHERE c.case_id=s.case_id),'')"
    source_cols = tuple(c for c in ('source_run_id', 'last_run_id', 'run_id') if c in available)
    source = _text(source_cols[:1], available)
    if group.table == 'runs':
        source = "s.id"
    elif not source_cols and 'case_id' in available:
        source = "COALESCE((SELECT c.source_run_id FROM security_cases c WHERE c.case_id=s.case_id),'')"
    analysis = "COALESCE(s.analysis_id,'')" if 'analysis_id' in available else ("s.id" if group.table == 'analysis_runs' else "''")
    dates = [f"NULLIF(s.{_quoted(col)},'')" for col in ('updated_at', 'last_seen', 'finished_at', 'created_at', 'started_at') if col in available]
    seen = "COALESCE(" + ','.join(dates + ["''"]) + ")" if dates else "''"
    where: list[str] = []
    args: list[Any] = []
    if query and query != '*':
        # Search literal text: a percent sign or underscore is not a wildcard.
        like = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        fields = [c for c in (group.fields or tuple(available)) if c in available and c not in _EXCLUDED]
        where.append('(' + ' OR '.join(f"CAST(s.{_quoted(c)} AS TEXT) LIKE ? ESCAPE '\\'" for c in sorted(fields)) + ')')
        args.extend([like] * len(fields))
    if record:
        where.append(value + '=?'); args.append(record)
    if target:
        if group.table == 'analysis_runs':
            where.append("(s.target=? OR (s.target='*' AND EXISTS(SELECT 1 FROM run_targets rt WHERE rt.run_id=s.source_run_id AND rt.target=?)))"); args.extend([target,target])
        elif 'target' in available:
            where.append('s.target=?'); args.append(target)
        elif group.table == 'runs':
            where.append('EXISTS(SELECT 1 FROM run_targets rt WHERE rt.run_id=s.id AND rt.target=?)'); args.append(target)
        elif 'analysis_id' in available:
            where.append('EXISTS(SELECT 1 FROM analysis_runs ar WHERE ar.id=s.analysis_id AND ar.target=?)'); args.append(target)
        elif 'case_id' in available:
            where.append('EXISTS(SELECT 1 FROM security_cases c WHERE c.case_id=s.case_id AND c.target=?)'); args.append(target)
        else:
            where.append('0')  # Global records do not belong to a selected target.
    if run_id:
        if group.table == 'runs':
            where.append('s.id=?'); args.append(run_id)
        elif source_cols:
            where.append('(' + ' OR '.join(f"s.{_quoted(c)}=?" for c in source_cols) + ')'); args.extend([run_id] * len(source_cols))
        elif 'analysis_id' in available:
            where.append('EXISTS(SELECT 1 FROM analysis_runs ar WHERE ar.id=s.analysis_id AND ar.source_run_id=?)'); args.append(run_id)
        elif 'case_id' in available:
            where.append('EXISTS(SELECT 1 FROM security_cases c WHERE c.case_id=s.case_id AND c.source_run_id=?)'); args.append(run_id)
        else:
            where.append('0')
    if since:
        where.append(seen + '>=?'); args.append(since)
    # Primary-key ordering makes adjacent pages stable when timestamps are equal.
    keys = [str(r['name']) for r in schema if r['pk']]
    tie = _text(tuple(keys), available)
    payload = ''
    if record:
        detail_columns = sorted(c for c in (group.fields or tuple(available)) if c in available and c not in _EXCLUDED)
        pairs = ','.join("'" + c.replace("'", "''") + "',s." + _quoted(c) for c in detail_columns)
        payload = ',json_object(' + pairs + ') record_details'
    sql = (f"SELECT {target_expr} target,{value} value,{context} extra,{seen} seen,"
           f"{source} source_run_id,{analysis} analysis_id,{tie} record_key{payload} "
           f"FROM {_quoted(group.table)} s WHERE " + (' AND '.join(where) or '1=1'))
    return sql, args


def search_targets(db: Database) -> list[str]:
    selects = ['SELECT target FROM run_targets']
    for table in dict.fromkeys(group.table for group in SEARCH_GROUPS):
        available = {str(row['name']) for row in db.all(f"PRAGMA table_info({_quoted(table)})")}
        if 'target' in available: selects.append(f"SELECT target FROM {_quoted(table)} WHERE target<>''")
    if not selects: return []
    return [str(row[0]) for row in db.all('SELECT target FROM (' + ' UNION '.join(selects) + ') ORDER BY target')]


def _change_matches(db: Database, query: str, target: str, run_id: str,
                    since: str, record: str) -> list[dict[str, Any]]:
    # Imported at call time to retain the existing, shared change semantics.
    from dashboard_core import _change_alert_events
    rows = []
    for event in _change_alert_events(db, target):
        if run_id and event['run_id'] != run_id: continue
        if since and str(event.get('detected') or '') < since: continue
        value = str(event['value'])
        if record and value != record: continue
        context = ' · '.join(str(event.get(key) or '') for key in ('kind','change','priority','details'))
        text = ' '.join(str(value) for value in event.values()).casefold()
        if query != '*' and query.casefold() not in text: continue
        params = {'view':'all','target':str(event['target']),'q':value,'kind':str(event['kind']),'change':str(event['change'])}
        rows.append({'target':str(event['target']), 'value':value, 'extra':context,
                     'seen':str(event.get('detected') or ''), 'source_run_id':str(event['run_id']),
                     'analysis_id':'', 'record_key':str(event['event_id']),
                     'href':'/alerts?'+urllib.parse.urlencode(params),'workspace':'/alerts'})
    return rows


def result_href(group: SearchGroup, row: dict[str, Any]) -> str:
    value = str(row.get('value') or '')
    params: dict[str, str] = {'target': str(row.get('target') or '')}
    selector_value = value
    if group.name == 'Stages':
        selector_value = str(row.get('source_run_id') or '')
    elif group.name == 'DNS records':
        selector_value = value.split(' · ', 1)[0]
    elif group.name in {'Validation runs', 'Imported evidence', 'Report drafts', 'Report claims'}:
        selector_value = str(row.get('extra') or '').split(' · ', 1)[0]
    if group.route == '/recon':
        params.update(view='raw', raw='port' if group.name == 'Ports' else 'javascript', q=value.split(' · ', 1)[0])
    elif group.selector == 'record':
        params.update(q='*', group=group.name, record=value)
    elif group.name in {'Stories', 'Captures', 'Hypotheses', 'Clusters', 'Dataflows', 'Semantic units', 'Source maps', 'GraphQL', 'Protocol findings', 'Endpoint contracts', 'Incidents', 'Analyses', 'Notes', 'Errors', 'Authentication contexts', 'Authentication boundaries', 'Authentication changes', 'Response shapes', 'Response changes', 'Behavioral observations', 'Differential findings', 'Technologies', 'Candidate bundles', 'Target memory'}:
        # These specialist pages do not all implement exact record selectors.
        # Open the matching local record, then offer its specialist workspace.
        params.update(q='*', group=group.name, record=value)
        return '/search?' + urllib.parse.urlencode({k: v for k, v in params.items() if v})
    else:
        params[group.selector] = selector_value
    return group.route + '?' + urllib.parse.urlencode({k: v for k, v in params.items() if v})


def search_workspace(db: Database, query: str, *, target: str = '', run_id: str = '',
                     group: str = '', days: int = 0, page: int = 1,
                     page_size: int = 100, record: str = '', include_files: bool = False,
                     paths: AppPaths | None = None) -> dict[str, Any]:
    with read_snapshot(db):
        return _search_workspace(db, query, target=target, run_id=run_id, group=group,
                                 days=days, page=page, page_size=page_size, record=record,
                                 include_files=include_files, paths=paths)


def _search_workspace(db: Database, query: str, *, target: str, run_id: str,
                      group: str, days: int, page: int, page_size: int,
                      record: str, include_files: bool, paths: AppPaths | None) -> dict[str, Any]:
    query = str(query or '').strip()
    if not query and not record:
        return {'counts': {}, 'total': 0, 'rows': {}, 'page': 1, 'page_size': page_size, 'unavailable': [], 'unavailable_files': 0}
    page_size = max(1, min(200, int(page_size)))
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat().replace('+00:00', 'Z') if days else ''
    counts: dict[str, int] = {}
    specs: dict[str, tuple[SearchGroup, str, list[Any]]] = {}
    unavailable: list[str] = []
    for item in SEARCH_GROUPS:
        spec = _spec(db, item, query, target, run_id, since, record)
        if spec is None:
            unavailable.append(item.name)
            continue
        sql, args = spec
        counts[item.name] = int(db.one('SELECT COUNT(*) FROM (' + sql + ')', args)[0])
        specs[item.name] = (item, sql, args)
    change_rows = _change_matches(db, query, target, run_id, since, record)
    counts['Change alerts'] = len(change_rows)
    file_rows: list[dict[str, Any]] = []
    unavailable_files = 0
    if include_files and paths is not None:
        file_rows, unavailable_files = search_artifact_text(db, paths, query, target=target, run_id=run_id, since=since, record=record)
        counts['Stored text'] = len(file_rows)
    chosen = [group] if group in counts else list(counts)
    total = sum(counts[name] for name in chosen)
    page = max(1, min(int(page), max(1, (total + page_size - 1) // page_size)))
    skip = (page - 1) * page_size
    remaining = page_size
    rows: dict[str, list[dict[str, Any]]] = {}
    for name in chosen:
        if skip >= counts[name]:
            skip -= counts[name]
            continue
        if remaining <= 0:
            break
        if name == 'Change alerts':
            batch = change_rows[skip:skip+remaining]
        elif name == 'Stored text':
            batch = file_rows[skip:skip+remaining]
        else:
            item, sql, args = specs[name]
            batch = [dict(r) for r in db.all(sql + ' ORDER BY seen DESC,record_key,value LIMIT ? OFFSET ?', (*args, remaining, skip))]
            for row in batch:
                row['href'] = result_href(item, row)
                row['workspace'] = item.route
        rows[name] = batch
        remaining -= len(batch)
        skip = 0
    return {'counts': counts, 'total': total, 'rows': rows, 'page': page,
            'page_size': page_size, 'unavailable': unavailable, 'unavailable_files': unavailable_files}
