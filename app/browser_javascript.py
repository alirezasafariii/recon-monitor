"""Bounded browser JavaScript evidence and isolated, offline engine analysis.

Archive claims describe a local browser capture, never verified live availability
or authentication. The live run and its current assets are read-only inputs.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import stat
import urllib.parse
import uuid
import zipfile
import zlib
from pathlib import Path
from typing import Any

from core import (
    AppPaths, Config, Database, Logger, PolicySet, ReconError, RunLock,
    TargetPolicy, atomic_write_text, extract_js_indicators, json_dumps, utc_now,
)
from intelligence import classify_endpoint
from javascript_normalization import normalize_javascript_bytes
from storage import ContentAddressedStore

FORMAT = 'recon-browser-javascript-v1'
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_SOURCES = 500  # The engine's per-analysis JavaScript source limit.
MAX_INDICATORS = 50_000
MAX_REPORT_BYTES = 16 * 1024 * 1024
JS_TYPES = frozenset({'application/javascript', 'text/javascript',
                      'application/ecmascript', 'text/ecmascript', 'application/x-javascript'})
DIGEST = re.compile(r'[0-9a-f]{64}')
IMPORT_ID = re.compile(r'bjs-[0-9a-f]{32}')
GQL = re.compile(r'\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{0,199})'
                 r'(?:\s|\\[nrt])*(?=\((?:\s|\\[nrt])*\$|\{)')
MAP = re.compile(r'(?m)^[ \t]*//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)\s*\Z')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReconError('Duplicate JSON keys in browser JavaScript evidence')
        result[key] = value
    return result


def _integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ReconError(f'Invalid {label} in browser JavaScript evidence')
    return value


def _redacted_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ReconError('Invalid browser JavaScript URL')
    try:
        value.encode('utf-8')
        u = urllib.parse.urlsplit(value)
        if u.scheme not in {'https', 'http'} or not u.hostname or u.username is not None or u.password is not None:
            raise ValueError('HTTP URL without credentials required')
        _ = u.port
        return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path,
            urllib.parse.urlencode([(key, '[redacted]') for key, _ in
                                    urllib.parse.parse_qsl(u.query, keep_blank_values=True)]), ''))
    except (ValueError, UnicodeError) as exc:
        raise ReconError('Invalid browser JavaScript URL') from exc


def _read_archive(file_path: str | Path, policy: TargetPolicy) -> dict[str, Any]:
    with Path(file_path).expanduser().open('rb') as handle:
        raw = handle.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ReconError('Browser JavaScript archive exceeds 128 MiB')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            names = {entry.filename for entry in members}
            if (len(names) != len(members) or 'index.json' not in names
                    or len(members) > min(MAX_SOURCES, policy.limits.max_js_files) + 1):
                raise ReconError('Invalid or over-limit browser JavaScript archive members')
            expanded = 0
            for entry in members:
                if (entry.filename != entry.orig_filename or not (
                        entry.filename == 'index.json' or re.fullmatch(r'[0-9a-f]{64}\.js', entry.filename))
                        or entry.flag_bits & 1
                        or stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG}
                        or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                    raise ReconError('Unexpected, linked, encrypted or unsupported archive member')
                limit = MAX_INDEX_BYTES if entry.filename == 'index.json' else policy.limits.max_js_bytes
                if entry.file_size > limit:
                    raise ReconError('Browser JavaScript archive member exceeds its size limit')
                expanded += entry.file_size
            if expanded > MAX_EXPANDED_BYTES:
                raise ReconError('Expanded browser JavaScript archive exceeds 128 MiB')
            index = json.loads(archive.read('index.json').decode('utf-8-sig'), object_pairs_hook=_object)
            allowed = {'format', 'target', 'provenance', 'javascript_observations',
                       'exported_observations', 'sources', 'omitted'}
            if (not isinstance(index, dict) or set(index) - allowed
                    or index.get('format') != FORMAT or index.get('provenance') != 'local_har'
                    or index.get('target') != policy.name):
                raise ReconError('Expected a scoped recon-browser-javascript-v1 export')
            sources = index.get('sources')
            if not isinstance(sources, list) or not 1 <= len(sources) <= min(MAX_SOURCES, policy.limits.max_js_files):
                raise ReconError('Browser JavaScript source count exceeds policy or the 500-source analysis limit')
            omitted = index.get('omitted', {})
            if not isinstance(omitted, dict) or len(omitted) > 30:
                raise ReconError('Invalid archive omission metadata')
            for key, value in omitted.items():
                if not re.fullmatch(r'[A-Za-z0-9_.-]{1,60}', key):
                    raise ReconError('Invalid archive omission metadata')
                _integer(value, 10**9, 'omission count')
            for field in ('javascript_observations', 'exported_observations'):
                if field in index:
                    _integer(index[field], 10**9, field)
            records, payloads, urls = [], {}, set()
            processing_bytes = 0
            for row in sources:
                if not isinstance(row, dict) or set(row) != {'url', 'method', 'status_code', 'content_type', 'sha256', 'bytes', 'file'}:
                    raise ReconError('Invalid browser JavaScript source record')
                url = _redacted_url(row['url'])
                if not policy.url_in_scope(url):
                    raise ReconError('Browser JavaScript source is outside the current target scope')
                if url in urls:
                    raise ReconError('Duplicate or ambiguous redacted source URL; export versions separately')
                urls.add(url)
                mime = str(row['content_type']).split(';', 1)[0].strip().lower()
                digest = row['sha256']
                if (row['method'] != 'GET' or type(row['status_code']) is not int or row['status_code'] != 200
                        or mime not in JS_TYPES or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                        or row['file'] != digest + '.js' or row['file'] not in names):
                    raise ReconError('Expected indexed GET/200 JavaScript response bodies')
                size = _integer(row['bytes'], policy.limits.max_js_bytes, 'source size')
                if not size:
                    raise ReconError('Empty JavaScript source body')
                processing_bytes += size
                if processing_bytes > MAX_EXPANDED_BYTES:
                    raise ReconError('Browser JavaScript source processing budget exceeded')
                if digest not in payloads:
                    with archive.open(row['file']) as member:
                        data = member.read(policy.limits.max_js_bytes + 1)
                    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                        raise ReconError('Browser JavaScript body size or SHA-256 mismatch')
                    payloads[digest] = data
                elif len(payloads[digest]) != size:
                    raise ReconError('Browser JavaScript body size mismatch')
                records.append({'url': url, 'sha256': digest, 'bytes': size, 'content_type': mime})
            if names != {'index.json'} | {digest + '.js' for digest in payloads}:
                raise ReconError('Unindexed browser JavaScript archive member')
            return {'sha256': hashlib.sha256(raw).hexdigest(), 'sources': records,
                    'payloads': payloads, 'omitted': omitted}
    except ReconError:
        raise
    except (zipfile.BadZipFile, UnicodeError, ValueError, KeyError, RuntimeError, NotImplementedError, zlib.error, EOFError) as exc:
        raise ReconError('Invalid or corrupted browser JavaScript archive') from exc


def _has_imports(db: Database) -> bool:
    return db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='browser_javascript_imports'") is not None


def _ensure_schema(db: Database) -> None:
    db.execute('''CREATE TABLE IF NOT EXISTS browser_javascript_imports (
        import_id TEXT PRIMARY KEY, target TEXT NOT NULL, source_run_id TEXT NOT NULL,
        archive_sha256 TEXT NOT NULL, policy_hash TEXT NOT NULL, context_label TEXT NOT NULL,
        source_count INTEGER NOT NULL, artifact_count INTEGER NOT NULL, byte_count INTEGER NOT NULL,
        analysis_id TEXT NOT NULL, report_json TEXT NOT NULL, report_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(target,source_run_id,archive_sha256,policy_hash,context_label))''')


def list_browser_javascript_imports(db: Database, *, target: str = '', limit: int = 100) -> list[dict[str, Any]]:
    if not _has_imports(db):
        return []
    where, params = (' WHERE target=?', (target,)) if target else ('', ())
    rows = db.all('SELECT import_id,target,source_run_id,context_label,source_count,artifact_count,'
                  'byte_count,analysis_id,created_at FROM browser_javascript_imports' + where +
                  ' ORDER BY created_at DESC,rowid DESC LIMIT ?', params + (max(1, min(int(limit), 100)),))
    return [{**dict(row), 'auth_state': 'unknown', 'provenance': 'local_har',
             'collection_status': 'partial'} for row in rows]


def browser_javascript_report(db: Database, import_id: str) -> dict[str, Any]:
    if not IMPORT_ID.fullmatch(str(import_id)) or not _has_imports(db):
        raise ReconError('Browser JavaScript import not found')
    row = db.one('SELECT report_json,report_sha256 FROM browser_javascript_imports WHERE import_id=?', (import_id,))
    if not row:
        raise ReconError('Browser JavaScript import not found')
    payload = str(row['report_json'])
    if hashlib.sha256(payload.encode()).hexdigest() != row['report_sha256']:
        raise ReconError('Browser JavaScript report integrity mismatch')
    try:
        report = json.loads(payload)
    except ValueError as exc:
        raise ReconError('Browser JavaScript report is invalid') from exc
    if not isinstance(report, dict) or report.get('import_id') != import_id:
        raise ReconError('Browser JavaScript report identity mismatch')
    return report


def _verify_stored_evidence(paths: AppPaths, report: dict[str, Any]) -> None:
    base = paths.state / 'browser-javascript'
    root = base / report['import_id']
    expected_parent = base.resolve()
    try:
        if base.is_symlink() or root.is_symlink() or root.resolve().parent != expected_parent:
            raise ValueError('Invalid evidence root')
        report_file = root / 'report.json'
        if report_file.is_symlink() or report_file.resolve().parent != root.resolve():
            raise ValueError('Invalid report path')
        with report_file.open('rb') as handle:
            if handle.read(MAX_REPORT_BYTES + 2) != json_dumps(report).encode() + b'\n':
                raise ValueError('Report mismatch')
        for source in {row['sha256']: row for row in report['sources']}.values():
            digest = source['sha256']
            body = AppPaths.from_root(root).objects / digest[:2] / digest[2:4] / digest
            if body.is_symlink() or not body.resolve().is_relative_to(root.resolve()):
                raise ValueError('Invalid evidence path')
            with body.open('rb') as handle:
                data = handle.read(source['bytes'] + 1)
            if len(data) != source['bytes'] or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Evidence mismatch')
    except (OSError, ValueError, KeyError) as exc:
        raise ReconError('Stored browser JavaScript evidence is missing or corrupted') from exc


def _source_indicators(url: str, text: str, policy: TargetPolicy):
    values = set()
    for kind, value, redacted in extract_js_indicators(text):
        if kind == 'graphql_operation':
            continue  # Require a declaration, rather than prose such as 'query string'.
        if kind in {'absolute_url', 'endpoint'}:
            try:
                value = _redacted_url(urllib.parse.urljoin(url, value))
            except ReconError:
                continue
            if not policy.url_in_scope(value):
                continue
        values.add((kind, value, redacted))
    # Bundlers encode document newlines as JS escapes. Decode only whitespace
    # escapes for this lexical declaration scan; never evaluate source strings.
    graphql_text = re.sub(r'\\[nrt]', ' ', text)
    values.update(('graphql_operation', f'{kind} {name}', False) for kind, name in GQL.findall(graphql_text))
    for match in MAP.finditer(text):
        try:
            value = _redacted_url(urllib.parse.urljoin(url, match[1].strip('"\'')))
        except ReconError:
            continue
        if policy.url_in_scope(value):
            values.add(('source_map_reference', value, False))
    return sorted(values)


def _analyze(root: Path, policy: TargetPolicy, capture: dict[str, Any]) -> dict[str, Any]:
    from analysis_engine import run_analysis

    paths = AppPaths.from_root(root)
    paths.ensure()
    # No installation headers, tokens, active-module settings or delivery secrets
    # are copied into the isolated analysis workspace.
    atomic_write_text(paths.config, 'I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="no"\nTELEGRAM_ENABLED="no"\n', mode=0o600)
    raw_policy = {'name': policy.name, 'roots': policy.roots, 'include': policy.include,
                  'exclude': policy.exclude, 'modules': {'javascript': True},
                  'limits': {'max_js_bytes': policy.limits.max_js_bytes, 'max_js_files': policy.limits.max_js_files}}
    atomic_write_text(paths.policy, json_dumps({'schema': 3, 'targets': [raw_policy]}), mode=0o600)
    db = Database(paths.db)
    try:
        paths.db.chmod(0o600)
        run_id = db.create_run(policy.name, 1, 'browser_javascript_offline')
        run_dir = paths.output / 'browser-javascript' / 'runs' / run_id
        run_dir.mkdir(parents=True)
        db.create_run_target(run_id, policy, run_dir, baseline=True)
        store = ContentAddressedStore(paths, db)
        indicator_count = 0
        sources = []
        for source in capture['sources']:
            data = capture['payloads'][source['sha256']]
            normalization = normalize_javascript_bytes(data)
            digest, blob, _ = store.put(data, content_type=source['content_type'])
            store.set_reference('browser_javascript', source['url'], digest)
            db.upsert_js(policy.name, source['url'], digest, normalization.fingerprint,
                         str(blob), len(data), run_id)
            db.upsert_url(policy.name, source['url'], 'javascript', 'browser_javascript', run_id)
            indicators = _source_indicators(source['url'], data.decode('utf-8', 'replace'), policy)
            indicator_count += len(indicators)
            if indicator_count > MAX_INDICATORS:
                raise ReconError('Browser JavaScript indicator budget exceeded')
            for kind, value, redacted in indicators:
                db.upsert_js_indicator(policy.name, source['url'], kind, value, redacted, run_id)
                if kind == 'endpoint':
                    db.upsert_endpoint_intelligence(policy.name, value, 'endpoint',
                        classify_endpoint(value), 'browser_javascript_static', run_id)
            sources.append({**source, 'normalization': normalization.mode,
                            'indicator_count': len(indicators)})
        # This is a captured JS subset, never a completed crawl or live baseline.
        db.stage_begin(run_id, policy.name, 'javascript', 1)
        db.stage_finish(run_id, policy.name, 'javascript', 'partial', metrics={
            'downloaded': 0, 'imported': len(sources), 'collection_status': 'partial',
            'collection_reasons': ['browser_javascript_subset'], 'provenance': 'local_har'})
        db.finish_run_target(run_id, policy.name, 'partial')
        db.finish_run(run_id, 'partial')
        analysis = run_analysis(paths, db, run_id, policy.name, mode='browser_javascript_offline')
        analysis_id = analysis['analysis_id']
        candidates = [dict(row) for row in db.all('''SELECT candidate_id,bug_family,title,
            candidate_state,likelihood_score,evidence_strength,priority_score
            FROM bug_candidates WHERE analysis_id=? ORDER BY priority_score DESC,candidate_id''', (analysis_id,))]
        operations = [dict(row) for row in db.all('''SELECT DISTINCT value AS declaration,js_url AS source_url
            FROM js_indicators WHERE kind='graphql_operation' ORDER BY value,js_url''')]
        endpoints = [dict(row) for row in db.all('''SELECT endpoint,primary_category,confidence
            FROM endpoint_intelligence ORDER BY endpoint''')]
        maps = [dict(row) for row in db.all('''SELECT js_url AS source_url,value AS url
            FROM js_indicators WHERE kind='source_map_reference' ORDER BY js_url,value''')]
        flows = [dict(row) for row in db.all('''SELECT js_url AS source_url,source_kind,sink_kind,confidence
            FROM js_dataflows WHERE analysis_id=? ORDER BY js_url,source_kind,sink_kind LIMIT 200''', (analysis_id,))]
        return {'sandbox_run_id': run_id, 'analysis_id': analysis_id, 'analysis_status': 'success',
                'engine_version': analysis['engine_version'], 'sources': sources,
                'indicator_count': indicator_count, 'endpoints': endpoints,
                'graphql_operations': operations,
                'graphql_operation_count': len({r['declaration'] for r in operations}),
                'source_map_references': maps, 'source_maps_fetched': 0,
                'dataflow_preview': flows, 'dataflow_preview_limit': 200,
                'static_intelligence': analysis['static_intelligence'],
                'candidate_count': len(candidates), 'candidates': candidates}
    finally:
        db.close()


def import_browser_javascript(paths: AppPaths, db: Database, *, target: str, run_id: str,
                              file_path: str | Path, context_label: str = 'browser-observed') -> dict[str, Any]:
    if not Config(paths).authorized:
        raise ReconError('Project authorization must be enabled before importing browser JavaScript')
    selected = PolicySet.load(paths).select(target)
    if len(selected) != 1:
        raise ReconError('Browser JavaScript import requires exactly one target')
    policy = selected[0]
    context_label = str(context_label).strip() or 'browser-observed'
    if len(context_label) > 120 or any(ord(c) < 32 or ord(c) == 127 for c in context_label):
        raise ReconError('Invalid browser JavaScript context label')
    source_run = db.one('''SELECT r.status FROM runs r JOIN run_targets rt ON rt.run_id=r.id
        WHERE r.id=? AND rt.target=?''', (run_id, policy.name))
    if not source_run or source_run['status'] not in {'success', 'partial', 'failed', 'interrupted', 'cancelled'}:
        raise ReconError('Select an existing, stopped source run belonging to this target')
    with RunLock(paths.lock, Logger(paths, verbose=False)):
        capture = _read_archive(file_path, policy)
        policy_hash = policy.policy_hash()
        _ensure_schema(db)
        existing = db.one('''SELECT import_id FROM browser_javascript_imports WHERE
            target=? AND source_run_id=? AND archive_sha256=? AND policy_hash=? AND context_label=?''',
            (policy.name, run_id, capture['sha256'], policy_hash, context_label))
        if existing:
            report = browser_javascript_report(db, str(existing['import_id']))
            _verify_stored_evidence(paths, report)
            return {**_summary(report), 'reused': True}
        import_id = 'bjs-' + uuid.uuid4().hex
        base = paths.state / 'browser-javascript'
        if base.is_symlink():
            raise ReconError('Browser JavaScript evidence directory must not be a symlink')
        base.mkdir(mode=0o700, exist_ok=True)
        if base.resolve().parent != paths.state.resolve():
            raise ReconError('Browser JavaScript evidence directory escaped project state')
        base.chmod(0o700)
        root = base / import_id
        root.mkdir(mode=0o700)
        try:
            result = _analyze(root, policy, capture)
            report = {**result, 'import_id': import_id, 'target': policy.name,
                      'source_run_id': run_id, 'source_run_status': source_run['status'],
                      'archive_sha256': capture['sha256'], 'policy_hash': policy_hash,
                      'context_label': context_label, 'auth_state': 'unknown',
                      'provenance': 'local_har', 'coverage_scope': 'browser_javascript_subset',
                      'collection_status': 'partial', 'network_requests': 0,
                      'scan_status_changed': False, 'archive_omissions': capture['omitted'],
                      'artifact_count': len(capture['payloads']),
                      'byte_count': sum(len(data) for data in capture['payloads'].values()),
                      'created_at': utc_now(),
                      'limitations': ['Static review leads require validation; no vulnerability is confirmed.',
                                      'Archive hashes verify local consistency, not server authenticity.',
                                      'Source-map references do not prove map availability.',
                                      'Context labels do not prove authentication.']}
            payload = json_dumps(report)
            if len(payload.encode()) > MAX_REPORT_BYTES:
                raise ReconError('Browser JavaScript report exceeds 16 MiB; import a smaller source subset')
            atomic_write_text(root / 'report.json', payload + '\n', mode=0o600)
            current = PolicySet.load(paths).select(policy.name)
            if (not Config(paths).authorized or len(current) != 1
                    or current[0].policy_hash() != policy_hash):
                raise ReconError('Target authorization or policy changed during browser JavaScript analysis')
            summary = _summary(report)
            with db.transaction():
                db.execute('''INSERT INTO browser_javascript_imports(import_id,target,source_run_id,
                    archive_sha256,policy_hash,context_label,source_count,artifact_count,byte_count,
                    analysis_id,report_json,report_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (import_id, policy.name, run_id, capture['sha256'], policy_hash, context_label,
                     len(report['sources']), report['artifact_count'], report['byte_count'],
                     report['analysis_id'], payload, hashlib.sha256(payload.encode()).hexdigest(), report['created_at']))
                db.audit('browser_javascript_imported', actor='cli', target=policy.name,
                         entity_type='browser_javascript_import', entity_value=import_id,
                         details={'source_run_id': run_id, 'sources': len(report['sources']),
                                  'archive_sha256': capture['sha256'], 'provenance': 'local_har'})
            return {**summary, 'reused': False}
        except BaseException:
            shutil.rmtree(root)
            raise


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    keys = ('import_id', 'target', 'source_run_id', 'source_run_status', 'analysis_id',
            'analysis_status', 'context_label', 'auth_state', 'provenance',
            'collection_status', 'network_requests', 'scan_status_changed', 'artifact_count',
            'byte_count', 'indicator_count', 'graphql_operation_count', 'candidate_count', 'archive_omissions')
    return {**{key: report[key] for key in keys}, 'source_count': len(report['sources']),
            'endpoint_count': len(report['endpoints']),
            'dashboard_path': '/browser-javascript?import_id=' + report['import_id']}
