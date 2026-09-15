"""Immutable raw inputs for analysis and replay.

TEMP tables shadow only collection inputs on this connection. Analysis outputs
continue to go to the live database. No historical scan is reconstructed from
mutable inventory when its original snapshot is unavailable.
"""

import contextlib
import hashlib
import json
from pathlib import Path

from core import ReconError, json_dumps, utc_now

INPUT_TABLES = (
    'assets', 'dns_records', 'urls', 'fingerprints', 'ports', 'findings',
    'endpoint_intelligence', 'endpoint_validations', 'js_files', 'js_indicators',
    'technology_observations', 'alerts', 'change_incidents', 'incident_events',
    'run_targets',
)


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@contextlib.contextmanager
def _capture_transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
    except BaseException:
        db.execute('ROLLBACK')
        raise
    else:
        db.execute('COMMIT')


def _freeze_blob(paths, value):
    if not value:
        return value
    source = Path(value)
    if not source.is_file():
        raise ReconError(f'Analysis input artifact is missing: {source.name}')
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    directory = paths.state / 'analysis-input-blobs'
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / digest
    if destination.exists():
        if destination.read_bytes() != data:
            raise ReconError('Analysis input artifact integrity mismatch')
    else:
        with destination.open('xb') as output:
            output.write(data)
    return str(destination)


@contextlib.contextmanager
def analysis_inputs(paths, db, run_id, target, *, replay=False):
    scope = target or '*'
    with db._lock:
        db.execute('''CREATE TABLE IF NOT EXISTS analysis_input_snapshots (
            run_id TEXT NOT NULL, scope TEXT NOT NULL, payload_json TEXT NOT NULL,
            integrity_hash TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY(run_id,scope))''')
        stored = db.one('SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope=?', (run_id, scope))
        if stored is None and not target:
            parts = db.all('SELECT * FROM analysis_input_snapshots WHERE run_id=? AND scope<>?', (run_id, '*'))
            expected = {row[0] for row in db.all('SELECT target FROM run_targets WHERE run_id=?', (run_id,))}
            scopes = {row['scope'] for row in parts}
            if parts and (not expected or expected <= scopes):
                merged = {}
                for part in parts:
                    if _digest(part['payload_json']) != part['integrity_hash']:
                        raise ReconError('Analysis input snapshot integrity mismatch')
                    for table, rows in json.loads(part['payload_json']).items():
                        bucket = merged.setdefault(table, {})
                        for row in rows:
                            bucket[json_dumps(row)] = row
                payload = json_dumps({table: list(rows.values()) for table, rows in merged.items()})
                stored = {'payload_json': payload, 'integrity_hash': _digest(payload)}
                db.execute('INSERT INTO analysis_input_snapshots VALUES(?,?,?,?,?)',
                           (run_id, scope, payload, _digest(payload), utc_now()))
        if stored:
            payload = str(stored['payload_json'])
            if _digest(payload) != stored['integrity_hash']:
                raise ReconError('Analysis input snapshot integrity mismatch')
            snapshot = json.loads(payload)
        else:
            if replay:
                raise ReconError('This historical run has no immutable analysis snapshot; run a fresh scan.')
            # A first analysis is safe only while this is still the latest run
            # for every selected target. Do not label a later inventory as old.
            later = db.one('''SELECT 1 FROM run_targets old JOIN run_targets newer
                ON newer.target=old.target AND newer.run_id<>old.run_id
                AND (newer.started_at>old.started_at OR
                     (newer.started_at=old.started_at AND newer.rowid>old.rowid))
                WHERE old.run_id=? AND (?='*' OR old.target=?) LIMIT 1''', (run_id, scope, scope))
            if later:
                raise ReconError('Historical analysis inputs were not preserved; run a fresh scan.')
            snapshot = {}
            with _capture_transaction(db):
                for table in INPUT_TABLES:
                    columns = [row['name'] for row in db.all(f'PRAGMA main.table_info("{table}")')]
                    if not columns:
                        continue
                    sql = f'SELECT * FROM main."{table}"'
                    params = ()
                    if target and 'target' in columns:
                        sql += ' WHERE target=?'
                        params = (target,)
                    records = []
                    cursor = db.execute(sql, params)
                    while True:
                        page = cursor.fetchmany(500)
                        if not page:
                            break
                        for raw in page:
                            row = dict(raw)
                            if table == 'js_files':
                                row['blob_path'] = _freeze_blob(paths, row.get('blob_path'))
                            records.append(row)
                    snapshot[table] = records
                payload = json_dumps(snapshot)
                db.execute('INSERT INTO analysis_input_snapshots VALUES(?,?,?,?,?)',
                           (run_id, scope, payload, _digest(payload), utc_now()))
        installed = []
        try:
            for table, rows in snapshot.items():
                if table not in INPUT_TABLES:
                    raise ReconError('Unsupported analysis snapshot table')
                if db.one('SELECT 1 FROM sqlite_temp_master WHERE name=?', (table,)):
                    raise ReconError('Nested analysis input contexts are not supported')
                db.execute(f'CREATE TEMP TABLE "{table}" AS SELECT * FROM main."{table}" WHERE 0')
                installed.append(table)
                for row in rows:
                    if table == 'js_files' and row.get('blob_path'):
                        blob = Path(row['blob_path'])
                        if not blob.is_file() or hashlib.sha256(blob.read_bytes()).hexdigest() != blob.name:
                            raise ReconError('Analysis input artifact integrity mismatch')
                    columns = list(row)
                    names = ','.join('"' + name.replace('"', '""') + '"' for name in columns)
                    placeholders = ','.join('?' for _ in columns)
                    db.execute(f'INSERT INTO temp."{table}" ({names}) VALUES ({placeholders})', tuple(row.values()))
                columns = {row['name'] for row in db.all(f'PRAGMA temp.table_info("{table}")')}
                for column in ('target', 'last_run_id', 'id', 'endpoint', 'url', 'js_url', 'incident_id'):
                    if column in columns:
                        db.execute(f'CREATE INDEX temp."snapshot_{table}_{column}" ON "{table}" ("{column}")')
            yield {'scope': scope, 'integrity_hash': _digest(payload), 'tables': len(snapshot)}
        finally:
            for table in reversed(installed):
                db.execute(f'DROP TABLE temp."{table}"')
