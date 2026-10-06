"""Optional local text search in referenced JS resources and run outputs."""
from __future__ import annotations

import codecs
import os
import stat
import urllib.parse
from pathlib import Path
from typing import Any

from core import AppPaths, Database

TEXT_OUTPUT_SUFFIXES = {'.log', '.txt', '.json', '.jsonl', '.csv', '.tsv', '.js', '.map', '.xml'}


def _safe_file(path: Path, roots: tuple[Path, ...]) -> Path | None:
    try:
        resolved = path.resolve(strict=True)
        root = next((r.resolve() for r in roots if resolved.is_relative_to(r.resolve())), None)
        if root is None or not resolved.is_file(): return None
        # Never follow links from a database reference or a run directory.
        current = path.absolute()
        while current != current.parent:
            if current.is_symlink(): return None
            current = current.parent
        return resolved
    except (OSError, ValueError):
        return None


def contains_text(path: Path, query: str) -> bool:
    """Read the whole file in bounded chunks, including cross-chunk matches."""
    needle = query.casefold()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode): return False
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            tail = ''
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return needle in (tail + decoder.decode(b'', final=True)).casefold()
                if b'\0' in chunk: return False
                text = tail + decoder.decode(chunk).casefold()
                if needle in text: return True
                tail = text[-max(0, len(needle)-1):] if len(needle) > 1 else ''
    finally:
        os.close(descriptor)


def search_artifact_text(db: Database, paths: AppPaths, query: str, *, target: str = '',
                         run_id: str = '', since: str = '', record: str = '') -> tuple[list[dict[str, Any]], int]:
    roots = (paths.blobs, paths.objects, paths.output, paths.logs)
    rows: list[dict[str, Any]] = []
    unavailable = 0
    visited: set[tuple[str, str, str]] = set()

    def inspect(path: Path, value: str, scope: str, source: str, seen: str, extra: str) -> None:
        nonlocal unavailable
        key = (str(path), scope, source)
        if key in visited or (record and value != record) or (since and seen < since): return
        visited.add(key)
        safe = _safe_file(path, roots)
        if safe is None:
            unavailable += 1
            return
        try:
            matched = query == '*' or contains_text(safe, query)
        except OSError:
            unavailable += 1
            return
        if matched:
            href = '/run-review?' + urllib.parse.urlencode({'id': source}) if source else '/recon?' + urllib.parse.urlencode({'view': 'raw', 'raw': 'javascript', 'target': scope, 'q': value})
            rows.append({'target': scope, 'value': value, 'extra': extra + ' · ' + str(path.relative_to(paths.root)) if path.is_relative_to(paths.root) else extra,
                         'seen': seen, 'source_run_id': source, 'analysis_id': '', 'record_key': str(path), 'href': href, 'workspace': '/javascript'})

    where = ["COALESCE(blob_path,'')<>''"]
    args: list[str] = []
    if target: where.append('target=?'); args.append(target)
    if run_id: where.append('last_run_id=?'); args.append(run_id)
    for row in db.all("SELECT target,url,blob_path,last_seen,last_run_id FROM js_files WHERE " + ' AND '.join(where), args):
        path = Path(str(row['blob_path']))
        if not path.is_absolute(): path = paths.root / path
        inspect(path, str(row['url']), str(row['target']), str(row['last_run_id'] or ''), str(row['last_seen']), 'Stored JavaScript text')

    clauses: list[str] = []
    args = []
    if target: clauses.append('target=?'); args.append(target)
    if run_id: clauses.append('run_id=?'); args.append(run_id)
    run_roots = db.all('SELECT run_id,target,run_dir,finished_at,started_at FROM run_targets' + (' WHERE ' + ' AND '.join(clauses) if clauses else ''), args)
    for row in run_roots:
        directory = Path(str(row['run_dir'] or ''))
        try:
            if not directory.resolve().is_relative_to(paths.output.resolve()) or directory.is_symlink(): continue
        except (OSError, ValueError): continue
        if not directory.is_dir(): continue
        for current, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
            for name in sorted(files):
                path = Path(current) / name
                if path.suffix.lower() not in TEXT_OUTPUT_SUFFIXES: continue
                inspect(path, str(path.relative_to(paths.root)), str(row['target']), str(row['run_id']), str(row['finished_at'] or row['started_at'] or ''), 'Stored run output')
    rows.sort(key=lambda row: (row['seen'], row['record_key']), reverse=True)
    return rows, unavailable
