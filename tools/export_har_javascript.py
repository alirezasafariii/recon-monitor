#!/usr/bin/env python3
"""Export scoped JavaScript response bodies from a local HAR, without replay."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import tempfile
import urllib.parse
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))

from core import AppPaths, Config, PolicySet, ReconError  # noqa: E402

MAX_HAR_BYTES = 128 * 1024 * 1024
JAVASCRIPT_TYPES = {
    'application/javascript', 'text/javascript', 'application/ecmascript',
    'text/ecmascript', 'application/x-javascript',
}


def export_javascript(paths: AppPaths, har_path: Path, target: str, output: Path) -> dict[str, Any]:
    """Export bytes and redacted source references; never mutate the run database."""
    if not Config(paths).authorized:
        raise ReconError('Project authorization must be confirmed in config.env')
    selected = PolicySet.load(paths).select(target)
    if len(selected) != 1:
        raise ReconError('Target selector must match exactly one policy')
    policy = selected[0]
    source = har_path.expanduser().resolve()
    output = output.expanduser().absolute()
    if source == output.resolve() or output.is_symlink():
        raise ReconError('Output must be separate from the HAR and must not be a symlink')
    if source.stat().st_size > MAX_HAR_BYTES:
        raise ReconError('HAR exceeds the 128 MiB input limit')
    payload = json.loads(source.read_text(encoding='utf-8-sig'))
    log = payload.get('log') if isinstance(payload, dict) else None
    entries = log.get('entries') if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise ReconError('Expected a HAR object containing log.entries[]')

    artifacts: dict[str, bytes] = {}
    records: dict[tuple[str, str], dict[str, Any]] = {}
    omitted: Counter[str] = Counter()
    candidates = 0
    exported_observations = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request, response = entry.get('request'), entry.get('response')
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        content = response.get('content')
        if not isinstance(content, dict):
            continue
        mime = str(content.get('mimeType') or '').split(';', 1)[0].strip().lower()
        if mime not in JAVASCRIPT_TYPES:
            continue
        url = str(request.get('url') or '')
        try:
            parsed = urllib.parse.urlsplit(url)
            allowed = (parsed.scheme in {'http', 'https'} and parsed.hostname
                       and parsed.username is None and parsed.password is None
                       and policy.url_in_scope(url))
        except ValueError:
            allowed = False
        if not allowed:
            omitted['outside_scope_or_invalid_url'] += 1
            continue
        if str(request.get('method') or '').upper() != 'GET':
            omitted['non_get'] += 1
            continue
        candidates += 1
        if response.get('status') != 200:
            omitted['non_200'] += 1
            continue
        text = content.get('text')
        if not isinstance(text, str) or not text:
            omitted['missing_body'] += 1
            continue
        encoding = str(content.get('encoding') or '').lower()
        if encoding not in {'', 'base64'}:
            omitted['unsupported_encoding'] += 1
            continue
        if len(text) > policy.limits.max_js_bytes * 4:
            omitted['body_limit'] += 1
            continue
        try:
            data = base64.b64decode(text, validate=True) if encoding == 'base64' else text.encode('utf-8')
        except (ValueError, UnicodeError, binascii.Error):
            omitted['invalid_encoding'] += 1
            continue
        if not data or len(data) > policy.limits.max_js_bytes:
            omitted['body_limit'] += 1
            continue
        redacted_url = urllib.parse.urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path,
            urllib.parse.urlencode([(key, '[redacted]') for key, _ in
                                    urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]), '',
        ))
        digest = hashlib.sha256(data).hexdigest()
        key = (redacted_url, digest)
        if key not in records and len(records) >= policy.limits.max_js_files:
            omitted['file_limit'] += 1
            continue
        artifacts[digest] = data
        records[key] = {'url': redacted_url, 'method': 'GET', 'status_code': 200,
                        'content_type': mime, 'sha256': digest, 'bytes': len(data),
                        'file': f'{digest}.js'}
        exported_observations += 1

    if not records:
        raise ReconError('No in-scope GET/200 JavaScript bodies found; export HAR with response content')
    index = {'format': 'recon-browser-javascript-v1', 'target': policy.name,
             'provenance': 'local_har', 'javascript_observations': candidates,
             'exported_observations': exported_observations,
             'sources': list(records.values()), 'omitted': dict(omitted)}
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.har-js-', delete=False) as handle:
            temporary = Path(handle.name)
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for digest, data in sorted(artifacts.items()):
                archive.writestr(f'{digest}.js', data)
            archive.writestr('index.json', json.dumps(index, ensure_ascii=False, indent=2))
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {'archive': str(output), 'sources': len(records), 'artifacts': len(artifacts),
            'javascript_observations': candidates, 'exported_observations': exported_observations,
            'omitted': dict(omitted), 'bytes': output.stat().st_size,
            'scan_status_changed': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--har', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        result = export_javascript(AppPaths.from_root(args.root), args.har, args.target, args.output)
    except (ReconError, OSError, ValueError) as exc:
        parser.exit(1, f'[ERROR] {exc}\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
