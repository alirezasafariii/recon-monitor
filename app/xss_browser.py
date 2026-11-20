"""Explicit, bounded browser XSS validation over existing target policies.

Each run uses a fresh browser/context. All HTTP traffic is intercepted and served
through the pinned transport; stored bodies, cookies and credentials are not
exported. No arbitrary JavaScript from a plan is evaluated by the worker.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from core import AppPaths, Config, Database, PolicySet, ReconError, atomic_write_text, utc_now
from family_analyzers.dom_xss import analyze_dom_xss_signal
from family_analyzers.phase2_expansion import PHASE2_ANALYZER_TYPES, analyze_phase2_family
from xss_browser_http import decode_entity, decode_text
from xss_browser_encodings import DEFAULT_ENCODINGS, ENCODINGS, encode, carries, reflected
from xss_browser_probes import PROBE_NAMES, INPUT_SOURCES, CLIENT_ONLY, probes as build_probes, source_script
from safe_transport import build_pinned_opener, resolve_public_addresses

VERSION = '1.2.0'
FAMILIES = {'reflected_xss', 'stored_xss', 'dom_xss'}
LIMIT = 1024 * 1024


def error_kind(exc):
    if isinstance(exc, ReconError):
        return str(exc)
    # Retain only a browser error code, never URLs, payloads or session secrets.
    code = re.search(r'\bnet::(ERR_[A-Z0-9_]+)\b', str(exc))
    return code.group(1) if code else type(exc).__name__


def origin(url):
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        port = p.port if p.port is not None else (443 if p.scheme == 'https' else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        return p.scheme, p.hostname.encode('idna').decode().lower(), port
    except (TypeError, ValueError, UnicodeError):
        raise ReconError('Browser plan requires a valid HTTP(S) URL without embedded credentials') from None


def origin_text(url):
    scheme, host, port = origin(url)
    host = '[' + host + ']' if ':' in host else host
    return scheme + '://' + host + ((':' + str(port)) if port != (443 if scheme == 'https' else 80) else '')


def public_url(url):
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, re.sub(r'RMXSS_[a-f0-9]{32}', '[marker]', p.path),
        urllib.parse.urlencode([(k, '[redacted]') for k, _ in urllib.parse.parse_qsl(p.query)]), ''))


def validate_plan(plan, policy):
    if not isinstance(plan, dict) or set(plan) - {'version', 'target', 'tests', 'max_requests', 'max_seconds'}:
        raise ReconError('Invalid browser plan fields')
    if plan.get('version') != 1 or plan.get('target') != policy.name:
        raise ReconError('Browser plan version/target mismatch')
    tests = plan.get('tests')
    if not isinstance(tests, list) or not tests:
        raise ReconError('Browser plan requires at least one test')
    for test in tests:
        if not isinstance(test, dict) or set(test) - {'id', 'family', 'url', 'input', 'steps', 'cleanup', 'probes', 'settle_ms', 'resource_origins', 'encodings', 'read_session'}:
            raise ReconError('Invalid browser test fields')
        if not isinstance(test.get('id'), str) or not test['id'] or test.get('family') not in FAMILIES:
            raise ReconError('Each test needs an ID and supported XSS family')
        origin(test.get('url', ''))
        if not policy.url_in_scope(test['url']):
            raise ReconError('Browser test URL outside policy')
        resources = test.get('resource_origins', [])
        if not isinstance(resources, list):
            raise ReconError('resource_origins must be a list')
        for resource in resources:
            origin(resource)
            parsed = urllib.parse.urlsplit(resource)
            if parsed.path not in {'', '/'} or parsed.query or parsed.fragment or not policy.url_in_scope(resource):
                raise ReconError('Resource origin must already be authorized by the target scope')
        field = test.get('input', {})
        if not isinstance(field, dict) or set(field) != {'kind', 'name'} or field['kind'] not in INPUT_SOURCES or not isinstance(field['name'], str) or not field['name']:
            raise ReconError('Input requires a supported source kind and name')
        if field['kind'] in CLIENT_ONLY and test['family'] != 'dom_xss':
            raise ReconError('Browser-only sources require the DOM XSS family')
        if test['family'] == 'stored_xss' and field['kind'] != 'form':
            raise ReconError('Stored XSS requires an explicit write/read form workflow')
        reader = test.get('read_session')
        if reader is not None:
            if (test['family'] != 'stored_xss' or not isinstance(reader, dict)
                    or set(reader) - {'url', 'steps', 'storage_state'} or not isinstance(reader.get('url'), str)
                    or (reader.get('storage_state') is not None and not isinstance(reader['storage_state'], str))):
                raise ReconError('read_session requires a Stored read URL and optional session file/steps')
            if origin(reader['url']) != origin(test['url']) or not policy.url_in_scope(reader['url']):
                raise ReconError('Reader URL outside the authorized test origin')
            reader_steps = reader.get('steps', [])
            if not isinstance(reader_steps, list) or any(not isinstance(step, dict) or step.get('action') == 'request'
                    or '{probe}' in json.dumps(step) or '{marker}' in json.dumps(step) for step in reader_steps):
                raise ReconError('Reader steps must be read-only and must not inject the probe')
            validate_plan({'version': 1, 'target': policy.name, 'tests': [{'id': 'reader',
                'family': 'reflected_xss', 'url': reader['url'], 'input': {'kind': 'query', 'name': 'unused'},
                'steps': reader_steps, 'encodings': [[]]}]}, policy)
        encodings = test.get('encodings', DEFAULT_ENCODINGS)
        if not isinstance(encodings, list) or not encodings or any(not isinstance(chain, list) or any(not isinstance(e, str) or e not in ENCODINGS for e in chain) for chain in encodings):
            raise ReconError('encodings must be named transformation chains')
        probes = test.get('probes', list(PROBE_NAMES))
        if not isinstance(probes, list) or not probes or any(p not in PROBE_NAMES for p in probes):
            raise ReconError('Invalid execution probes')
        if type(test.get('settle_ms', 350)) is not int or test.get('settle_ms', 350) < 0:
            raise ReconError('settle_ms must be a nonnegative integer observation wait')
        for stage in ('steps', 'cleanup'):
            steps = test.get(stage, [])
            if not isinstance(steps, list):
                raise ReconError('Browser workflow steps must be a list')
            for step in steps:
                if not isinstance(step, dict) or step.get('action') not in {'goto', 'fill', 'click', 'wait_for', 'request'}:
                    raise ReconError('Unsupported browser workflow action')
                if step['action'] == 'request':
                    if set(step) != {'action', 'url', 'method', 'json'} or step['method'] not in {'POST', 'PUT', 'PATCH', 'DELETE'} or not isinstance(step['json'], dict):
                        raise ReconError('Request step requires an explicit write method and JSON object')
                    if origin(step['url']) != origin(test['url']) or not policy.url_in_scope(step['url']):
                        raise ReconError('API write URL outside test origin or scope')
                    continue
                expected = {'action', 'url'} if step['action'] == 'goto' else {'action', 'selector', 'value'} if step['action'] == 'fill' else {'action', 'selector'}
                if set(step) != expected or any(not isinstance(v, str) or len(v) > 4096 for v in step.values()):
                    raise ReconError('Invalid browser workflow step')
                if step['action'] == 'goto':
                    if origin(step['url']) != origin(test['url']) or not policy.url_in_scope(step['url']):
                        raise ReconError('Workflow navigation must stay in the test origin and scope')
        if field['kind'] == 'form' and not any((s['action'] == 'fill' and '{probe}' in s['value']) or (s['action'] == 'request' and '{probe}' in json.dumps(s['json'])) for s in test.get('steps', [])):
            raise ReconError('Form/API workflows need an explicit value containing {probe}')
    if len({t['id'] for t in tests}) != len(tests):
        raise ReconError('Duplicate test IDs')
    # Legacy max_requests/max_seconds fields are accepted and ignored.
    return plan


class Broker:
    def __init__(self, policy, plan, allowed_origin, allow_write, check, declared_writes=(), resource_origins=()):
        self.policy, self.plan, self.allowed_origin = policy, plan, allowed_origin
        self.allow_write, self.check = allow_write, check
        self.declared_writes = set(declared_writes)
        self.resource_origins = {self.allowed_origin, *(origin(u) for u in resource_origins)}
        self.records, self.documents = [], []
        self.bytes = 0
        self.error = ''
        self.phase = 'probe'
        self.redirects = {}
        self.probe_value = ''
        self.role = 'writer'

    def route(self, route, *, role=None):
        role = role or self.role
        request = route.request
        try:
            self.check()
            url, method = request.url, request.method
            requested_origin = origin(url)
            if (requested_origin not in self.resource_origins or not self.policy.url_in_scope(url)
                    or (request.is_navigation_request() and requested_origin != self.allowed_origin)
                    or (requested_origin != self.allowed_origin and method not in {'GET', 'HEAD', 'OPTIONS'})
                    or (role == 'reader' and method not in {'GET', 'HEAD', 'OPTIONS'})
                    or (method not in {'GET', 'HEAD', 'OPTIONS'} and not (self.allow_write and (method == 'POST' or (method, url) in self.declared_writes)))):
                raise ReconError('outside_scope_or_unapproved_method')
            parsed = urllib.parse.urlsplit(url)
            public, addresses = resolve_public_addresses(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
            if not public or not addresses:
                raise ReconError('non_public_or_missing_dns')
            rid = 'REQ-' + secrets.token_hex(8)
            rec = {'id': rid, 'url': public_url(url), 'method': method, 'phase': self.phase,
                   'probe_sent': carries(url, request.post_data or '', self.probe_value), 'role': role}
            self.records.append(rec)  # Reserve before connecting, including failed requests.
            headers = request.all_headers()
            headers['accept-encoding'] = 'identity'
            headers.pop('content-length', None)
            req = urllib.request.Request(url, data=request.post_data_buffer, headers=headers, method=method)
            try:
                response = build_pinned_opener(addresses[0]).open(req, timeout=8)
            except urllib.error.HTTPError as exc:
                response = exc  # Redirects are returned to Chromium and re-intercepted.
            with response:
                chunks = []
                read = getattr(response, 'read1', response.read)
                while True:
                    self.check()
                    chunk = read(64 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                wire = b''.join(chunks)
                self.bytes += len(wire)
                raw = decode_entity(wire, response.headers.get('Content-Encoding', ''), self.check)
                text, charset = decode_text(raw, response.headers)
                out_headers = {k.lower(): v for k, v in response.headers.items()}
                location = response.headers.get('Location')
                if 300 <= response.code < 400 and location:
                    redirected = urllib.parse.urljoin(url, location)
                    if origin(redirected) not in self.resource_origins or not self.policy.url_in_scope(redirected) or (request.is_navigation_request() and origin(redirected) != self.allowed_origin):
                        raise ReconError('redirect_outside_scope')
                cookies = response.headers.get_all('Set-Cookie')
                if cookies:
                    out_headers['set-cookie'] = '\n'.join(cookies)
                for key in list(out_headers):
                    if key.lower() in {'content-length', 'transfer-encoding', 'content-encoding', 'connection'}:
                        out_headers.pop(key)
                rec.update(status=response.code, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                    wire_sha256=hashlib.sha256(wire).hexdigest(), wire_bytes=len(wire), response_charset=charset)
                if request.is_navigation_request() and request.frame == request.frame.page.main_frame:
                    if 300 <= response.code < 400 and location:
                        if response.code in {307, 308} and method not in {'GET', 'HEAD'}:
                            raise ReconError('redirect_requires_non_get_replay')
                        self.redirects[id(request.frame.page)] = redirected
                    if response.code >= 400:
                        self.error = 'main_document_http_' + str(response.code)
                if request.is_navigation_request() or request.resource_type in {'fetch', 'xhr'}:
                    self.documents.append({'page_id': id(request.frame.page), 'role': role, 'request_id': rid, 'request_url': url, 'response_url': url,
                        'response_text': text, 'response_charset': charset,
                        'content_type': response.headers.get('Content-Type', ''),
                        'csp': response.headers.get('Content-Security-Policy', ''), 'phase': self.phase,
                        'body_has_probe': carries(url, request.post_data or '', self.probe_value)})
                route.fulfill(status=response.code, headers=out_headers, body=raw)
        except Exception as exc:
            self.error = error_kind(exc)
            route.abort()


def _follow_redirects(page, broker, check):
    # Fulfilled Chromium navigations can expose a 3xx as a document. Follow
    # logged same-origin GET/303 destinations explicitly; never replay a POST.
    visited = set()
    while id(page) in broker.redirects:
        check()
        url = broker.redirects.pop(id(page))
        if url in visited:
            raise ReconError('redirect_cycle')
        visited.add(url)
        page.goto(url, wait_until='domcontentloaded')


def _steps(page, steps, probe, marker, check, broker):
    for step in steps:
        check()
        action = step['action']
        if action == 'goto':
            page.goto(step['url'], wait_until='domcontentloaded')
        elif action == 'fill':
            page.locator(step['selector']).fill(step['value'].replace('{probe}', probe).replace('{marker}', marker))
        elif action == 'request':
            body = json.loads(json.dumps(step['json']).replace('{probe}', json.dumps(probe)[1:-1]).replace('{marker}', marker))
            status = page.evaluate('''async ({url, method, body}) => {const r = await fetch(url, {method, credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); return r.status;}''', {'url': step['url'], 'method': step['method'], 'body': body})
            if status >= 400:
                raise ReconError('API workflow HTTP failure')
        elif action == 'click':
            page.locator(step['selector']).click()
        else:
            page.locator(step['selector']).wait_for(state='visible')
        _follow_redirects(page, broker, check)


def execute_test(browser, policy, plan, test, *, verify, allow_write, storage_state=None, check=lambda: None):
    marker = 'RMXSS_' + secrets.token_hex(16)
    capture = 'XB-' + secrets.token_hex(12)
    results, events, executions, controls = [], [], [], []
    writes = [(s['method'], s['url']) for s in test.get('steps', []) + test.get('cleanup', []) if s['action'] == 'request']
    broker = Broker(policy, plan, origin(test['url']), allow_write, check, writes, test.get('resource_origins', []))
    broker.marker = marker
    def sink_event(source, item):
        if not isinstance(item, dict) or item.get('marker') != marker:
            return
        if source['frame'] == source['page'].main_frame or source['frame'].url == 'about:srcdoc':
            events.append({'sink': item['sink'], 'url': public_url(source['page'].url), 'phase': broker.phase})
    def executed(source, token):
        if token != marker:
            return
        frame = source['frame']
        main = source['page'].main_frame
        # Attribute srcdoc execution only to an unsandboxed child of this scoped page.
        srcdoc = frame.url == 'about:srcdoc' and frame.parent_frame == main
        if frame == main and origin(frame.url) == origin(test['url']) or srcdoc:
            executions.append({'phase': broker.phase, 'url': main.url,
                               'frame_kind': 'srcdoc' if srcdoc else 'main', 'page_id': id(source['page'])})
    def control_event(source, item):
        if isinstance(item, dict) and item.get('directive') in {'script-src', 'script-src-elem', 'script-src-attr', 'require-trusted-types-for', 'trusted-types'}:
            controls.append({'phase': broker.phase, 'directive': item['directive'],
                'disposition': 'enforce' if item.get('disposition') == 'enforce' else 'report',
                'marker_related': item.get('marker_related') is True})
    hook = (Path(__file__).with_name('xss_browser_hooks.js')).read_text()
    session_hashes = {}
    def new_context(state, role='writer'):
        snapshot = json.loads(Path(state).read_text()) if isinstance(state, (str, Path)) else state
        state_hash = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
        ctx = browser.new_context(service_workers='block', accept_downloads=False, storage_state=snapshot)
        session_hashes[id(ctx)] = state_hash
        ctx.route('**/*', lambda route: broker.route(route, role=role))
        ctx.route_web_socket('**/*', lambda ws: ws.close())
        ctx.expose_binding('__rmSink', sink_event)
        ctx.expose_binding('__rmXss', executed)
        ctx.expose_binding('__rmControl', control_event)
        ctx.add_init_script('(' + hook + ')(' + json.dumps({'marker': marker, 'allowedOrigin': origin_text(test['url'])}) + ')')
        return ctx
    context = new_context(storage_state)
    page = context.new_page()
    writer_page, reader_context = page, None
    cdp = context.new_cdp_session(page)
    cdp.send('Page.enable')
    source_init = None
    page.set_default_timeout(10000)  # Per-operation stall timeout, not a total runtime quota.
    page.on('dialog', lambda dialog: dialog.dismiss())
    errors = []
    cleanup = 'not_requested'
    try:
        probes = test.get('probes', list(PROBE_NAMES))
        attempts = [(chain, name) for chain in test.get('encodings', DEFAULT_ENCODINGS)
                    for name in (['probe'] + list(probes) if verify else ['probe'])]
        for attempt, (chain, probe_name) in enumerate(attempts):
            if reader_context is not None:
                reader_context.close()
                reader_context = None
            page = writer_page
            broker.role = 'writer'
            check()
            phase = str(attempt) + ':' + ('probe' if probe_name == 'probe' else 'execution:' + probe_name) + ':encoding:' + (','.join(chain) or 'identity')
            broker.phase = phase
            variants = build_probes(marker)
            probe = encode(marker if probe_name == 'probe' else variants[probe_name], chain)
            broker.probe_value = probe
            field = test['input']
            url = test['url']
            if field['kind'] == 'query':
                p = urllib.parse.urlsplit(url)
                query = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True) if k != field['name']]
                url = urllib.parse.urlunsplit(p._replace(query=urllib.parse.urlencode(query + [(field['name'], probe)])))
            elif field['kind'] == 'hash':
                url = urllib.parse.urldefrag(url)[0] + '#' + urllib.parse.quote(probe, safe='')
            if source_init:
                cdp.send('Page.removeScriptToEvaluateOnNewDocument', {'identifier': source_init})
                source_init = None
            if field['kind'] in {'local_storage', 'session_storage', 'window_name'}:
                source_init = cdp.send('Page.addScriptToEvaluateOnNewDocument', {'source': source_script(field['kind'], field['name'], probe)})['identifier']
            page.goto('about:blank')
            page.goto(url, wait_until='domcontentloaded')
            _follow_redirects(page, broker, check)
            if field['kind'] == 'post_message':
                message = probe if field['name'] == '$' else {field['name']: probe}
                target = origin_text(test['url'])
                sender = page.evaluate_handle('''() => {
                  const frame = document.createElement('iframe');
                  frame.setAttribute('sandbox','allow-scripts');
                  document.body.append(frame);
                  return frame;
                }''').as_element()
                sender_frame = sender.content_frame() if sender else None
                if sender_frame is None:
                    raise ReconError('postmessage_source_unavailable')
                sent_from = sender_frame.evaluate('''({message, target}) => {
                  parent.postMessage(message, target); return self.origin;
                }''', {'message': message, 'target': target})
                if sent_from != 'null':
                    raise ReconError('postmessage_source_origin_mismatch')
            _steps(page, test.get('steps', []), probe, marker, check, broker)
            reader = test.get('read_session')
            if reader is not None:
                broker.role = 'reader'
                broker.redirects.clear()
                reader_context = new_context(reader.get('storage_state'), role='reader')
                page = reader_context.new_page()
                page.set_default_timeout(10000)
                page.on('dialog', lambda dialog: dialog.dismiss())
                page.goto(reader['url'], wait_until='domcontentloaded')
                _follow_redirects(page, broker, check)
                _steps(page, reader.get('steps', []), '', '', check, broker)
            observation_end = time.monotonic() + test.get('settle_ms', 350) / 1000
            while time.monotonic() < observation_end:
                check()
                page.wait_for_timeout(min(100, max(0, (observation_end - time.monotonic()) * 1000)))
            check()
            # Snapshot only marker location/contexts; never export the live DOM/body.
            documents = [d for d in broker.documents if d['phase'] == phase and d['page_id'] == id(page) and (marker in d['response_text'] or reflected(d['response_text'], probe))]
            document = documents[-1] if documents else (next((d for d in reversed(broker.documents) if d['phase'] == phase and d['page_id'] == id(page)), {}))
            writes = [r for r in broker.records if r['method'] in {'POST', 'PUT', 'PATCH'} and r['phase'] == phase and r.get('probe_sent')]
            executed_here = any(e['phase'] == phase and e['url'] == page.url and e['page_id'] == id(page) for e in executions)
            if test['family'] == 'dom_xss':
                phase_events = [e for e in events if e['phase'] == phase]
                unattributed = bool(executed_here and not phase_events and field['kind'] in CLIENT_ONLY)
                if unattributed:
                    phase_events = [{'sink': 'browser_execution_callback'}]
                details = {'unsanitized_dom_flow': executed_here, 'dom_runtime_observations': [{'source_kind': INPUT_SOURCES[field['kind']],
                    'sink_kind': e['sink'], 'runtime_dom_sink_reached': True,
                    **({'sanitized': False, 'execution_context_reached': True} if executed_here else {})}
                    for e in phase_events]}
                dedicated = analyze_dom_xss_signal(None, analysis_id=capture, target=policy.name,
                    endpoint=public_url(test['url']), source_kind=INPUT_SOURCES[field['kind']],
                    sink_kind=phase_events[0]['sink'], details=details) if phase_events else None
            else:
                observation = {**document, 'marker': marker, 'input_marker': marker,
                    'input_name': field['name'], 'encoding_chain': chain,
                    'encoded_input_reflected': reflected(document.get('response_text', ''), probe),
                    'request_carried_input': bool(writes or document.get('body_has_probe')),
                    'browser_capture_id': capture,
                    'controlled_test_context': True, 'benign_test_marker': True,
                    'execution_marker': marker, 'execution_url': page.url,
                    test['family'].replace('_xss', '_script_execution_observed'): executed_here}
                if test['family'] == 'stored_xss':
                    observation.update(write_request_id=writes[0]['id'] if writes else '',
                        write_marker=marker, read_request_contains_marker=document.get('body_has_probe', True))
                # The exact request URL is the capture endpoint; findings keep the reviewed plan URL.
                endpoint = document.get('request_url', test['url'])
                dedicated = analyze_phase2_family(analyzer=PHASE2_ANALYZER_TYPES[test['family']](),
                    family=test['family'], endpoint=endpoint, method='GET',
                    details={test['family'] + '_observations': [observation]})
            if dedicated:
                dedicated['summary'] = ('Browser execution observed; family attribution and analyst review remain required.' if executed_here
                                        else 'Bounded browser test did not demonstrate JavaScript execution.')
                if test['family'] == 'dom_xss':
                    for evidence in dedicated['support']:
                        if evidence['type'] in {'dataflow_source', 'dataflow_sink'}:
                            evidence['source'] = 'browser_input' if evidence['type'] == 'dataflow_source' else 'browser_instrumentation'
                            evidence['source_group'] = capture + ':' + evidence['source']
                            evidence['text'] = 'Controlled browser input and instrumented DOM sink observation; no static dataflow is claimed.'
                    dedicated['family_analyzer']['static_source_and_sink_are_one_evidence_root'] = False
                preconditions = []
                if field['kind'] in {'local_storage', 'session_storage', 'window_name'}:
                    preconditions = ['Independently establish that an attacker can set this operator-seeded browser source in the real workflow.']
                    dedicated['missing'] = list(dict.fromkeys(dedicated['missing'] + preconditions))
                    dedicated['direct'] = False
                    dedicated['support'] = [s for s in dedicated['support'] if s['type'] != 'unsanitized_dom_flow']
                    dedicated['variant'] = 'operator_seeded_browser_execution'
                    dedicated['family_analyzer']['confirmation_ready_from_stored_target_evidence'] = False
                    dedicated['family_analyzer']['confirmation_missing'] = preconditions
                dedicated['family_analyzer']['source_control_preconditions'] = preconditions
                dedicated['family_analyzer'].update(active_validation_performed=True, active_request_performed=True,
                    payload_generated=probe_name != 'probe', safe_runtime_marker_only=probe_name == 'probe',
                    state_changing_action_performed=bool(writes), browser_capture_id=capture, exact_sink_attribution=not (test['family'] == 'dom_xss' and unattributed))
            results.append({'phase': phase, 'execution_observed': executed_here, 'analysis': dedicated, 'coverage': {'source': field['kind'], 'probe': probe_name, 'encoding_chain': chain, 'input_sha256': hashlib.sha256(probe.encode()).hexdigest(), 'writer_session_sha256': session_hashes[id(context)], 'reader_session_sha256': session_hashes[id(reader_context)] if reader_context else None, 'read_session': 'separate_read_only' if test.get('read_session') else 'writer', 'settle_ms': test.get('settle_ms', 350), 'observed_controls': [c for c in controls if c['phase'] == phase], 'executing_frames': sorted({e['frame_kind'] for e in executions if e['phase'] == phase})}})
            if executed_here:
                break
    except Exception as exc:
        errors.append(error_kind(exc))
    finally:
        broker.role = 'writer'
        page = writer_page
        broker.redirects.clear()
        try:
            if test.get('cleanup'):
                broker.phase = 'cleanup'
                _steps(page, test['cleanup'], '', marker, check, broker)
                cleanup = 'completed'
        except Exception:
            cleanup = 'failed'
            errors.append('cleanup_failed')
        if reader_context is not None:
            reader_context.close()
        context.close()
    if broker.error:
        errors.append(broker.error)
    execution = any(r['execution_observed'] for r in results)
    return {'capture_id': capture, 'test_id': test['id'], 'family': test['family'],
        'endpoint': public_url(test['url']), 'status': 'incomplete' if errors else 'execution_observed' if execution else 'not_demonstrated',
        'errors': errors, 'cleanup': cleanup, 'phases': results, 'sink_events': events,
        'requests': broker.records, 'confirmed': False,
        'notice': 'A bounded test is not proof of absence. Analyst confirmation remains required.'}


def _run(paths, db, plan, *, analysis_id, allow_active=False, verify=False, allow_write=False,
        storage_state=None, executable=None, headed=False, control=lambda: None):
    if not isinstance(plan, dict):
        raise ReconError('Browser plan must be a JSON object')
    matches = [p for p in PolicySet.load(paths).targets if p.name == plan.get('target')]
    if len(matches) != 1:
        raise ReconError('Browser plan requires an exact configured target')
    policy = matches[0]
    validate_plan(plan, policy)
    if not policy.active_allowed(Config(paths), allow_active):
        raise ReconError('Browser testing requires installation authorization, active enablement, target confirmation and --allow-active')
    if any(t['input']['kind'] == 'form' or t.get('cleanup') or any(s['action'] == 'request' for s in t.get('steps', [])) for t in plan['tests']) and not allow_write:
        raise ReconError('Form workflows/cleanup require explicit --allow-write')
    row = db.one('SELECT source_run_id,status FROM analysis_runs WHERE id=? AND target=?', (analysis_id, policy.name))
    if not row or row[1] != 'success':
        raise ReconError('A completed successful Analysis must belong to the plan target')
    policy_hash = policy.policy_hash()
    def check():
        control()
        current = [p for p in PolicySet.load(paths).targets if p.name == policy.name]
        if len(current) != 1 or current[0].policy_hash() != policy_hash or not current[0].active_allowed(Config(paths), allow_active):
            raise ReconError('Authorization or target policy changed')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ReconError('Install requirements-browser.txt and run python -m playwright install chromium') from None
    mid = 'XSS-' + secrets.token_hex(12)
    report = {'version': VERSION, 'capture_id': mid, 'analysis_id': analysis_id,
        'target': policy.name, 'source_run_id': row[0], 'created_at': utc_now(),
        'plan_sha256': hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(), 'tests': []}
    directory = paths.output / 'xss-browser' / mid
    directory.mkdir(parents=True, mode=0o700)
    path = directory / 'report.json'
    def save():
        atomic_write_text(path, json.dumps(report, indent=2) + '\n', 0o600)
    save()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=not headed, executable_path=executable,
                args=['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
            try:
                report['browser_version'] = browser.version
                report['hook_sha256'] = hashlib.sha256(Path(__file__).with_name('xss_browser_hooks.js').read_bytes()).hexdigest()
                report['probe_module_sha256'] = hashlib.sha256(Path(__file__).with_name('xss_browser_probes.py').read_bytes()).hexdigest()
                report['http_decoder_sha256'] = hashlib.sha256(Path(__file__).with_name('xss_browser_http.py').read_bytes()).hexdigest()
                report['encoding_module_sha256'] = hashlib.sha256(Path(__file__).with_name('xss_browser_encodings.py').read_bytes()).hexdigest()
                report['coverage_profile'] = {'version': VERSION, 'sources': list(INPUT_SOURCES), 'probes': list(PROBE_NAMES), 'default_encodings': DEFAULT_ENCODINGS}
                for test in plan['tests']:
                    check()
                    result = execute_test(browser, policy, plan, test, verify=verify,
                        allow_write=allow_write, storage_state=storage_state, check=check)
                    capture_path = directory / (result['capture_id'] + '.json')
                    atomic_write_text(capture_path, json.dumps(result, indent=2) + '\n', 0o600)
                    result['artifact'] = str(capture_path)
                    report['tests'].append(result)
                    save()
                    # Existing hypothesis/promotion path owns candidates and decisions.
                    import bug_candidates  # Initialize canonical expanded family registries first.
                    from bug_candidates_family21 import _promote_static_family_result
                    for phase in result['phases']:
                        if phase['analysis']:
                            capture_hash = hashlib.sha256(capture_path.read_bytes()).hexdigest()
                            for signal in phase['analysis']['support'] + phase['analysis']['contradict']:
                                signal.update(artifact=str(capture_path), artifact_sha256=capture_hash,
                                    source_tool='xss_browser', parser_name='xss_browser', parser_version=VERSION)
                                if signal['type'] in {'unsanitized_dom_flow', 'reflected_script_execution_observed', 'stored_script_execution_observed'}:
                                    signal['direct'] = True
                            _promote_static_family_result(db, analysis_id=analysis_id, run_id=row[0],
                                target=policy.name, endpoint=result['endpoint'], source_ref=str(capture_path),
                                family=test['family'], dedicated=phase['analysis'], confidence=85)
                    from security_reasoning import _materialize_evidence
                    for candidate in db.all('SELECT * FROM bug_candidates WHERE analysis_id=? AND target=? AND endpoint=? AND bug_family=?',
                                            (analysis_id, policy.name, result['endpoint'], test['family'])):
                        candidate = dict(candidate)
                        _materialize_evidence(db, candidate, json.loads(candidate['supporting_evidence_json']),
                                              json.loads(candidate['contradicting_evidence_json']))
            finally:
                browser.close()
    except (Exception, KeyboardInterrupt) as exc:
        report['error_type'] = type(exc).__name__
    report['status'] = 'incomplete' if report.get('error_type') or len(report['tests']) != len(plan['tests']) or any(t['status'] == 'incomplete' for t in report['tests']) else 'completed'
    save()
    db.audit('xss_browser_finished', actor='browser-worker', target=policy.name,
        entity_type='browser_capture', entity_value=mid, details={'status': report['status'], 'report': str(path)})
    return {'capture_id': mid, 'status': report['status'], 'report': str(path),
            'execution_observed': sum(t['status'] == 'execution_observed' for t in report['tests'])}


def add_parser(subparsers):
    parser = subparsers.add_parser('xss-browser', help='Run explicit scoped Playwright XSS evidence plans')
    parser.add_argument('--plan', required=True)
    parser.add_argument('--analysis', required=True)
    parser.add_argument('--allow-active', action='store_true')
    parser.add_argument('--allow-write', action='store_true')
    parser.add_argument('--verify-execution', action='store_true')
    parser.add_argument('--storage-state')
    parser.add_argument('--chromium')
    parser.add_argument('--headed', action='store_true')


def cli(paths, args):
    plan = read_plan(Path(args.plan))
    db = Database(paths.db)
    try:
        return run(paths, db, plan, analysis_id=args.analysis, allow_active=args.allow_active,
            allow_write=args.allow_write, verify=args.verify_execution, storage_state=args.storage_state,
            executable=args.chromium, headed=args.headed)
    finally:
        db.close()


def read_plan(source):
    try:
        with Path(source).open('rb') as handle:
            raw = handle.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ReconError('Browser plan exceeds 1 MiB')
        return json.loads(raw)
    except (OSError, ValueError) as exc:
        raise ReconError('Cannot read browser plan JSON') from None


def run(paths, db, plan, **options):
    target = str(plan.get('target', '')) if isinstance(plan, dict) else ''
    lock_path = paths.state / ('xss-browser-' + hashlib.sha256(target.encode()).hexdigest()[:24] + '.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReconError('Another browser capture is running for this target') from None
        return _run(paths, db, plan, **options)
    finally:
        os.close(fd)
