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
from safe_transport import build_pinned_opener, resolve_public_addresses

VERSION = '1.0.0'
FAMILIES = {'reflected_xss', 'stored_xss', 'dom_xss'}
LIMIT = 1024 * 1024


def origin(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
        raise ReconError('Browser plan requires HTTP(S) URLs without embedded credentials')
    return p.scheme, p.hostname, p.port or (443 if p.scheme == 'https' else 80)


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
    if not isinstance(tests, list) or not 1 <= len(tests) <= 30:
        raise ReconError('Browser plan requires 1–30 tests')
    for test in tests:
        if not isinstance(test, dict) or set(test) - {'id', 'family', 'url', 'input', 'steps', 'cleanup', 'probes'}:
            raise ReconError('Invalid browser test fields')
        if not isinstance(test.get('id'), str) or not test['id'] or test.get('family') not in FAMILIES:
            raise ReconError('Each test needs an ID and supported XSS family')
        origin(test.get('url', ''))
        if not policy.url_in_scope(test['url']):
            raise ReconError('Browser test URL outside policy')
        field = test.get('input', {})
        if not isinstance(field, dict) or set(field) != {'kind', 'name'} or field['kind'] not in {'query', 'hash', 'form'} or not isinstance(field['name'], str) or not field['name']:
            raise ReconError('Input requires kind=query/hash/form and name')
        if test['family'] == 'stored_xss' and field['kind'] != 'form':
            raise ReconError('Stored XSS requires an explicit write/read form workflow')
        probes = test.get('probes', ['html', 'attribute', 'js_single', 'js_double', 'js_expression'])
        if not isinstance(probes, list) or not probes or len(probes) > 5 or any(p not in {'html', 'attribute', 'js_single', 'js_double', 'js_expression'} for p in probes):
            raise ReconError('Invalid bounded execution probes')
        for stage in ('steps', 'cleanup'):
            steps = test.get(stage, [])
            if not isinstance(steps, list) or len(steps) > 30:
                raise ReconError('Too many browser workflow steps')
            for step in steps:
                if not isinstance(step, dict) or step.get('action') not in {'goto', 'fill', 'click', 'wait_for'}:
                    raise ReconError('Only goto/fill/click/wait_for steps are supported')
                expected = {'action', 'url'} if step['action'] == 'goto' else {'action', 'selector', 'value'} if step['action'] == 'fill' else {'action', 'selector'}
                if set(step) != expected or any(not isinstance(v, str) or len(v) > 4096 for v in step.values()):
                    raise ReconError('Invalid browser workflow step')
                if step['action'] == 'goto':
                    if origin(step['url']) != origin(test['url']) or not policy.url_in_scope(step['url']):
                        raise ReconError('Workflow navigation must stay in the test origin and scope')
        if field['kind'] == 'form' and not any(s['action'] == 'fill' and '{probe}' in s['value'] for s in test.get('steps', [])):
            raise ReconError('Form workflows need an explicit fill value containing {probe}')
    if len({t['id'] for t in tests}) != len(tests):
        raise ReconError('Duplicate test IDs')
    for key, default, maximum in [('max_requests', 100, 1000), ('max_seconds', 120, 900)]:
        value = plan.get(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ReconError('Invalid browser budget')
    return plan


class Broker:
    def __init__(self, policy, plan, allowed_origin, allow_write, check):
        self.policy, self.plan, self.allowed_origin = policy, plan, allowed_origin
        self.allow_write, self.check = allow_write, check
        self.records, self.documents = [], []
        self.bytes = 0
        self.started = time.monotonic()
        self.error = ''
        self.phase = 'probe'
        self.redirect = None

    def route(self, route):
        request = route.request
        try:
            self.check()
            url, method = request.url, request.method
            if (origin(url) != self.allowed_origin or not self.policy.url_in_scope(url)
                    or method not in ({'GET', 'HEAD', 'OPTIONS', 'POST'} if self.allow_write else {'GET', 'HEAD', 'OPTIONS'})):
                raise ReconError('outside_scope_or_unapproved_method')
            if len(self.records) >= min(self.plan.get('max_requests', 100), self.policy.limits.max_http_requests):
                raise ReconError('request_budget_exhausted')
            remaining = self.plan.get('max_seconds', 120) - (time.monotonic() - self.started)
            if remaining <= 0:
                raise ReconError('runtime_budget_exhausted')
            parsed = urllib.parse.urlsplit(url)
            public, addresses = resolve_public_addresses(parsed.hostname, parsed.port or self.allowed_origin[2])
            if not public or not addresses:
                raise ReconError('non_public_or_missing_dns')
            rid = 'REQ-' + secrets.token_hex(8)
            rec = {'id': rid, 'url': public_url(url), 'method': method, 'phase': self.phase}
            self.records.append(rec)  # Reserve before connecting, including failed requests.
            headers = request.all_headers()
            headers.pop('accept-encoding', None)
            headers.pop('content-length', None)
            req = urllib.request.Request(url, data=request.post_data_buffer, headers=headers, method=method)
            try:
                response = build_pinned_opener(addresses[0]).open(req, timeout=min(8, remaining))
            except urllib.error.HTTPError as exc:
                response = exc  # Redirects are returned to Chromium and re-intercepted.
            with response:
                raw = response.read(LIMIT + 1)
                self.bytes += len(raw)
                if len(raw) > LIMIT or self.bytes > min(self.plan.get('_max_bytes', 16 * LIMIT), self.policy.limits.max_download_mb * LIMIT):
                    raise ReconError('response_byte_budget_exhausted')
                out_headers = {k.lower(): v for k, v in response.headers.items()}
                location = response.headers.get('Location')
                if 300 <= response.code < 400 and location:
                    redirected = urllib.parse.urljoin(url, location)
                    if origin(redirected) != self.allowed_origin or not self.policy.url_in_scope(redirected):
                        raise ReconError('redirect_outside_scope')
                cookies = response.headers.get_all('Set-Cookie')
                if cookies:
                    out_headers['set-cookie'] = '\n'.join(cookies)
                for key in list(out_headers):
                    if key.lower() in {'content-length', 'transfer-encoding', 'content-encoding', 'connection'}:
                        out_headers.pop(key)
                rec.update(status=response.code, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
                if request.is_navigation_request() and request.frame == request.frame.page.main_frame:
                    if 300 <= response.code < 400 and location:
                        if response.code in {307, 308} and method not in {'GET', 'HEAD'}:
                            raise ReconError('redirect_requires_non_get_replay')
                        self.redirect = redirected
                    if response.code >= 400:
                        self.error = 'main_document_http_' + str(response.code)
                    self.documents.append({'request_id': rid, 'request_url': url, 'response_url': url,
                        'response_text': raw.decode('utf-8', errors='replace'),
                        'content_type': response.headers.get('Content-Type', ''),
                        'csp': response.headers.get('Content-Security-Policy', ''),
                        'body_has_probe': self.marker in (request.post_data or '') or self.marker in url})
                route.fulfill(status=response.code, headers=out_headers, body=raw)
        except Exception as exc:
            self.error = str(exc) if isinstance(exc, ReconError) else type(exc).__name__
            route.abort()


def _follow_redirects(page, broker, check):
    # Fulfilled Chromium navigations can expose a 3xx as a document. Follow
    # logged same-origin GET/303 destinations explicitly; never replay a POST.
    for _ in range(8):
        if not broker.redirect:
            return
        check()
        url, broker.redirect = broker.redirect, None
        page.goto(url, wait_until='domcontentloaded')
    if broker.redirect:
        raise ReconError('redirect_limit_exhausted')


def _steps(page, steps, probe, marker, check, broker):
    for step in steps:
        check()
        action = step['action']
        if action == 'goto':
            page.goto(step['url'], wait_until='domcontentloaded')
        elif action == 'fill':
            page.locator(step['selector']).fill(step['value'].replace('{probe}', probe).replace('{marker}', marker))
        elif action == 'click':
            page.locator(step['selector']).click()
        else:
            page.locator(step['selector']).wait_for(state='visible')
        _follow_redirects(page, broker, check)


def execute_test(browser, policy, plan, test, *, verify, allow_write, storage_state=None, check=lambda: None):
    marker = 'RMXSS_' + secrets.token_hex(16)
    capture = 'XB-' + secrets.token_hex(12)
    results, events, executions = [], [], []
    broker = Broker(policy, plan, origin(test['url']), allow_write, check)
    broker.marker = marker
    context = browser.new_context(service_workers='block', accept_downloads=False, storage_state=storage_state)
    context.route('**/*', broker.route)
    context.route_web_socket('**/*', lambda ws: ws.close())
    context.expose_binding('__rmSink', lambda source, item: events.append({'sink': item['sink'],
        'url': public_url(source['frame'].url), 'phase': broker.phase})
        if isinstance(item, dict) and item.get('marker') == marker and len(events) < 100 else None)
    def executed(source, token):
        if token == marker and origin(source['frame'].url) == origin(test['url']) and len(executions) < 20:
            executions.append({'phase': broker.phase, 'url': source['frame'].url})
    context.expose_binding('__rmXss', executed)
    hook = (Path(__file__).with_name('xss_browser_hooks.js')).read_text()
    context.add_init_script('(' + hook + ')(' + json.dumps({'marker': marker}) + ')')
    page = context.new_page()
    page.set_default_timeout(min(plan.get('max_seconds', 120) * 1000, 10000))
    page.on('dialog', lambda dialog: dialog.dismiss())
    errors = []
    cleanup = 'not_requested'
    try:
        probes = test.get('probes', ['html', 'attribute', 'js_single', 'js_double', 'js_expression'])
        for phase in (['probe'] + ['execution:' + p for p in probes] if verify else ['probe']):
            check()
            broker.phase = phase
            callback = 'window.__rmXss(' + json.dumps(marker) + ')'
            html_probe = f"""<img src="/.__recon_xss_missing_{marker}" onerror='{callback}'>"""
            variants = {'html': html_probe, 'attribute': '\'">' + html_probe,
                        'js_single': "';" + callback + '//', 'js_double': '\";' + callback + '//',
                        'js_expression': callback}
            probe = marker if phase == 'probe' else variants[phase.split(':', 1)[1]]
            field = test['input']
            url = test['url']
            if field['kind'] == 'query':
                p = urllib.parse.urlsplit(url)
                query = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True) if k != field['name']]
                url = urllib.parse.urlunsplit(p._replace(query=urllib.parse.urlencode(query + [(field['name'], probe)])))
            elif field['kind'] == 'hash':
                url = urllib.parse.urldefrag(url)[0] + '#' + urllib.parse.quote(probe, safe='')
            page.goto('about:blank')
            page.goto(url, wait_until='domcontentloaded')
            _follow_redirects(page, broker, check)
            _steps(page, test.get('steps', []), probe, marker, check, broker)
            page.wait_for_timeout(350)
            # Snapshot only marker location/contexts; never export the live DOM/body.
            documents = [d for d in broker.documents if marker in d['response_text']]
            document = documents[-1] if documents else (broker.documents[-1] if broker.documents else {})
            writes = [r for r in broker.records if r['method'] == 'POST' and r['phase'] == phase]
            executed_here = any(e['phase'] == phase and e['url'] == page.url for e in executions)
            if test['family'] == 'dom_xss':
                phase_events = [e for e in events if e['phase'] == phase]
                details = {'dom_runtime_observations': [{'source_kind': 'location_hash' if field['kind'] == 'hash' else 'urlsearchparams' if field['kind'] == 'query' else 'input_value',
                    'sink_kind': e['sink'], 'runtime_dom_sink_reached': True,
                    **({'sanitized': False, 'execution_context_reached': True} if executed_here else {})}
                    for e in phase_events]}
                dedicated = analyze_dom_xss_signal(None, analysis_id=capture, target=policy.name,
                    endpoint=public_url(test['url']), source_kind='location_hash' if field['kind'] == 'hash' else 'urlsearchparams' if field['kind'] == 'query' else 'input_value',
                    sink_kind=phase_events[0]['sink'] if phase_events else 'innerhtml', details=details)
            else:
                observation = {**document, 'marker': marker, 'input_marker': marker,
                    'input_name': field['name'], 'browser_capture_id': capture,
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
                dedicated['family_analyzer'].update(active_validation_performed=True, active_request_performed=True,
                    payload_generated=phase != 'probe', safe_runtime_marker_only=phase == 'probe',
                    state_changing_action_performed=bool(writes), browser_capture_id=capture)
            results.append({'phase': phase, 'execution_observed': executed_here, 'analysis': dedicated})
            if executed_here:
                break
    except Exception as exc:
        errors.append(str(exc) if isinstance(exc, ReconError) else type(exc).__name__)
    finally:
        try:
            if test.get('cleanup'):
                broker.phase = 'cleanup'
                _steps(page, test['cleanup'], '', marker, check, broker)
                cleanup = 'completed'
        except Exception:
            cleanup = 'failed'
            errors.append('cleanup_failed')
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
    if any(t['input']['kind'] == 'form' or t.get('cleanup') for t in plan['tests']) and not allow_write:
        raise ReconError('Form workflows/cleanup require explicit --allow-write')
    row = db.one('SELECT source_run_id,status FROM analysis_runs WHERE id=? AND target=?', (analysis_id, policy.name))
    if not row or row[1] != 'success':
        raise ReconError('A completed successful Analysis must belong to the plan target')
    policy_hash = policy.policy_hash()
    deadline = time.monotonic() + plan.get('max_seconds', 120)
    def check():
        control()
        if time.monotonic() >= deadline:
            raise ReconError('runtime_budget_exhausted')
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
                remaining_requests = min(plan.get('max_requests', 100), policy.limits.max_http_requests)
                remaining_bytes = min(16 * LIMIT, policy.limits.max_download_mb * LIMIT)
                for test in plan['tests']:
                    check()
                    if remaining_requests <= 0 or remaining_bytes <= 0:
                        report['budget_exhausted'] = True
                        break
                    bounded = {**plan, 'max_requests': remaining_requests, '_max_bytes': remaining_bytes}
                    result = execute_test(browser, policy, bounded, test, verify=verify,
                        allow_write=allow_write, storage_state=storage_state, check=check)
                    remaining_requests -= len(result['requests'])
                    remaining_bytes -= sum(r.get('bytes', 0) for r in result['requests'])
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
    report['status'] = 'incomplete' if report.get('error_type') or report.get('budget_exhausted') or len(report['tests']) != len(plan['tests']) or any(t['status'] == 'incomplete' for t in report['tests']) else 'completed'
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
