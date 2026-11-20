"""Chromium request-stage interception, including native redirect follow-ups.

The browser never connects to a target itself. A local rejecting proxy is the
fallback for requests from an unattached target; intercepted requests are served
by the policy-aware pinned Broker instead.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socketserver
import threading
import time
from types import SimpleNamespace


class RejectingProxy:
    def __init__(self, blocked):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    # Chromium may preconnect to its proxy without sending a
                    # request. An idle TCP connection is not missed evidence.
                    self.request.settimeout(1)
                    first = self.request.recv(1)
                    if not first:
                        return
                    blocked()
                    self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:
                    pass
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
        self.server = Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()
        self.settings = {'server': 'http://127.0.0.1:' + str(self.server.server_address[1]), 'bypass': '<-loopback>'}

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class _Route:
    def __init__(self, transport, event):
        self.transport, self.event = transport, event
        self.capture_id = ''
        raw = event['request']
        self.chain, self.redirected_from = transport.chains.pop(event.get('redirectedRequestId'), (set(), ''))
        headers = {k.lower(): str(v) for k, v in raw['headers'].items()}
        credentials = hashlib.sha256(json.dumps({k: headers.get(k) for k in ('cookie', 'authorization')}, sort_keys=True).encode()).hexdigest()
        self.key = (raw['method'], raw['url'], credentials)
        self.cycle = self.key in self.chain
        self.chain.add(self.key)
        main = event.get('frameId') == transport.main_id
        navigation = event['resourceType'] == 'Document'
        frame_url = raw['url'] if navigation else transport.frames.get(event.get('frameId'), '')
        frame = transport.page.main_frame if main else SimpleNamespace(page=transport.page)
        data = raw.get('postData')
        entries = raw.get('postDataEntries')
        if entries and all('bytes' in entry for entry in entries):
            body = b''.join(base64.b64decode(entry['bytes'], validate=True) for entry in entries)
        else:
            body = data.encode('utf-8') if isinstance(data, str) else None
        self.missing_body = raw.get('hasPostData', False) and (body is None or
            headers.get('content-type', '').lower().startswith('multipart/') and not (entries and all('bytes' in entry for entry in entries)))
        self.request = SimpleNamespace(url=raw['url'], method=raw['method'], frame=frame,
            frame_url=frame_url, resource_type=event['resourceType'].lower(),
            is_navigation_request=lambda: navigation, all_headers=lambda: headers,
            post_data_buffer=body, post_data=body.decode('utf-8', errors='replace') if body is not None else None,
            redirected_from=self.redirected_from)

    def fulfill(self, *, status, headers, body):
        values = []
        for name, value in headers.items():
            for item in value.split('\n') if name.lower() == 'set-cookie' else [value]:
                values.append({'name': name, 'value': item})
        if status in {301, 302, 303, 307, 308} and 'location' in headers:
            self.transport.chains[self.event['requestId']] = (self.chain, self.capture_id)
        try:
            self.transport.session.send('Fetch.fulfillRequest', {'requestId': self.event['requestId'],
                'responseCode': status, 'responseHeaders': values, 'body': base64.b64encode(body).decode('ascii')})
            return True
        except Exception as exc:
            if 'Invalid InterceptionId' not in str(exc):
                raise
            self.transport.chains.pop(self.event['requestId'], None)
            return False  # The browser cancelled this request during navigation.

    def abort(self):
        try:
            self.transport.session.send('Fetch.failRequest', {'requestId': self.event['requestId'], 'errorReason': 'BlockedByClient'})
        except Exception as exc:
            if 'Invalid InterceptionId' not in str(exc):
                raise


class _ChildSession:
    """A CDP child target paused before its renderer can issue requests."""
    def __init__(self, parent, session_id):
        self.parent, self.session_id = parent, session_id
        self.next_id, self.replies, self.handlers = 0, {}, {}

    def on(self, name, callback):
        self.handlers[name] = callback

    def received(self, message):
        if 'id' in message:
            self.replies[message['id']] = message
        elif message.get('method') in self.handlers:
            self.handlers[message['method']](message.get('params', {}))

    def send(self, method, params=None):
        self.next_id += 1
        mid = self.next_id
        self.parent.session.send('Target.sendMessageToTarget', {'sessionId': self.session_id,
            'message': json.dumps({'id': mid, 'method': method, 'params': params or {}})})
        until = time.monotonic() + 10  # An individual CDP operation stall timeout.
        while mid not in self.replies:
            self.parent.broker.check()
            if time.monotonic() >= until:
                raise TimeoutError('Browser child protocol stalled')
            self.parent.page.wait_for_timeout(1)
        reply = self.replies.pop(mid)
        if 'error' in reply:
            raise RuntimeError(reply['error'].get('message', 'Browser child protocol error'))
        return reply.get('result', {})


class ChromiumTransport:
    def __init__(self, context, page, broker, role, *, session=None, root_id=None):
        self.page, self.broker, self.role = page, broker, role
        self.chains, self.frames, self.requests = {}, {}, set()
        self.children = {}
        self.context = context
        self.session = session or context.new_cdp_session(page)
        self.session.send('Page.enable')
        tree = self.session.send('Page.getFrameTree')['frameTree']
        self.main_id = root_id or tree['frame']['id']
        def seed(node):
            self.frames[node['frame']['id']] = node['frame']['url']
            for child in node.get('childFrames', []):
                seed(child)
        seed(tree)
        self.session.on('Page.frameNavigated', lambda event: self.frames.update({event['frame']['id']: event['frame']['url']}))
        self.session.on('Network.requestWillBeSent', lambda event: self.requests.add(event['requestId']))
        self.session.on('Network.loadingFailed', self.failed)
        self.session.send('Network.enable')
        self.session.on('Fetch.requestPaused', self.paused)
        self.session.send('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
        self.session.on('Target.receivedMessageFromTarget', self.child_message)
        self.session.on('Target.attachedToTarget', self.attached)
        self.session.send('Target.setAutoAttach', {'autoAttach': True, 'waitForDebuggerOnStart': True, 'flatten': False})

    def child_message(self, event):
        child = self.children.get(event['sessionId'])
        if child:
            child.received(json.loads(event['message']))

    def attached(self, event):
        child = _ChildSession(self, event['sessionId'])
        self.children[event['sessionId']] = child
        try:
            # Workers/popups are not an authorized page workflow. Their network
            # remains behind the rejecting proxy; do not resume a paused worker.
            if event['targetInfo']['type'] != 'iframe':
                self.broker.error = self.broker.error or 'unsupported_browser_child_target'
                return
            child.transport = ChromiumTransport(self.context, self.page, self.broker, self.role,
                session=child, root_id=self.main_id)
            child.send('Runtime.runIfWaitingForDebugger')
        except Exception:
            self.broker.error = self.broker.error or 'browser_child_interception_failed'

    def failed(self, event):
        if event['requestId'] in self.requests and event.get('errorText') != 'net::ERR_ABORTED' and not self.broker.error:
            # Browser-controlled failures include CORS, CSP and TLS policy.
            self.broker.error = 'browser_request_failed'

    def paused(self, event):
        route = None
        try:
            route = _Route(self, event)
            if route.cycle or route.missing_body:
                self.broker.error = 'redirect_cycle' if route.cycle else 'browser_request_body_unavailable'
                route.abort()
                return
            self.broker.route(route, role=self.role)
        except Exception as exc:
            if not self.broker.error:
                self.broker.error = type(exc).__name__
            try:
                if route is not None:
                    route.abort()
                else:
                    self.session.send('Fetch.failRequest', {'requestId': event['requestId'], 'errorReason': 'BlockedByClient'})
            except Exception:
                pass  # A closing context already terminates its paused requests.
