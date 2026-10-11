"""Verify mapped bundle modules are not crawled as separate files."""
import argparse
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--binary', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
hits = []
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        hits.append(self.path)
        if self.path == '/':
            body = b'<script src="/bundle.js"></script>'
        elif self.path == '/bundle.js':
            body = b'''boot({1:[function(require,module,exports){module.exports=1},{}],2:[function(require,module,exports){(function(){require("./internal.js");require("core-js/modules/es.array.at.js");require("./missing.js");node.src="./real.123.min.js";})();},{"./internal.js":1,"core-js/modules/es.array.at.js":1,"./missing.js":99}]});require("./standalone.js");'''
        else:
            body = b'console.log(1);'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if self.path == '/' else 'application/javascript')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
s = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
t = threading.Thread(target=s.serve_forever, daemon=True)
t.start()
try:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / 'completion.jsonl'
        result = subprocess.run([
            str(Path(a.binary).resolve()), '-u', f'http://127.0.0.1:{s.server_port}/',
            '-silent', '-duc', '-jc', '-d', '2', '-ct', '8s', '-timeout', '5',
            '-retry', '0', '-c', '1', '-p', '1', '-rl', '3', '-cs', r'^http://127\.0\.0\.1:',
            '-recon-completion-log', str(log),
        ], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
           env=dict(os.environ, NO_PROXY='127.0.0.1', no_proxy='127.0.0.1'))
        assert result.returncode == 0, result.stderr
        assert set(hits) == {'/', '/bundle.js', '/missing.js', '/standalone.js', '/real.123.min.js'}, hits
        completion = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(completion) == 1 and completion[0]['stop_reason'] == 'queue_exhausted', completion
        report = {'passed': True, 'scenario': 'resolved_bundle_modules', 'requested_paths': hits, 'completion': completion}
        Path(a.output).write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report))
finally:
    s.shutdown()
    s.server_close()
    t.join()
