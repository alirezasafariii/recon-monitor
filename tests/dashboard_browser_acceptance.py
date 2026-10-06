from __future__ import annotations

"""Exercise the real dashboard over HTTP and, optionally, native macOS Safari.

Only temporary synthetic data is used. No collector, worker or target request is
started. Safari uses its own isolated WebDriver session; normal tabs are untouched.
This is an explicit acceptance runner, not part of default unittest discovery.
"""

import argparse
import base64
import datetime as dt
import http.cookiejar
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
import recon_monitor  # Install the same additive handlers as the actual CLI.
from core import APP_VERSION, AppPaths, Config, Database, Logger, utc_now
from dashboard import DashboardHandler
from progress_tracking import ProgressRecord
from session_auth import create_user

SOURCE = "ui-source-20261005-120000-complete-identifier"
PARTIAL = "ui-partial-20261005-130000-complete-identifier"
LIVE = "ui-retry-20261005-140000-complete-identifier"
TARGET = "example.test"
PASSWORD = "synthetic-dashboard-test-only-12345"
OUTPUT: Path
EVIDENCE: dict = {"fixture": "synthetic, loopback only", "screenshots": [], "viewports": []}


def search_path(**changes):
    params = {"q": "catalogneedle", "target": TARGET, "group": "URLs",
              "run": SOURCE, "days": "7", "files": "1"}
    params.update(changes)
    return "/search?" + urllib.parse.urlencode(params)


class Links(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.hrefs = []
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.hrefs.append(values["href"])


LONG_ENDPOINT='/api/admin/'+'complete-observation-'*24+"?name=<saved>&literal='value'"
LONG_SOURCE='https://example.test/assets/'+'complete-source-'*32+'.js'

class DashboardFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="recon-ui-acceptance-")
        self.paths = AppPaths.from_root(Path(self.tmp.name))
        self.paths.ensure()
        self.paths.config.write_text(
            'I_HAVE_AUTHORIZATION="no"\nENABLE_ACTIVE_MODULES="no"\n'
            'DASHBOARD_AUTH_ENABLED="yes"\nDASHBOARD_AUTH_MODE="session"\n',
            encoding="utf-8",
        )
        self.paths.policy.write_text('{"schema":1,"defaults":{},"targets":[]}', encoding="utf-8")
        now = utc_now()
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)).isoformat()
        db = Database(self.paths.db)
        try:
            for run_id, status in ((SOURCE, "success"), (PARTIAL, "partial"), (LIVE, "running")):
                db.execute("INSERT INTO runs(id,version,status,started_at,target_count) VALUES(?,?,?,?,1)",
                           (run_id, APP_VERSION, status, now))
                db.execute(
                    "INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,run_dir) VALUES(?,?,?,?,?,?)",
                    (run_id, TARGET, "synthetic-only", status, now, str(self.paths.output / run_id)),
                )
            for count, target, source, label, seen in (
                (210, TARGET, SOURCE, "catalogneedle", now),
                (3, "other.test", SOURCE, "catalogneedle", now),
                (2, TARGET, PARTIAL, "catalogneedle-other-run", now),
                (1, TARGET, SOURCE, "catalogneedle-old", old),
                (1, TARGET, SOURCE, "literal_%", now),
            ):
                for index in range(count):
                    db.execute(
                        "INSERT INTO urls(target,url,kind,source,first_seen,last_seen,last_run_id) "
                        "VALUES(?,?,'url','katana',?,?,?)",
                        (target, f"https://{target}/{label}/{index:05}", seen, seen, source),
                    )
            db.upsert_endpoint_intelligence(TARGET,LONG_ENDPOINT,'endpoint',{'primary_category':'administration','confidence':88,'categories':['administration']},LONG_SOURCE,SOURCE)
            self.selected_analysis='analysis-selected-complete-identifier'
            self.other_analysis='analysis-other-complete-identifier'
            for analysis,target,state,finished in [(self.selected_analysis,TARGET,'new',now),(self.other_analysis,'other.test','false_positive','2099-01-01T00:00:00Z')]:
                alert,_,_=db.upsert_alert(target,'quality-'+target,'changed_js','HIGH',78,'Saved observation','/api/admin/export',{},SOURCE)
                if state!='new':db.set_alert_status(alert,state,'synthetic feedback')
                db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,status,started_at,finished_at) VALUES(?,?,?,'fixture','fixture','success',?,?)",(analysis,SOURCE,target,now,finished))
                db.execute("INSERT INTO analysis_results(analysis_id,alert_id,target,source_run_id,category,original_score,adjusted_score,confidence,hypothesis,next_action,playbook_id,business_context,duplicate_cluster,created_at) VALUES(?,?,?,?,'changed_js',78,78,55,'Synthetic only','Review','general','fixture','fixture',?)",(analysis,alert,target,SOURCE,now))
            admission={'knowledge_context':{'meta_ranker':{'primary':{'family':'broken_object_authorization','label':'Synthetic investigation','bug_proximity_score':61,'target_evidence_confidence':49,'hunt_priority':'HIGH','why':['Saved observation requires review','No vulnerability is confirmed']},'rankings':[{'family':'broken_object_authorization','bug_proximity_score':61}]}}}
            db.execute("INSERT INTO analysis_hypotheses(hypothesis_id,hypothesis_fingerprint,analysis_id,source_run_id,target,endpoint,bug_family,bug_variant,state,admission_json,rule_version,first_seen_at,last_seen_at,created_at,updated_at) VALUES('fixture-hypothesis','fixture-fingerprint',?,?,?,?,'broken_object_authorization','object','context_only',?,'fixture',?,?,?,?)",(self.selected_analysis,SOURCE,TARGET,LONG_ENDPOINT,json.dumps(admission),now,now,now,now))
            db.stage_begin(PARTIAL, TARGET, "urls", 1)
            self.timeout_metrics = {
                "collection_status": "partial", "katana_status": "timeout",
                "katana_timed_out": True, "katana_input_origins": 24,
                "katana_origins_completed": 15, "katana_pending_origins": 9,
                "katana_observed": 73, "katana_stop_reason": "batch_timeout",
                "katana_exit_code": 124, "katana_duration_seconds": 1800,
            }
            db.stage_finish(PARTIAL, TARGET, "urls", "partial", exit_code=124, duration=1800,
                            metrics=self.timeout_metrics)
            db.stage_begin(PARTIAL, TARGET, "javascript", 1)
            db.stage_finish(PARTIAL, TARGET, "javascript", "success", metrics={
                "collection_status": "no_input", "files": 0, "downloaded": 0,
                "source_url_count": 73, "input_url_count": 0, "selected_input_count": 0,
                "javascript_dropped_by_url_limit": 0, "javascript_dropped_by_file_limit": 0,
                "zero_download_reasons": ["no_selected_js_urls"],
            })
            db.stage_begin(LIVE, TARGET, "urls", 1)
            db.stage_finish(LIVE, TARGET, "urls", "partial", exit_code=124,
                            duration=1800, metrics=self.timeout_metrics)
            db.stage_begin(LIVE, TARGET, "urls", 2)
        finally:
            db.close()
        create_user(self.paths, "fixture-viewer", PASSWORD, "viewer")
        self.progress = ProgressRecord(self.paths, "recon", LIVE, TARGET)
        self.progress.start(phase="urls", label="URL collection", percent=20, message="Acceptance initial phase")
        self.requests = []
        fixture = self

        class TestHandler(DashboardHandler):
            def log_message(self, format, *args):
                fixture.requests.append(self.path)

        TestHandler.paths = self.paths
        TestHandler.db_path = self.paths.db
        TestHandler.config = Config(self.paths)
        TestHandler.logger = Logger(self.paths, verbose=False)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def poll_count(self):
        return sum(path.startswith("/api/live-progress?") for path in self.requests)


class LiveHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = DashboardFixture()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close()

    def setUp(self):
        self.client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}),
        )

    def get(self, path):
        with self.client.open(self.fixture.base + path, timeout=10) as response:
            return response.status, response.geturl(), response.read().decode()

    def login(self):
        data = urllib.parse.urlencode({"username": "fixture-viewer", "password": PASSWORD}).encode()
        with self.client.open(self.fixture.base + "/login", data=data, timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(urllib.parse.urlsplit(response.geturl()).path, "/")

    def test_quality_scope_and_unknown_feedback(self):
        self.login()
        _,_,body=self.get('/analysis-quality?target='+TARGET)
        self.assertIn(self.fixture.selected_analysis,body);self.assertNotIn(self.fixture.other_analysis,body)
        self.assertIn('Insufficient feedback',body);self.assertNotIn('>0.0%<',body);self.assertNotIn('overconfident',body)
        _,_,body=self.get('/analysis-quality?target=other.test')
        self.assertIn(self.fixture.other_analysis,body);self.assertNotIn(self.fixture.selected_analysis,body)
        self.assertIn('>0.0%<',body);self.assertIn('>100.0%<',body)

    def test_recon_long_values_remain_complete(self):
        import html
        self.login()
        for view in ('categories','raw'):
            _,_,body=self.get('/recon?'+urllib.parse.urlencode({'target':TARGET,'view':view,'q':'complete-observation'}))
            self.assertIn(html.escape(LONG_ENDPOINT,quote=True),body);self.assertIn(html.escape(LONG_SOURCE,quote=True),body)
            self.assertIn('responsive-records recon-records',body)

    def test_login_logout_and_authentication_wall(self):
        self.assertEqual(urllib.parse.urlsplit(self.get(search_path())[1]).path, "/login")
        self.login()
        self.assertIn("Universal search", self.get(search_path())[2])
        self.get("/logout")
        self.assertEqual(urllib.parse.urlsplit(self.get("/")[1]).path, "/login")

    def test_combined_filters_and_pagination(self):
        self.login()
        for page, count in ((1, 100), (2, 100), (3, 10)):
            status, _, body = self.get(search_path(page=page))
            self.assertEqual(status, 200)
            self.assertIn("URLs · 210 matching records", body)
            self.assertIn(f"{count} shown · 210 matching records", body)
            self.assertNotIn("catalogneedle-other-run/", body)
            self.assertNotIn("catalogneedle-old/", body)
            self.assertNotIn("https://other.test/catalogneedle/", body)

    def test_drilldown_links_keep_every_filter(self):
        self.login()
        body = self.get(search_path())[2]
        link = next(h for h in Links(body).hrefs if "record=" in h)
        expected = urllib.parse.parse_qs(urllib.parse.urlsplit(search_path()).query)
        actual = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        for key in expected:
            self.assertEqual(actual[key], expected[key])
        details = self.get(link)[2]
        self.assertIn("Stored record details", details)
        back = next(h for h in Links(details).hrefs if h.startswith("/search?") and "record=" not in h)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(back).query), expected)
        self.assertIn("210 matching records", self.get(back)[2])

    def test_literal_and_empty_queries(self):
        self.login()
        literal = self.get(search_path(q="literal_%"))[2]
        self.assertIn("URLs · 1 matching records", literal)
        self.assertIn("https://example.test/literal_%/00000", literal)
        self.assertIn("No matching records", self.get(search_path(q="absent-record"))[2])
        self.assertIn("Search your workspace", self.get("/search")[2])

    def test_run_timeout_no_input_and_running_retry(self):
        self.login()
        partial = self.get("/run-review?" + urllib.parse.urlencode({"id": PARTIAL}))[2]
        for value in ("1 timeout(s)", "1 stage(s) had no input", "Partial / Timeout",
                      "No JavaScript input", "24 input", "15 completed", "9 pending", "73 lines", "batch_timeout"):
            self.assertIn(value, partial)
        running = self.get("/run-review?" + urllib.parse.urlencode({"id": LIVE}))[2]
        summary = running.split("class='panel run-review-summary'", 1)[1].split("</section>", 1)[0]
        self.assertNotIn("timeout(s)", summary)
        self.assertIn("Earlier attempt metrics", running)
        self.assertIn("In progress", running)

    def test_real_polling_endpoint_and_viewer_cannot_advance_stage(self):
        self.login()
        body = self.get("/api/live-progress?kind=recon&target=example.test")[2]
        payload = json.loads(body)
        self.assertEqual(payload["status"], "running")
        self.assertIn("Acceptance initial phase", payload["html"])
        self.assertNotIn("Partial / Timeout", payload["html"])
        self.assertNotIn("30m 0s", payload["html"])
        data = urllib.parse.urlencode({"run_id": LIVE, "target": TARGET, "stage": "urls", "attempt": 2}).encode()
        with self.client.open(self.fixture.base + "/run/next-stage", data=data, timeout=10) as response:
            self.assertEqual(urllib.parse.urlsplit(response.geturl()).path, "/login")
        db = Database(self.fixture.paths.db)
        try:
            self.assertEqual(db.one("SELECT COUNT(*) n FROM stage_next_requests")["n"], 0)
        finally:
            db.close()


class Safari:
    """Small standard W3C WebDriver client; no optional package dependency."""
    def __init__(self):
        if sys.platform != "darwin":
            raise RuntimeError("Native Safari acceptance requires macOS")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.session = ""
        self.log = (OUTPUT / "safaridriver.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            ["/usr/bin/safaridriver", "--port", str(port)], stdout=self.log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError("safaridriver exited; see safaridriver.log")
                try:
                    self.request("GET", "/status")
                    break
                except urllib.error.URLError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
            session = self.request("POST", "/session", {
                "capabilities": {"alwaysMatch": {"browserName": "safari", "platformName": "mac"}},
            })
            self.session = session["sessionId"]
            EVIDENCE["browser"] = session["capabilities"]
            self.command("POST", "/timeouts", {"pageLoad": 20000, "script": 20000, "implicit": 0})
        except BaseException:
            self.close()
            raise

    def request(self, method, path, data=None):
        request = urllib.request.Request(
            self.base + path, method=method,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.client.open(request, timeout=35) as response:
                return json.load(response)["value"]
        except urllib.error.HTTPError as error:
            with error:
                payload = error.read().decode()
            raise RuntimeError(f"WebDriver {method} {path}: {payload}") from error

    def command(self, method, path, data=None):
        return self.request(method, "/session/" + self.session + path, data)

    def js(self, script, *args):
        return self.command("POST", "/execute/sync", {"script": script, "args": list(args)})

    def element(self, selector):
        value = self.command("POST", "/element", {"using": "css selector", "value": selector})
        return value["element-6066-11e4-a52e-4f735466cecf"]

    def click(self, selector):
        # Position a visible control before Safari's native pointer action.
        # Hidden controls still fail; callers must open their actual disclosure.
        self.js("const e=document.querySelector(arguments[0]);if(e && e.tagName!=='OPTION' && e.getClientRects().length){const r=e.getBoundingClientRect(),top=document.querySelector('.topbar')?.getBoundingClientRect().bottom||0;if(r.top<top||r.bottom>innerHeight)e.scrollIntoView({block:'center',behavior:'instant'});}", selector)
        self.command("POST", "/element/" + self.element(selector) + "/click", {})

    def fill(self, selector, value):
        element = self.element(selector)
        self.command("POST", "/element/" + element + "/clear", {})
        self.command("POST", "/element/" + element + "/value", {"text": str(value)})

    def go(self, path):
        self.command("POST", "/url", {"url": path})

    def wait(self, script, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.js(script)
            if value:
                return value
            time.sleep(0.15)
        state = self.js("return {url:location.href,y:scrollY,ready:document.readyState,saved:sessionStorage.getItem('recon-same-page-scroll'),submission:sessionStorage.getItem('ui-submission-debug'),submit:window.__uiSubmit||null,history:history.scrollRestoration}")
        raise AssertionError(f"Safari condition not reached: {script}; state={state}")

    def screenshot(self, name):
        data = self.command("GET", "/screenshot")
        (OUTPUT / (name + ".png")).write_bytes(base64.b64decode(data, validate=True))
        EVIDENCE["screenshots"].append(name + ".png")

    def close(self):
        if self.session:
            try:
                self.command("DELETE", "")
            except Exception:
                pass
            self.session = ""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class SafariDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = DashboardFixture()
        cls.addClassCleanup(cls.fixture.close)
        cls.browser = Safari()
        cls.addClassCleanup(cls.browser.close)
        cls.browser.go(cls.fixture.base + "/search")
        cls.browser.fill("input[name='username']", "fixture-viewer")
        cls.browser.fill("input[name='password']", PASSWORD)
        cls.browser.click("form[action='/login'] button")
        cls.browser.wait("return location.pathname==='/' && document.querySelector('.command-balanced')")

    def setUp(self):
        self.browser.command("POST", "/window/rect", {"width": 1366, "height": 900})
        self.go("/search")
        self.browser.js("window.getSelection().removeAllRanges();document.activeElement.blur();localStorage.removeItem('recon-filters-/search-Search filters');document.querySelector('details[data-filter-panel]').open=false;")

    def go(self, path):
        self.browser.go(self.fixture.base + path)
        self.browser.wait("return document.readyState==='complete'")

    def text(self):
        return self.browser.js("return document.querySelector('.content').innerText")

    def appearance(self, button):
        if not self.browser.js("return document.querySelector('.display-menu').open"):
            self.browser.click(".display-menu > summary")
        self.browser.click("#" + button)
        if self.browser.js("return document.querySelector('.display-menu').open"):
            self.browser.click(".display-menu > summary")

    def test_native_search_form_and_record_round_trip(self):
        b = self.browser
        b.fill(".filter-panel input[name='q']", "catalogneedle")
        b.click(".filter-panel select[name='target'] option[value='example.test']")
        b.click("details[data-filter-panel] > summary")
        b.click(".filter-panel select[name='group'] option[value='URLs']")
        b.fill(".filter-panel input[name='run']", SOURCE)
        b.click(".filter-panel select[name='days'] option[value='7']")
        b.click(".filter-panel select[name='files'] option[value='1']")
        b.click(".filter-actions button")
        b.wait("return document.querySelector('.search-type-browser')?.textContent.includes('210 matching records')")
        expected = urllib.parse.parse_qs(urllib.parse.urlsplit(search_path()).query)
        actual = urllib.parse.parse_qs(urllib.parse.urlsplit(b.command("GET", "/url")).query)
        self.assertEqual(actual, expected)
        self.assertEqual(b.js("return document.querySelectorAll('table[aria-label=\"URLs\"] tbody>tr').length"), 100)
        b.click("table[aria-label='URLs'] a.small")
        b.wait("return new URLSearchParams(location.search).has('record') && !!document.querySelector('.search-record-details')")
        self.assertIn("Stored record details", self.text())
        detail = b.command("GET", "/url")
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(detail).query)
        for key in expected:
            self.assertEqual(params[key], expected[key])
        b.command("POST", "/back", {})
        b.wait("return !new URLSearchParams(location.search).has('record') && !!document.querySelector('.pager')")
        self.assertIn("210 matching records", self.text())
        b.command("POST", "/forward", {})
        b.wait("return new URLSearchParams(location.search).has('record') && !!document.querySelector('.search-record-details')")
        self.assertEqual(b.command("GET", "/url"), detail)
        b.click(".page-header a[href^='/search?']")
        b.wait("return !new URLSearchParams(location.search).has('record') && !!document.querySelector('.pager')")
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(b.command("GET", "/url")).query), expected)
        self.assertIn("210 matching records", self.text())

    def test_same_page_pagination_and_filter_submit_preserve_scroll(self):
        self.go(search_path())
        b = self.browser
        b.js("document.documentElement.style.scrollBehavior='auto';window.scrollTo(0,900)")
        before = b.js("return window.scrollY")
        self.assertGreater(before, 600)
        b.js("document.addEventListener('submit',()=>sessionStorage.setItem('ui-submission-debug',JSON.stringify({y:scrollY,saved:sessionStorage.getItem('recon-same-page-scroll')})),{capture:true,once:true});window.__uiSubmit='old-document';document.querySelector('.filter-panel form').requestSubmit()")
        b.wait("return window.__uiSubmit===undefined && document.readyState==='complete' && Math.abs(window.scrollY-900)<5")
        self.assertAlmostEqual(b.js("return window.scrollY"), before, delta=5)
        # Bottom pagination is a real native link with the same number of rows.
        b.js("const a=[...document.querySelectorAll('.pager a')].filter(a=>a.textContent.includes('Next')).pop();a.id='acceptance-next';a.scrollIntoView({block:'center',behavior:'instant'});")
        before = b.js("return window.scrollY")
        b.click("#acceptance-next")
        b.wait("return new URLSearchParams(location.search).get('page')==='2'")
        b.wait("return Math.abs(window.scrollY-" + str(before) + ")<8")
        self.assertIn("/catalogneedle/00100", self.text())
        self.assertNotIn("/catalogneedle/00000", self.text())
        b.command("POST", "/back", {})
        self.assertIn("/catalogneedle/00000", self.text())

    def test_native_pagination_preserves_scroll_and_complete_pages(self):
        self.go(search_path())
        b = self.browser
        b.js("document.documentElement.style.scrollBehavior='auto';const a=[...document.querySelectorAll('.pager a')].filter(a=>a.textContent.includes('Next')).pop();a.id='acceptance-next-native';a.scrollIntoView({block:'center',behavior:'instant'});")
        before = b.js("return window.scrollY")
        self.assertGreater(before, 900)
        b.click("#acceptance-next-native")
        b.wait("return new URLSearchParams(location.search).get('page')==='2'")
        b.wait("return Math.abs(window.scrollY-" + str(before) + ")<8")
        self.assertIn("/catalogneedle/00100", self.text())
        self.assertNotIn("/catalogneedle/00000", self.text())

    def test_native_disclosures_and_metrics_hash(self):
        self.go(search_path())
        b = self.browser
        self.assertFalse(b.js("return document.querySelector('details[data-filter-panel]').open"))
        b.click("details[data-filter-panel] > summary")
        b.command("POST", "/refresh", {})
        self.assertTrue(b.js("return document.querySelector('details[data-filter-panel]').open"))
        b.click("details[data-filter-panel] > summary")
        b.command("POST", "/refresh", {})
        self.assertFalse(b.js("return document.querySelector('details[data-filter-panel]').open"))
        self.go("/run-review?" + urllib.parse.urlencode({"id": PARTIAL}))
        for value in ("1 timeout(s)", "1 stage(s) had no input", "Partial / Timeout", "No JavaScript input"):
            self.assertIn(value, self.text())
        b.click(".run-metrics-link")
        self.assertTrue(b.js("return document.getElementById(decodeURIComponent(location.hash.slice(1))).open"))

    def test_themes_density_and_responsive_fields(self):
        b = self.browser
        for name, path, width in (
            ("search-desktop", search_path(), 1366),
            ("run-desktop", "/run-review?" + urllib.parse.urlencode({"id": PARTIAL}), 1366),
            ("search-narrow", search_path(), 390),
            ("record-narrow", search_path(record=f"https://{TARGET}/catalogneedle/00000"), 390),
            ("run-narrow", "/run-review?" + urllib.parse.urlencode({"id": PARTIAL}), 390),
        ):
            b.command("POST", "/window/rect", {"width": width, "height": 900})
            self.go(path)
            viewport = b.js("return {width:innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}")
            EVIDENCE["viewports"].append({"view": name, "requested_width": width, **viewport})
            self.assertLessEqual(viewport["scroll"], viewport["client"] + 1, (name, viewport))
            if width == 390:
                self.assertLessEqual(viewport["width"], 680, "Safari window must reach the stacked layout breakpoint")
                self.assertEqual(b.js("return getComputedStyle(document.querySelector('.responsive-records tbody>tr')).display"), "block")
                self.assertEqual(b.js("return [...document.querySelectorAll('.responsive-records tbody>tr:first-child .record-field-label')].filter(x=>getComputedStyle(x).display!=='none').length"), 5)
            for theme in ("light", "dark"):
                if b.js("return document.documentElement.dataset.theme") != theme:
                    self.appearance("themeToggle")
                self.assertEqual(b.js("return document.documentElement.dataset.theme"), theme)
                b.screenshot(name + "-" + theme)
            self.appearance("densityToggle")
            compact = b.js("return document.body.classList.contains('compact')")
            b.command("POST", "/refresh", {})
            self.assertEqual(b.js("return document.body.classList.contains('compact')"), compact)
            self.appearance("densityToggle")

    def test_recon_long_sources_and_mobile_labels(self):
        b=self.browser
        for view in ('categories','raw'):
            for width in (1366,390):
                b.command('POST','/window/rect',{'width':width,'height':900})
                self.go('/recon?'+urllib.parse.urlencode({'target':TARGET,'view':view,'q':'complete-observation'}))
                values=b.js("return [...document.querySelectorAll('.recon-records tbody tr:first-child .record-field-value')].map(x=>x.textContent)")
                self.assertEqual(len(values),8);self.assertTrue(any(LONG_ENDPOINT in v for v in values));self.assertTrue(any(LONG_SOURCE in v for v in values))
                bounds=b.js("const row=document.querySelector('.recon-records tbody tr');return {client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,height:row.getBoundingClientRect().height,valueWidth:row.children["+('3' if view=='categories' else '2')+"].getBoundingClientRect().width,labels:[...row.querySelectorAll('.record-field-label')].filter(x=>getComputedStyle(x).display!=='none').length}")
                self.assertLessEqual(bounds['scroll'],bounds['client']+1)
                if width==390:self.assertEqual(bounds['labels'],8)
                else:self.assertGreaterEqual(bounds['valueWidth'],200)
                b.js("document.querySelector('.recon-table-panel').scrollIntoView({block:'start',behavior:'instant'});scrollBy({top:-80,behavior:'instant'})")
                for theme in ('light','dark'):
                    if b.js('return document.documentElement.dataset.theme')!=theme:self.appearance('themeToggle')
                    b.js("document.querySelector('.recon-table-panel').scrollIntoView({block:'start',behavior:'instant'});scrollBy({top:-80,behavior:'instant'})")
                    self.assertTrue(b.js("const r=document.querySelector('.recon-table-panel').getBoundingClientRect();return r.top<innerHeight && r.bottom>document.querySelector('.topbar').getBoundingClientRect().bottom"))
                    b.screenshot('recon-'+view+'-'+str(width)+'-'+theme)

    def test_quality_contained_tables_and_native_target_filter(self):
        b=self.browser
        for width in (1366,390):
            b.command('POST','/window/rect',{'width':width,'height':900})
            self.go('/analysis-quality?target='+TARGET)
            self.assertIn(self.fixture.selected_analysis,self.text());self.assertNotIn(self.fixture.other_analysis,self.text())
            self.assertIn('Insufficient feedback',self.text())
            self.assertTrue(b.js("return [...document.querySelectorAll('.quality-table')].every(t=>t.getBoundingClientRect().right<=t.parentElement.getBoundingClientRect().right+1)"))
            self.assertTrue(b.js("return [...document.querySelectorAll('.quality-table tbody .quality-status')].every(p=>p.getBoundingClientRect().right<=p.closest('td').getBoundingClientRect().right+1)"))
            self.assertTrue(b.js('return document.documentElement.scrollWidth<=document.documentElement.clientWidth+1'))
            self.assertFalse(b.js("return document.querySelector('.quality-playbook').open"))
            b.click('.quality-playbook > summary');self.assertTrue(b.js("return document.querySelector('.quality-playbook').open"))
            b.click('.quality-playbook > summary')
            for theme in ('light','dark'):
                if b.js('return document.documentElement.dataset.theme')!=theme:self.appearance('themeToggle')
                b.screenshot('quality-'+str(width)+'-'+theme)
        b.click("select[name=target]")
        b.click("select[name=target] option[value='other.test']")
        b.click('.filter-panel form button');b.wait("return location.search.includes('other.test')")
        self.assertIn(self.fixture.other_analysis,self.text());self.assertNotIn(self.fixture.selected_analysis,self.text());self.assertIn('0.0%',self.text())

    def test_recon_native_filters_and_complete_pagination(self):
        b=self.browser
        self.go('/recon?target='+TARGET+'&view=categories')
        b.fill(".filter-panel input[name='q']:not([type='hidden'])",'catalogneedle')
        b.click('.filter-advanced > summary')
        b.click("select[name='category'] option[value='other']")
        b.click("select[name='days'] option[value='7']")
        b.click("form.filters:has(input[name='q']:not([type='hidden'])) button")
        b.wait("return location.search.includes('catalogneedle')")
        self.assertIn('212 results',self.text())
        b.click("a[href*='view=raw']")
        b.wait("return location.search.includes('view=raw')")
        if not b.js("return document.querySelector('.filter-advanced').open"):b.click('.filter-advanced > summary')
        b.click("select[name='raw'] option[value='url']")
        b.click("form.filters:has(input[name='q']:not([type='hidden'])) button")
        b.wait("return location.search.includes('raw=url')")
        values=[]
        for page,count in ((1,100),(2,100),(3,12)):
            if page>1:
                b.click(".pager a[href*='page="+str(page)+"']")
                b.wait("return new URL(location.href).searchParams.get('page')==='"+str(page)+"'")
            observed=b.js("return [...document.querySelectorAll('.recon-records tbody tr')].map(r=>r.children[2].querySelector('.record-field-value').textContent)")
            self.assertEqual(len(observed),count);values.extend(observed)
            params=b.js("return Object.fromEntries(new URL(location.href).searchParams)")
            for key,value in {'target':TARGET,'view':'raw','raw':'url','q':'catalogneedle','days':'7'}.items():self.assertEqual(params.get(key),value)
        self.assertEqual(len(set(values)),212)
        self.assertFalse(any('catalogneedle-old' in v for v in values))

    def test_analysis_has_one_complete_identity(self):
        self.go('/analysis?target='+TARGET)
        content=self.text()
        self.assertEqual(content.count(self.fixture.selected_analysis),1)
        self.assertIn('Potential Findings',content);self.assertIn('Analysis Quality',content)
        self.browser.screenshot('analysis-compact-desktop')

    def test_compact_investigation_keeps_details_and_cluster_navigation(self):
        b=self.browser
        self.go('/potential-findings?target='+TARGET)
        b.wait("return document.querySelector('.investigation-queue-card')")
        self.assertEqual(b.js("return document.querySelector('.filter-panel select[name=target]').value"),TARGET)
        self.assertTrue(b.js("const filter=document.querySelector('.filter-panel'),queue=document.querySelector('#investigation-queue');return !!(filter.compareDocumentPosition(queue)&Node.DOCUMENT_POSITION_FOLLOWING)"))
        self.assertTrue(b.js("const heading=[...document.querySelectorAll('h3')].find(e=>e.textContent==='Ranked candidates');return !heading || !!(heading.compareDocumentPosition(document.querySelector('#investigation-queue'))&Node.DOCUMENT_POSITION_FOLLOWING)"))
        b.screenshot('potential-filters-first-desktop')
        self.assertFalse(b.js("return document.querySelector('.queue-item-details').open"))
        card=b.js("const e=document.querySelector('.investigation-queue-card');return {height:e.getBoundingClientRect().height,text:e.innerText}")
        self.assertLessEqual(card['height'],320)
        for text in ('HIGH','NOT CONFIRMED',TARGET,'49','Open cluster'):self.assertIn(text,card['text'])
        b.js("document.querySelector('.investigation-queue-card').scrollIntoView({block:'center'})")
        b.screenshot('investigation-compact-desktop')
        b.click('.queue-item-details > summary')
        self.assertIn(LONG_ENDPOINT,self.text());self.assertIn('No vulnerability is confirmed',self.text())
        b.click('.queue-item-details > summary')
        b.command('POST','/window/rect',{'width':390,'height':900})
        self.assertTrue(b.js('return document.documentElement.scrollWidth<=document.documentElement.clientWidth+1'))
        b.screenshot('investigation-compact-narrow')
        b.click('.queue-item-actions a')
        b.wait("return document.querySelector('#investigation-cluster-detail')")
        self.assertIn(LONG_ENDPOINT,self.text());self.assertIn('target=example.test',b.js('return location.search'))

    def live(self, label):
        self.fixture.progress.update(label=label, message=label)
        self.go("/recon?target=example.test&view=raw&raw=url")
        self.browser.wait("return document.querySelector('#live-progress').textContent.includes(" + json.dumps(label) + ")")

    def wait_poll(self, after):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.fixture.poll_count() > after:
                return
            time.sleep(0.2)
        self.fail("Real five-second polling request was not observed")

    def test_polling_keeps_disclosures_and_reading_position(self):
        self.live("Safari reading position baseline")
        b = self.browser
        b.click("#live-progress-details > summary")
        b.click(".filter-panel input[name='q']:not([type='hidden'])")
        b.js("document.documentElement.style.scrollBehavior='auto';window.scrollTo(0,1200);window.__uiPanel=document.querySelector('#live-progress');")
        before = b.js("return document.querySelector('.page-header').getBoundingClientRect().top")
        self.fixture.progress.update(message="Safari reading position changed. " + "A longer synthetic progress message. " * 24)
        b.wait("return window.__uiPanel!==document.querySelector('#live-progress') && document.querySelector('#live-progress').textContent.includes('Safari reading position changed')")
        self.assertTrue(b.js("return document.querySelector('#live-progress-details').open"))
        self.assertAlmostEqual(b.js("return document.querySelector('.page-header').getBoundingClientRect().top"), before, delta=8)

    def test_polling_keeps_focused_control(self):
        self.live("Safari focus baseline")
        b = self.browser
        b.click("#live-progress-details > summary")
        b.js("document.querySelector('#live-progress-details > summary').focus();window.__uiPanel=document.querySelector('#live-progress')")
        count = self.fixture.poll_count()
        self.fixture.progress.update(message="Safari focus changed")
        self.wait_poll(count)
        self.assertTrue(b.js("return window.__uiPanel===document.querySelector('#live-progress')"))
        self.assertTrue(b.js("return document.activeElement===document.querySelector('#live-progress-details > summary')"))
        b.click(".filter-panel input[name='q']:not([type='hidden'])")
        b.wait("return document.querySelector('#live-progress').textContent.includes('Safari focus changed')")

    def test_polling_keeps_selected_text_until_released(self):
        self.live("Safari selection baseline")
        b = self.browser
        b.js("const range=document.createRange();range.selectNodeContents(document.querySelector('#live-progress h3'));const selection=getSelection();selection.removeAllRanges();selection.addRange(range);window.__uiPanel=document.querySelector('#live-progress');window.__uiSelected=selection.toString();")
        count = self.fixture.poll_count()
        self.fixture.progress.update(message="Safari selection changed")
        self.wait_poll(count)
        self.assertTrue(b.js("return window.__uiPanel===document.querySelector('#live-progress')"))
        self.assertTrue(b.js("return getSelection().toString()===window.__uiSelected && !!window.__uiSelected"))
        b.js("getSelection().removeAllRanges()")
        b.wait("return document.querySelector('#live-progress').textContent.includes('Safari selection changed')")


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records.append({"test": test.id(), "status": "passed"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.records.append({"test": test.id(), "status": "failed", "error": self._exc_info_to_string(err, test)})

    def addError(self, test, err):
        super().addError(test, err)
        self.records.append({"test": test.id(), "status": "error", "error": self._exc_info_to_string(err, test)})

    def stopTest(self, test):
        if isinstance(test, SafariDashboardTests):
            try:
                state = test.browser.js("return {url:location.href,y:scrollY,ready:document.readyState,saved:sessionStorage.getItem('recon-same-page-scroll'),history:history.scrollRestoration,viewport:innerWidth}")
                EVIDENCE.setdefault("browser_states", []).append({"test": test.id(), **state})
            except Exception:
                pass
            if any(row["test"] == test.id() and row["status"] != "passed" for row in self.records):
                try:
                    test.browser.screenshot("failure-" + test._testMethodName)
                except Exception:
                    pass
        super().stopTest(test)


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("safari",))
    parser.add_argument("--http-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.browser) == bool(args.http_only):
        parser.error("Choose exactly one of --browser safari or --http-only")
    OUTPUT = args.output.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LiveHTTPTests)
    if args.browser:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SafariDashboardTests))
    original_connect = socket.socket.connect

    def loopback_connect(sock, address):
        if isinstance(address, tuple) and address[0] not in {"127.0.0.1", "::1", "localhost"}:
            raise AssertionError(f"Acceptance tests refuse non-loopback network: {address[0]}")
        return original_connect(sock, address)

    started = time.monotonic()
    with patch("socket.socket.connect", loopback_connect):
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    EVIDENCE.update(tests=result.records, tests_run=result.testsRun,
                    success=result.wasSuccessful(), duration_seconds=round(time.monotonic() - started, 3))
    (OUTPUT / "results.json").write_text(json.dumps(EVIDENCE, indent=2) + "\n", encoding="utf-8")
    print("DASHBOARD_ACCEPTANCE " + json.dumps({k: v for k, v in EVIDENCE.items() if k != "tests"}), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
