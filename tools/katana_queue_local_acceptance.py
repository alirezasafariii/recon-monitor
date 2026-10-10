#!/usr/bin/env python3
"""Manual Katana queue fixture; inputs and HTTP server are loopback-only."""
import argparse
import json
import os
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--scenario", choices=("fast", "slow", "short-idle", "deadline", "request-error", "page-limit"), required=True)
    parser.add_argument("--completion-contract", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    delay, timeout, crawl = {
        "fast": (0, 30, 6), "slow": (3, 30, 8),
        "short-idle": (3, 2, 8), "deadline": (6, 30, 2),
        "request-error": (0, 30, 6), "page-limit": (0, 30, 6),
    }[args.scenario]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            self.server.hits.append(path)
            if path == "/slow":
                if args.scenario == "request-error":
                    self.connection.close()
                    return
                time.sleep(delay)
            pages = {
                "/": '<a href="/slow">slow</a>',
                "/slow": '<a href="/proof">proof</a>',
                "/proof": "<html>proof</html>",
            }
            body = pages.get(path, "missing").encode()
            self.send_response(200 if path in pages else 404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *unused):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.hits = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    report = {"scenario": args.scenario, "binary": str(binary),
              "delay_seconds": delay, "timeout_flag": timeout, "crawl_seconds": crawl}
    try:
        with tempfile.TemporaryDirectory(prefix="katana-queue-local-") as tmp:
            errors = Path(tmp) / "errors.jsonl"
            env = dict(os.environ)
            env.update(NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
            started = time.monotonic()
            try:
                command = [
                    str(binary), "-u", url, "-silent", "-duc", "-d", "3",
                    "-ct", f"{crawl}s", "-timeout", str(timeout), "-retry", "0",
                    "-c", "1", "-p", "1", "-rl", "3", "-elog", str(errors),
                    "-cs", r"^http://127\.0\.0\.1:",
                ]
                if args.scenario == "page-limit":
                    command += ["-max-domain-pages", "1"]
                completion = Path(tmp) / "completion.jsonl"
                if args.completion_contract:
                    command += ["-recon-completion-log", str(completion)]
                result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, env=env)
                if args.completion_contract:
                    from katana_completion_contract import read_completion
                    report["completion"] = read_completion(completion, [url], returncode=result.returncode, timed_out=False)
                    report["completion_raw"] = completion.read_text() if completion.exists() else None
                report.update(exit_code=result.returncode, outer_timeout=False,
                              proof_emitted=url + "proof" in result.stdout,
                              stdout=result.stdout, stderr=result.stderr)
            except subprocess.TimeoutExpired:
                report.update(outer_timeout=True, proof_emitted=False)
            report.update(duration_seconds=round(time.monotonic() - started, 3),
                          requested_paths=server.hits.copy(),
                          error_log=errors.read_text(errors="replace") if errors.exists() else None)
            print(json.dumps(report, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()

