from __future__ import annotations

from pathlib import Path
import hashlib


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one replacement, found {count}: {old[:100]!r}")
    return text.replace(old, new, 1)


executor = Path("app/validation_executor.py")
text = executor.read_text(encoding="utf-8")

if "PERSISTED_RESPONSE_HEADERS" not in text:
    text = replace_once(
        text,
        'ALLOWED_RECIPE_HEADERS = {"origin", "access-control-request-method", "accept"}\n',
        'ALLOWED_RECIPE_HEADERS = {"origin", "access-control-request-method", "accept"}\n'
        'PERSISTED_RESPONSE_HEADERS = {\n'
        '    "content-type",\n'
        '    "cache-control",\n'
        '    "vary",\n'
        '    "age",\n'
        '    "etag",\n'
        '    "location",\n'
        '    "access-control-allow-origin",\n'
        '    "access-control-allow-credentials",\n'
        '    "allow",\n'
        '    "server",\n'
        '}\n',
    )

if "run directory is outside the current Recon Monitor output root" not in text:
    text = replace_once(
        text,
        '    if not run_dir.exists() or not run_dir.is_dir():\n'
        '        raise ReconError(f"Run directory does not exist: {run_dir}")\n'
        '    return selected_target, run_dir\n',
        '    run_dir = run_dir.resolve()\n'
        '    output_root = paths.output.resolve()\n'
        '    try:\n'
        '        run_dir.relative_to(output_root)\n'
        '    except ValueError as exc:\n'
        '        raise ReconError(\n'
        '            f"Run directory is outside the current Recon Monitor output root: {run_dir}"\n'
        '        ) from exc\n'
        '    if not run_dir.exists() or not run_dir.is_dir():\n'
        '        raise ReconError(f"Run directory does not exist: {run_dir}")\n'
        '    return selected_target, run_dir\n',
    )

if "Refusing symlinked Validation Runner artifact" not in text:
    text = replace_once(
        text,
        'def _load_json(path: Path) -> dict[str, Any]:\n'
        '    if not path.exists() or not path.is_file():\n',
        'def _load_json(path: Path) -> dict[str, Any]:\n'
        '    if path.is_symlink():\n'
        '        raise ReconError(f"Refusing symlinked Validation Runner artifact: {path}")\n'
        '    if not path.exists() or not path.is_file():\n',
    )

if "def _sanitize_observation(" not in text:
    insertion = '''def _strip_query_fragment(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return ""
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        return urllib.parse.urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", "")
        )
    return urllib.parse.urlunsplit(("", "", parsed.path or "", "", ""))


def _bounded_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return default


def _sanitize_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Project transport output onto a fixed redacted persistence schema."""

    source = dict(observation or {})
    persisted_headers: dict[str, str] = {}
    raw_headers = source.get("headers")
    if isinstance(raw_headers, Mapping):
        for key, value in raw_headers.items():
            normalized = str(key or "").strip().lower()
            if normalized not in PERSISTED_RESPONSE_HEADERS:
                continue
            rendered = str(value or "")[:1000]
            if normalized == "location":
                rendered = _strip_query_fragment(rendered)
            persisted_headers[normalized] = rendered

    method = str(source.get("method") or "").upper()
    if method not in ALLOWED_METHODS:
        method = ""
    shape = source.get("response_shape", {})
    if not isinstance(shape, (dict, list, str, int, float, bool)) and shape is not None:
        shape = {}

    return {
        "method": method,
        "url": _strip_query_fragment(source.get("url")),
        "status_code": _bounded_int(source.get("status_code")),
        "headers": persisted_headers,
        "content_type": str(source.get("content_type") or "")[:500],
        "response_bytes": _bounded_int(source.get("response_bytes")),
        "body_sha256": str(source.get("body_sha256") or "")[:128],
        "response_shape": shape,
        "shape_hash": str(source.get("shape_hash") or "")[:128],
        "sensitive_key_names": [
            str(value)[:240]
            for value in list(source.get("sensitive_key_names") or [])[:100]
        ],
        "sensitive_pattern_categories": [
            str(value)[:120]
            for value in list(source.get("sensitive_pattern_categories") or [])[:50]
        ],
        "redirect_outside_scope": bool(source.get("redirect_outside_scope")),
        "raw_body_stored": False,
        "error": str(source.get("error") or "")[:500],
        "observed_at": str(source.get("observed_at") or utc_now()),
    }


'''
    text = replace_once(
        text,
        'def _append_execution(run_dir: Path, result: Mapping[str, Any]) -> Path:\n',
        insertion + 'def _append_execution(run_dir: Path, result: Mapping[str, Any]) -> Path:\n',
    )

if "Refusing symlinked Validation Runner execution log" not in text:
    text = replace_once(
        text,
        'def _append_execution(run_dir: Path, result: Mapping[str, Any]) -> Path:\n'
        '    output = run_dir / "validation-runner-executions.jsonl"\n'
        '    output.parent.mkdir(parents=True, exist_ok=True)\n',
        'def _append_execution(run_dir: Path, result: Mapping[str, Any]) -> Path:\n'
        '    output = run_dir / "validation-runner-executions.jsonl"\n'
        '    if output.is_symlink():\n'
        '        raise ReconError(f"Refusing symlinked Validation Runner execution log: {output}")\n'
        '    output.parent.mkdir(parents=True, exist_ok=True)\n',
    )

if "row = _sanitize_observation(observation or {})" not in text:
    text = replace_once(
        text,
        '            row = dict(observation or {})\n'
        '            row["sequence"] = index + 1\n'
        '            row["request_purpose"] = str(request.get("purpose") or "")\n'
        '            row["raw_body_stored"] = False\n',
        '            row = _sanitize_observation(observation or {})\n'
        '            row["sequence"] = index + 1\n'
        '            row["request_purpose"] = str(request.get("purpose") or "")[:500]\n',
    )

executor.write_text(text, encoding="utf-8")


tests = Path("tests/test_validation_executor.py")
test_text = tests.read_text(encoding="utf-8")
marker = "    def test_cors_recipe_uses_only_allowlisted_safe_headers_and_methods(self):\n"
if "test_response_projection_drops_unknown_fields_and_scrubs_location" not in test_text:
    regression = '''    def test_response_projection_drops_unknown_fields_and_scrubs_location(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())

        def response_with_secret(item, policy):
            row = self.observation(item)
            row["headers"]["location"] = "https://api.example.test/login?token=RESPONSE-SECRET#fragment"
            row["raw_body"] = "RESPONSE-SECRET"
            row["unexpected_transport_field"] = "RESPONSE-SECRET"
            return row, "ok"

        with patch(
            "validation_executor.safe_validation._perform_request",
            side_effect=response_with_secret,
        ), patch("validation_executor.time.sleep", return_value=None):
            result = self.fx.execute(contract_id)

        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("RESPONSE-SECRET", encoded)
        self.assertNotIn("raw_body", encoded)
        self.assertNotIn("unexpected_transport_field", encoded)
        location = result["observations"][0]["headers"]["location"]
        self.assertEqual(location, "https://api.example.test/login")

    def test_run_directory_outside_current_output_root_is_rejected(self):
        _, _, _, contract_id = self.fx.make_artifacts(passive_plan())
        outside = self.fx.root / "outside-run"
        outside.mkdir(parents=True, exist_ok=True)
        self.fx.db.execute(
            "UPDATE run_targets SET run_dir=? WHERE run_id=? AND target=?",
            (str(outside), RUN_ID, TARGET),
        )
        with patch("validation_executor.safe_validation._perform_request") as request:
            with self.assertRaisesRegex(ReconError, "outside the current Recon Monitor output root"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

'''
    if marker not in test_text:
        raise SystemExit("test insertion marker not found")
    test_text = test_text.replace(marker, regression + marker, 1)
tests.write_text(test_text, encoding="utf-8")


manifest = Path("MANIFEST.sha256")
entries: dict[str, str] = {}
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    digest, rel = raw.split("  ", 1)
    entries[rel] = digest
for rel in (
    "app/recon_monitor.py",
    "app/validation_executor.py",
    "tests/test_validation_executor.py",
):
    entries[rel] = hashlib.sha256(Path(rel).read_bytes()).hexdigest()
manifest.write_text(
    "".join(f"{entries[rel]}  {rel}\n" for rel in sorted(entries)),
    encoding="utf-8",
)
