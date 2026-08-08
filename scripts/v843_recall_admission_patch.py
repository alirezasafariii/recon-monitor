from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one match in {path}, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def insert_before_once(path: str, marker: str, payload: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if text.count(marker) != 1:
        raise SystemExit(f"expected one insertion marker in {path}: {marker[:120]!r}")
    p.write_text(text.replace(marker, payload + marker, 1), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    a = text.find(start)
    if a < 0:
        raise SystemExit(f"start marker not found in {path}: {start!r}")
    b = text.find(end, a + len(start))
    if b < 0:
        raise SystemExit(f"end marker not found in {path}: {end!r}")
    p.write_text(text[:a] + replacement + text[b:], encoding="utf-8")


# ---------------------------------------------------------------------------
# Core version + additive schema 18 hypothesis ledger.
# ---------------------------------------------------------------------------
replace_once("app/core.py", 'APP_VERSION = "8.4.2"\nSCHEMA_VERSION = 17\n', 'APP_VERSION = "8.4.3"\nSCHEMA_VERSION = 18\n')

hypothesis_table = '''            CREATE TABLE IF NOT EXISTS analysis_hypotheses (\n              hypothesis_id TEXT PRIMARY KEY, hypothesis_fingerprint TEXT NOT NULL, analysis_id TEXT NOT NULL, source_run_id TEXT NOT NULL,\n              alert_id INTEGER, target TEXT NOT NULL, asset TEXT NOT NULL DEFAULT '', endpoint TEXT NOT NULL DEFAULT '', source_ref TEXT NOT NULL DEFAULT '',\n              bug_family TEXT NOT NULL, bug_variant TEXT NOT NULL, state TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',\n              supporting_evidence_json TEXT NOT NULL DEFAULT '[]', contradicting_evidence_json TEXT NOT NULL DEFAULT '[]', missing_evidence_json TEXT NOT NULL DEFAULT '[]',\n              decisive_signals_json TEXT NOT NULL DEFAULT '[]', admission_json TEXT NOT NULL DEFAULT '{}', knowledge_references_json TEXT NOT NULL DEFAULT '[]',\n              rule_ids_json TEXT NOT NULL DEFAULT '[]', rule_version TEXT NOT NULL, seen_count INTEGER NOT NULL DEFAULT 1,\n              first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, promoted_candidate_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,\n              UNIQUE(analysis_id,hypothesis_fingerprint), FOREIGN KEY(analysis_id) REFERENCES analysis_runs(id) ON DELETE CASCADE\n            );\n'''
insert_before_once("app/core.py", "            CREATE TABLE IF NOT EXISTS bug_candidates (\n", hypothesis_table)
insert_before_once(
    "app/core.py",
    "            CREATE INDEX IF NOT EXISTS idx_bug_candidates_analysis ON bug_candidates(analysis_id,priority_score,candidate_state);\n",
    "            CREATE INDEX IF NOT EXISTS idx_analysis_hypotheses_state ON analysis_hypotheses(analysis_id,state,bug_family,target);\n"
    "            CREATE INDEX IF NOT EXISTS idx_analysis_hypotheses_endpoint ON analysis_hypotheses(target,bug_family,endpoint,last_seen_at);\n",
)

# ---------------------------------------------------------------------------
# Candidate engine: hypothesis-first, candidate-after-admission.
# ---------------------------------------------------------------------------
replace_once("app/bug_candidates.py", 'from core import Database, ReconError, json_dumps, parse_int, sha256_text, utc_now\n',
             'from core import Database, ReconError, json_dumps, parse_int, sha256_text, utc_now\nfrom hypothesis_admission import mark_promoted, record_hypothesis\n')
replace_once("app/bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "5.0.1"\nCANDIDATE_RULE_VERSION = "2026.08.8.1"\n',
             'CANDIDATE_ENGINE_VERSION = "5.1.0"\nCANDIDATE_RULE_VERSION = "2026.08.8.3"\n')
replace_once(
    "app/bug_candidates.py",
    '    "file_upload": {"required_any": (("file_input",), ("upload_operation", "import_operation")), "label": "file input plus upload or import operation"},\n',
    '    "file_upload": {"required_any": (("file_input",), ("upload_operation", "import_operation")), "label": "file input plus upload or import operation"},\n'
    '    "path_traversal": {"required_any": (("path_parameter", "filename_field", "storage_path"), ("file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation")), "label": "user-influenced path or filename plus a file operation"},\n',
)

old_emit = '''    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:\n        nonlocal count\n        # Two independent signals are required unless the evidence is a direct static relation.\n        independent = {str(x.get("source") or x.get("type") or "rule") for x in support}\n        if len(support) < 2 or (len(independent) < 2 and not direct):\n            return\n        likelihood = base + sum(parse_int(x.get("weight"), 0) for x in support) + sum(parse_int(x.get("weight"), 0) for x in contradict)\n        strength = _evidence_strength(confidence, support, contradict, direct=direct)\n        _insert_candidate(\n            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,\n            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant,\n            likelihood=likelihood, evidence_strength=strength,\n            impact_potential=_impact(impact if impact is not None else BUG_FAMILIES[family]["impact"], context, method),\n            support=support, contradict=contradict, missing=missing, rule_ids=rules, summary=summary,\n        )\n        count += 1\n'''
new_emit = '''    def emit(family: str, variant: str, base: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], missing: list[str], rules: list[str], summary: str, *, direct: bool = False, impact: int | None = None) -> None:\n        nonlocal count\n        hypothesis = record_hypothesis(\n            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,\n            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant, support=support,\n            contradict=contradict, missing=missing, rule_ids=rules, summary=summary,\n        )\n        support = hypothesis["support"]\n        contradict = hypothesis["contradict"]\n        missing = hypothesis["missing"]\n        rules = hypothesis["rule_ids"]\n        if not hypothesis["assessment"]["admitted"]:\n            return\n        # Admission decides family-specific sufficiency. This generic quality guard still\n        # protects against a single duplicated source while retaining all weaker signals\n        # in analysis_hypotheses for future correlation.\n        independent = {str(x.get("source") or x.get("source_group") or x.get("type") or "rule") for x in support}\n        if len(support) < 2 or (len(independent) < 2 and not direct):\n            return\n        likelihood = base + sum(parse_int(x.get("weight"), 0) for x in support) + sum(parse_int(x.get("weight"), 0) for x in contradict)\n        strength = _evidence_strength(confidence, support, contradict, direct=direct)\n        candidate_id = _insert_candidate(\n            db, analysis_id=analysis_id, source_run_id=run_id, target=target, alert_id=alert_id, asset=asset,\n            endpoint=endpoint, source_ref=source_ref, family=family, variant=variant,\n            likelihood=likelihood, evidence_strength=strength,\n            impact_potential=_impact(impact if impact is not None else BUG_FAMILIES[family]["impact"], context, method),\n            support=support, contradict=contradict, missing=missing, rule_ids=rules, summary=summary,\n        )\n        mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)\n        count += 1\n'''
replace_once("app/bug_candidates.py", old_emit, new_emit)

new_file_block = '''    # File handling. Hypothesis generation is deliberately recall-oriented, while\n    # admission is based only on structural file/path evidence. Generic metadata such\n    # as Content-Type is retained in the hidden hypothesis ledger but cannot promote.\n    structured_fields = [str(value) for value in body_fields + query_fields + path_fields]\n    normalized_fields = {re.sub(r"[^a-z0-9]", "", value.lower()): value for value in structured_fields}\n    file_input_names = {"file", "files", "filename", "file_name", "attachment", "attachments", "avatar", "document", "documents", "upload", "uploadfile", "upload_file"}\n    file_input_norm = {re.sub(r"[^a-z0-9]", "", value) for value in file_input_names}\n    path_names = {"path", "filepath", "file_path", "filename", "file_name", "directory", "dir", "folder", "storage_path", "storagepath"}\n    path_norm = {re.sub(r"[^a-z0-9]", "", value) for value in path_names}\n    filename_norm = {"filename", "file_name"}\n    filename_norm = {re.sub(r"[^a-z0-9]", "", value) for value in filename_norm}\n    endpoint_lower = endpoint.lower()\n    write_method = method in {"POST", "PUT", "PATCH"}\n    upload_route = any(token in endpoint_lower for token in ("/upload", "/uploads", "/attachment", "/attachments", "/avatar", "/document", "/documents"))\n    import_route = "/import" in endpoint_lower or endpoint_lower.rstrip("/").endswith("import")\n    download_route = any(token in endpoint_lower for token in ("/download", "/downloads", "/file", "/files", "/attachment", "/export"))\n    archive_route = any(token in endpoint_lower for token in ("/archive", "/zip", "/tar", "/extract", "/unpack"))\n    multipart = "multipart/form-data" in haystack or "multipart/form-data" in str(details.get("content_type") or "").lower()\n    generic_file_markers = _contains_any(haystack, ("upload", "attachment", "avatar", "document", "multipart", "filename", "file_name", "contenttype", "content_type", "import"))\n    file_fields = [original for normalized, original in normalized_fields.items() if normalized in file_input_norm]\n    path_fields_structured = [original for normalized, original in normalized_fields.items() if normalized in path_norm]\n    filename_fields = [original for normalized, original in normalized_fields.items() if normalized in filename_norm]\n\n    if generic_file_markers or file_fields or multipart or upload_route or import_route:\n        support: list[dict[str, Any]] = []\n        if generic_file_markers:\n            support.append({"type": "file_surface", "source": "semantic", "weight": 7, "text": f"File-related markers observed: {', '.join(generic_file_markers[:6])}"})\n        if file_fields:\n            support.append({"type": "file_input", "source": "schema", "weight": 20, "text": f"Structured file input observed: {', '.join(file_fields[:6])}"})\n        elif multipart and upload_route:\n            support.append({"type": "file_input", "source": "http_contract", "weight": 18, "text": "Multipart request semantics are tied to an explicit upload route"})\n        if multipart:\n            support.append({"type": "content_type_field", "source": "http_contract", "weight": 7, "text": "multipart/form-data semantics are present"})\n        elif "content_type" in haystack or "contenttype" in haystack:\n            support.append({"type": "content_type_field", "source": "semantic", "weight": 3, "text": "Content-Type metadata is present; this does not by itself establish file upload"})\n        if write_method and (upload_route or file_fields or multipart):\n            support.append({"type": "upload_operation", "source": "endpoint", "weight": 18, "text": f"{method} operation is tied to an upload-capable route or structured file input"})\n        if write_method and import_route:\n            support.append({"type": "import_operation", "source": "endpoint", "weight": 18, "text": f"{method} operation is tied to an import route"})\n        if write_method:\n            support.append({"type": "write_method", "source": "method", "weight": 5, "text": f"State-changing method observed: {method}"})\n        emit("file_upload", "file_validation", 18, support, [],\n             ["Allowed file types and size", "Storage and serving behavior", "Server-generated filenames and content disposition"],\n             ["candidate-file-surface", "candidate-file-validation", "admission-file-input-operation"],\n             "File-handling evidence is retained for correlation; promotion requires an actual file input plus upload/import operation.")\n\n    generic_path_markers = _contains_any(haystack, ("filepath", "file_path", "path", "directory", "folder", "download", "archive", "extract"))\n    if generic_path_markers or path_fields_structured or download_route or archive_route:\n        path_support: list[dict[str, Any]] = []\n        if generic_path_markers:\n            path_support.append({"type": "path_surface", "source": "semantic", "weight": 5, "text": f"Path/file markers observed: {', '.join(generic_path_markers[:6])}"})\n        if filename_fields:\n            path_support.append({"type": "filename_field", "source": "schema", "weight": 20, "text": f"Structured filename input observed: {', '.join(filename_fields[:5])}"})\n        structured_nonfilename = [value for value in path_fields_structured if value not in filename_fields]\n        if structured_nonfilename:\n            path_support.append({"type": "path_parameter", "source": "schema", "weight": 20, "text": f"Structured path input observed: {', '.join(structured_nonfilename[:5])}"})\n        if any(re.sub(r"[^a-z0-9]", "", value.lower()) == "storagepath" for value in path_fields_structured):\n            path_support.append({"type": "storage_path", "source": "schema", "weight": 18, "text": "Structured storage path field is client-visible"})\n        if method == "GET" and download_route:\n            path_support.append({"type": "download_operation", "source": "endpoint", "weight": 18, "text": "GET operation is tied to an explicit download/file route"})\n        if archive_route:\n            path_support.append({"type": "archive_operation", "source": "endpoint", "weight": 17, "text": "Archive/extract operation is visible in the endpoint"})\n        if write_method and import_route:\n            path_support.append({"type": "import_operation", "source": "endpoint", "weight": 16, "text": f"{method} import operation may consume a path or archive entry"})\n        if write_method and (upload_route or file_fields or multipart):\n            path_support.append({"type": "upload_operation", "source": "endpoint", "weight": 15, "text": f"{method} upload operation may consume a client-controlled filename"})\n        explicit_file_operation = download_route or archive_route or upload_route or import_route\n        if explicit_file_operation and method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:\n            path_support.append({"type": "file_operation", "source": "endpoint_contract", "weight": 10, "text": "Endpoint semantics identify an explicit file-related operation"})\n        emit("path_traversal", "path_construction", 16, path_support, [],\n             ["Path canonicalization", "Base-directory enforcement", "Whether user-controlled path data reaches filesystem APIs"],\n             ["candidate-path-input", "candidate-file-path", "admission-path-input-operation"],\n             "Path/file clues are retained for correlation; promotion requires structured path/filename control plus a file-relevant operation.")\n\n'''
replace_between("app/bug_candidates.py", "    # File handling\n", "    # Information exposure / headers\n", new_file_block)

# ---------------------------------------------------------------------------
# Security reasoning: align preconditions with admission and expose knowledge as
# context only, never evidence.
# ---------------------------------------------------------------------------
replace_once("app/security_reasoning.py", 'from analysis_audit import build_evidence_dossier, capture_evidence_snapshot, record_analysis_version, record_excluded_signal\n',
             'from analysis_audit import build_evidence_dossier, capture_evidence_snapshot, record_analysis_version, record_excluded_signal\nfrom hypothesis_admission import hypothesis_summary, knowledge_for_family\n')
replace_once("app/security_reasoning.py", 'REASONING_ENGINE_VERSION = "5.1.1"\nREASONING_RULE_VERSION = "2026.08.8.1"\n',
             'REASONING_ENGINE_VERSION = "5.2.0"\nREASONING_RULE_VERSION = "2026.08.8.3"\n')
replace_once(
    "app/security_reasoning.py",
    '        "required": [{"file_input", "upload_operation", "import_operation"}, {"state_change", "write_method", "endpoint_contract"}],\n',
    '        "required": [{"file_input"}, {"upload_operation", "import_operation"}],\n',
)
replace_once(
    "app/security_reasoning.py",
    '        "required": [{"path_parameter", "filename_field", "storage_path"}, {"file_operation", "download_operation", "import_operation"}],\n',
    '        "required": [{"path_parameter", "filename_field", "storage_path"}, {"file_operation", "download_operation", "import_operation", "archive_operation", "upload_operation"}],\n',
)
replace_once(
    "app/security_reasoning.py",
    '            "maturity_limiter": maturity_limiter,\n            "scores": {\n',
    '            "maturity_limiter": maturity_limiter,\n            "knowledge_context": {"role": "detection_guidance_only_not_target_evidence", "references": knowledge_for_family(family)},\n            "scores": {\n',
)
replace_once(
    "app/security_reasoning.py",
    '    return {"updated": updated, "strong_candidates": strong, "insufficient_evidence": insufficient, "evidence_records": int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"]), "shadow_rule_matches": shadow_matches, "evaluation": evaluation, "engine_version": REASONING_ENGINE_VERSION, "rule_version": REASONING_RULE_VERSION}\n',
    '    return {"updated": updated, "strong_candidates": strong, "insufficient_evidence": insufficient, "evidence_records": int((db.one("SELECT COUNT(*) count FROM evidence_records WHERE analysis_id=?", (analysis_id,)) or {"count": 0})["count"]), "shadow_rule_matches": shadow_matches, "hypotheses": hypothesis_summary(db, analysis_id), "evaluation": evaluation, "engine_version": REASONING_ENGINE_VERSION, "rule_version": REASONING_RULE_VERSION}\n',
)

# ---------------------------------------------------------------------------
# CLI: audit hidden hypotheses on demand; no dashboard navigation added.
# ---------------------------------------------------------------------------
replace_once(
    "app/recon_monitor.py",
    'analysis_cmd.add_argument("action", choices=["replay", "quality", "calibration", "feedback", "list", "show", "candidates", "candidate-show",',
    'analysis_cmd.add_argument("action", choices=["replay", "quality", "calibration", "feedback", "list", "show", "candidates", "hypotheses", "candidate-show",',
)
old_dispatch = '''            elif args.action == "candidates":\n                result = list_bug_candidates(db, analysis_id=args.analysis_id, target=args.target or "", family=args.family, state=args.state, limit=args.limit)\n            elif args.action == "candidate-show":\n'''
new_dispatch = '''            elif args.action == "candidates":\n                result = list_bug_candidates(db, analysis_id=args.analysis_id, target=args.target or "", family=args.family, state=args.state, limit=args.limit)\n            elif args.action == "hypotheses":\n                analysis_id = args.analysis_id\n                if not analysis_id:\n                    latest = db.one("SELECT id FROM analysis_runs WHERE status='success' ORDER BY finished_at DESC LIMIT 1")\n                    analysis_id = str(latest["id"]) if latest else ""\n                if not analysis_id:\n                    result = []\n                else:\n                    clauses = ["analysis_id=?"]; params: list[Any] = [analysis_id]\n                    if args.target:\n                        clauses.append("target=?"); params.append(args.target)\n                    if args.family:\n                        clauses.append("bug_family=?"); params.append(args.family)\n                    if args.state:\n                        clauses.append("state=?"); params.append(args.state)\n                    params.append(max(1, min(1000, args.limit)))\n                    result = [dict(row) for row in db.all("SELECT * FROM analysis_hypotheses WHERE " + " AND ".join(clauses) + " ORDER BY state='promoted' DESC,last_seen_at DESC LIMIT ?", tuple(params))]\n            elif args.action == "candidate-show":\n'''
replace_once("app/recon_monitor.py", old_dispatch, new_dispatch)

# ---------------------------------------------------------------------------
# Release-version contracts. These files intentionally assert the current app
# version/schema rather than historical migration versions.
# ---------------------------------------------------------------------------
for name in [
    "tests/test_workspace_v70.py",
    "tests/test_platform_v60.py",
    "tests/test_stability_v451.py",
    "tests/test_product_platform_v50.py",
    "tests/test_safe_validation_v51.py",
]:
    p = Path(name)
    text = p.read_text(encoding="utf-8")
    text = text.replace('"8.4.2"', '"8.4.3"').replace("'8.4.2'", "'8.4.3'")
    text = text.replace('(APP_VERSION, SCHEMA_VERSION, db.meta_get("schema_version")), ("8.4.3", 17, "17")', '(APP_VERSION, SCHEMA_VERSION, db.meta_get("schema_version")), ("8.4.3", 18, "18")')
    text = text.replace("(APP_VERSION, SCHEMA_VERSION, db.meta_get('schema_version')), ('8.4.3', 17, '17')", "(APP_VERSION, SCHEMA_VERSION, db.meta_get('schema_version')), ('8.4.3', 18, '18')")
    text = text.replace('self.assertEqual(SCHEMA_VERSION, 17)', 'self.assertEqual(SCHEMA_VERSION, 18)')
    text = text.replace('self.assertEqual(db.meta_get("schema_version"), "17")', 'self.assertEqual(db.meta_get("schema_version"), "18")')
    text = text.replace("self.assertEqual(db.meta_get('schema_version'), '17')", "self.assertEqual(db.meta_get('schema_version'), '18')")
    p.write_text(text, encoding="utf-8")

print("v8.4.3 recall-preserving admission patch applied")
