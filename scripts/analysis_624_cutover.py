from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


module = '''from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from core import Database, parse_int
from family_detectors.registry import DETECTOR_SPECS

STATIC_SPECIALIZED_COLLECTOR_VERSION = "1.0.0"
STATIC_SPECIALIZED_COLLECTOR_RULE_VERSION = "2026.08.12.6.24"
STATIC_SPECIALIZED_FAMILIES = (
    "source_map_exposure",
    "secret_exposure",
    "graphql_authorization",
    "graphql_data_exposure",
    "websocket_authorization",
)


@dataclass(frozen=True)
class StaticFamilyObservation:
    target: str
    endpoint: str
    source_ref: str
    family: str
    variant: str
    likelihood: int
    evidence_strength: int
    impact: int
    support: tuple[dict[str, Any], ...]
    contradict: tuple[dict[str, Any], ...]
    missing: tuple[str, ...]
    rules: tuple[str, ...]
    summary: str


def _clamp(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _strength(confidence: int, support: list[dict[str, Any]], contradict: list[dict[str, Any]], *, direct: bool = False) -> int:
    sources = {str(item.get("source") or item.get("type") or "rule") for item in support}
    value = 18 + min(32, confidence * 0.34) + min(30, len(support) * 8) + min(12, len(sources) * 4)
    if direct:
        value += 12
    value -= min(16, len(contradict) * 4)
    return _clamp(value, 10, 96)


def _list_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def validate_static_specialized_collectors() -> list[str]:
    errors: list[str] = []
    for family in STATIC_SPECIALIZED_FAMILIES:
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if not spec.wstg_ids:
            errors.append(f"static detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"static detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"static detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"static detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"static detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"static detector lacks condition contract: {family}")
    return errors


def collect_specialized_static_observations(db: Database, analysis_id: str, target: str | None = None) -> list[StaticFamilyObservation]:
    errors = validate_static_specialized_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.24 specialized static registry: " + "; ".join(errors))

    observations: list[StaticFamilyObservation] = []
    params: list[Any] = [analysis_id]
    target_clause = ""
    if target:
        target_clause = " AND target=?"
        params.append(target)

    for row in db.all(f"SELECT * FROM source_map_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        internal_count = parse_int(row["internal_source_count"], 0)
        if internal_count <= 0:
            continue
        support = [
            {"type": "source_map", "source": "source_map_intelligence", "source_group": "source_map_surface", "weight": 22, "text": f"Referenced source map contains {parse_int(row['source_count'],0)} source entries."},
            {"type": "internal_sources", "source": "source_map_intelligence", "source_group": "source_map_contents", "weight": 16, "text": f"{internal_count} internal-looking source paths were identified in stored source-map intelligence."},
        ]
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint=str(row["source_map_url"]), source_ref=f"source-map:{row['js_url']}",
            family="source_map_exposure", variant="internal_source_paths", likelihood=62, evidence_strength=78, impact=52,
            support=tuple(support), contradict=(),
            missing=("Verified public reachability of the source-map URL", "Whether sourcesContent or equivalent meaningful original source is exposed"),
            rules=("static-collector-specialized-v1", "candidate-source-map", "candidate-internal-source-path"),
            summary="A referenced source map contains internal-looking source metadata; promotion still requires meaningful source content and verified public reachability.",
        ))

    for row in db.all(f"SELECT * FROM secret_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        assessment = str(row["assessment"]); confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "secret_pattern", "source": "secret_intelligence", "source_group": "secret_pattern", "weight": 26, "text": f"A redacted {row['secret_kind']} pattern was detected in production JavaScript."},
            {"type": "production_javascript", "source": "secret_intelligence", "source_group": "client_context", "weight": 10, "text": "The redacted secret-like material was observed in client-delivered JavaScript."},
        ]
        contradict: list[dict[str, Any]] = []
        if assessment == "likely_placeholder":
            contradict.append({"type": "placeholder", "source": "secret_intelligence", "source_group": "secret_assessment", "weight": -24, "text": "Stored secret intelligence classifies the value as a likely example/test/placeholder."})
        else:
            support.append({"type": "non_placeholder_secret", "source": "secret_intelligence", "source_group": "secret_assessment", "weight": 18, "text": "Secret intelligence did not classify the redacted value as a known placeholder."})
        likelihood = _clamp(24 + confidence * 0.5 + sum(parse_int(x.get("weight"), 0) for x in contradict))
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint=str(row["js_url"]), source_ref=f"secret:{row['js_url']}:{row['value_fingerprint']}",
            family="secret_exposure", variant=str(row["secret_kind"]), likelihood=likelihood,
            evidence_strength=_strength(confidence, support, contradict, direct=True), impact=90,
            support=tuple(support), contradict=tuple(contradict),
            missing=("Whether the credential remains live", "Intended exposure and privilege", "Rotation or revocation status"),
            rules=("static-collector-specialized-v1", "candidate-secret-pattern", "candidate-client-secret"),
            summary="A redacted credential- or token-like value appears in production client JavaScript; no online credential validation is performed.",
        ))

    for row in db.all(f"SELECT * FROM graphql_intelligence WHERE analysis_id=?{target_clause}", tuple(params)):
        identifiers = [str(x) for x in _list_json(row["identifiers_json"])]
        sensitive = [str(x) for x in _list_json(row["sensitive_fields_json"])]
        confidence = parse_int(row["confidence"], 0)
        if identifiers:
            support = [
                {"type": "graphql_identifier", "source": "graphql_intelligence", "source_group": "graphql_identifier", "weight": 20, "text": f"GraphQL object identifiers observed: {', '.join(identifiers[:6])}."},
                {"type": "graphql_operation", "source": "graphql_intelligence", "source_group": "graphql_operation", "weight": 12, "text": f"Client-visible {row['operation_type']} operation is stored in GraphQL intelligence."},
            ]
            observations.append(StaticFamilyObservation(
                target=str(row["target"]), endpoint="/graphql", source_ref=f"graphql:{row['js_url']}:{row['operation_name']}",
                family="graphql_authorization", variant="object_boundary",
                likelihood=_clamp(32 + confidence * 0.35 + len(identifiers) * 3),
                evidence_strength=_strength(confidence, support, [], direct=True), impact=80,
                support=tuple(support), contradict=(),
                missing=("Resolver-level authorization failure evidence", "Expected object ownership/tenant boundary", "Controlled cross-identity or cross-tenant response comparison"),
                rules=("static-collector-specialized-v1", "candidate-graphql-identifier", "candidate-graphql-authorization"),
                summary="A client-visible GraphQL operation accepts object identifiers; resolver/object authorization failure remains unproven.",
            ))
        if sensitive:
            support = [
                {"type": "sensitive_fields", "source": "graphql_intelligence", "source_group": "graphql_fields", "weight": 20, "text": f"Sensitive GraphQL fields observed: {', '.join(sensitive[:8])}."},
                {"type": "client_operation", "source": "graphql_intelligence", "source_group": "graphql_operation", "weight": 10, "text": "Sensitive fields are referenced by a stored client GraphQL operation."},
            ]
            observations.append(StaticFamilyObservation(
                target=str(row["target"]), endpoint="/graphql", source_ref=f"graphql-data:{row['js_url']}:{row['operation_name']}",
                family="graphql_data_exposure", variant="sensitive_fields",
                likelihood=_clamp(24 + confidence * 0.32 + len(sensitive) * 2),
                evidence_strength=_strength(confidence, support, [], direct=True), impact=68,
                support=tuple(support), contradict=(),
                missing=("Actual response data for the current role", "Field-level authorization policy", "Evidence that sensitive fields cross the intended field policy"),
                rules=("static-collector-specialized-v1", "candidate-graphql-sensitive-field", "candidate-graphql-data"),
                summary="A GraphQL operation references sensitive fields; actual response exposure beyond the caller's field policy remains unproven.",
            ))

    ws_params: list[Any] = [analysis_id]
    ws_clause = ""
    if target:
        ws_clause = " AND target=?"
        ws_params.append(target)
    for row in db.all(f"SELECT * FROM js_dataflows WHERE analysis_id=? AND sink_kind='websocket'{ws_clause}", tuple(ws_params)):
        confidence = parse_int(row["confidence"], 0)
        support = [
            {"type": "websocket_url", "source": "javascript_dataflow", "source_group": "websocket_surface", "weight": 14, "text": "Stored JavaScript data-flow intelligence reaches WebSocket construction/messaging."},
        ]
        observations.append(StaticFamilyObservation(
            target=str(row["target"]), endpoint="", source_ref=f"js-dataflow:{row['js_url']}:{row['source_kind']}:websocket",
            family="websocket_authorization", variant="client_channel_construction",
            likelihood=_clamp(28 + confidence * 0.45 + 6), evidence_strength=_strength(confidence, support, [], direct=True), impact=76,
            support=tuple(support), contradict=({"type": "static_only", "source": "analysis_limit", "source_group": "static_limit", "weight": -8, "text": "Static WebSocket construction does not prove channel identity scope or subscription authorization failure."},),
            missing=("Actual channel/room/tenant identity relation", "Subscription/message authorization behavior", "Controlled out-of-scope subscription or message evidence"),
            rules=("static-collector-specialized-v1", "candidate-js-websocket", "candidate-websocket-authorization"),
            summary="Client JavaScript constructs or feeds a WebSocket channel surface; channel/identity authorization failure remains unproven.",
        ))

    return observations
'''
(ROOT / "app" / "static_family_collectors.py").write_text(module, encoding="utf-8")

# Replace weak/generic write-up locations with exact relevant vulnerability records.
(ROOT / "app" / "family_detectors" / "source_map_exposure.py").write_text('''from .base import make_spec, writeup
SPEC = make_spec(
    family="source_map_exposure", strategy="public_internal_source_map",
    surface_terms=("sourcemappingurl",".map","sourcescontent","webpack://","source map"),
    surface_fields=("sourceMappingURL","sources","sourcesContent"),
    confounders=("information_disclosure","secret_exposure"),
    expected_wstg=("WSTG-CONF-04",), expected_cwe=("CWE-200",),
    writeups=(
        writeup(
            "CVE-2024-27257 / IBM OpenPages JavaScript source-map information exposure",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27257",
            "exact",
            "Source-map presence is not sufficient; promotion requires source-map content that discloses meaningful client source information to an unauthorized or unintended audience.",
            source="NVD / IBM vulnerability record",
        ),
    ),
)
''', encoding="utf-8")

(ROOT / "app" / "family_detectors" / "graphql_authorization.py").write_text('''from .base import make_spec, writeup
SPEC = make_spec(
    family="graphql_authorization", strategy="graphql_resolver_authorization",
    surface_terms=("graphql","query","mutation","resolver","node id","relay"),
    surface_fields=("id","nodeId","userId","tenantId","operationName"),
    confounders=("broken_object_authorization","broken_function_authorization","graphql_data_exposure"),
    expected_wstg=("WSTG-APIT-02","WSTG-ATHZ-02"), expected_cwe=("CWE-862","CWE-863"),
    writeups=(
        writeup(
            "GHSL-2025-130 / Sentry cross-organization object authorization failure",
            "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/",
            "adjacent_primary_case",
            "GraphQL transport does not change the authorization condition: an object identifier is only a surface until the resolver/object lookup is shown to escape the caller's organization, tenant, or ownership boundary.",
        ),
    ),
)
''', encoding="utf-8")

(ROOT / "app" / "family_detectors" / "websocket_authorization.py").write_text('''from .base import make_spec, writeup
SPEC = make_spec(
    family="websocket_authorization", strategy="channel_identity_boundary",
    surface_terms=("websocket","ws://","wss://","subscribe","channel","room","ddp","socket"),
    surface_fields=("channel","room","topic","user_id","tenant_id","boardId"),
    confounders=("graphql_authorization","broken_object_authorization","authentication_session"),
    expected_wstg=("WSTG-CLNT-10","WSTG-ATHZ-02"), expected_cwe=("CWE-862","CWE-863"),
    writeups=(
        writeup(
            "GHSL-2025-118 / Outline suspended-user WebSocket authentication bypass",
            "https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/",
            "exact",
            "Realtime authorization must hold when the connection/subscription is used; WebSocket construction or an authenticated handshake alone does not prove authorization to every channel, message, or identity scope.",
        ),
    ),
)
''', encoding="utf-8")

bug_path = ROOT / "app" / "bug_candidates.py"
replace_once(
    bug_path,
    'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations\n',
    'from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations\nfrom static_family_collectors import collect_specialized_static_observations\n',
)
text = bug_path.read_text(encoding="utf-8")
# WebSocket family ownership moves out of the generic JS data-flow block; client-side static flows remain supplemental for the already-physical client families.
ws_branch = '''        elif sink == "websocket":
            family, variant = "websocket_authorization", "client_channel_construction"
            summary = "User-influenced data appears in WebSocket construction or messaging; channel authorization remains unknown."
'''
if text.count(ws_branch) != 1:
    raise RuntimeError("6.24 websocket static branch drift")
text = text.replace(ws_branch, "", 1)
start = text.find("    # Source maps.\n")
end = text.find("    return count\n", start)
if start < 0 or end < 0:
    raise RuntimeError("6.24 specialized static legacy block boundaries not found")
replacement = '''    # Analysis 6.24 — specialized static family ownership for Source Map, Secret,
    # GraphQL authorization/data exposure, and WebSocket authorization. Evidence is
    # extracted only from persisted static-intelligence rows; standards/write-ups are
    # detector knowledge and are never inserted as target evidence.
    for observation in collect_specialized_static_observations(db, analysis_id, target):
        candidate_id = _insert_candidate(
            db, analysis_id=analysis_id, source_run_id=run_id, target=observation.target,
            alert_id=None, asset="", endpoint=observation.endpoint, source_ref=observation.source_ref,
            family=observation.family, variant=observation.variant,
            likelihood=observation.likelihood, evidence_strength=observation.evidence_strength,
            impact_potential=observation.impact, support=[dict(item) for item in observation.support],
            contradict=[dict(item) for item in observation.contradict], missing=list(observation.missing),
            rule_ids=list(observation.rules), summary=observation.summary,
        )
        if candidate_id:
            count += 1

'''
text = text[:start] + replacement + text[end:]
bug_path.write_text(text, encoding="utf-8")


test = '''from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from bug_candidates import _static_candidates
from core import AppPaths, Database, json_dumps, utc_now
from family_detectors import evaluate_family_detector, get_detector_spec
from hypothesis_admission import assess_admission
from static_family_collectors import STATIC_SPECIALIZED_FAMILIES, collect_specialized_static_observations, validate_static_specialized_collectors


class SpecializedStaticCollectors6240Tests(unittest.TestCase):
    def _seed(self, db: Database, analysis_id: str, run_id: str, target: str) -> None:
        now = utc_now()
        db.execute("INSERT OR REPLACE INTO source_map_intelligence(analysis_id,target,run_id,js_url,source_map_url,source_count,internal_source_count,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","https://fixture.invalid/app.js.map",12,3,json_dumps(["src/auth.ts","src/api.ts","src/admin.ts"]),now))
        db.execute("INSERT OR REPLACE INTO secret_intelligence(analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","api_key","deadbeefcafefeed1234",82,"candidate",json_dumps(["redacted production indicator"]),now))
        db.execute("INSERT OR REPLACE INTO graphql_intelligence(analysis_id,target,run_id,js_url,operation_name,operation_type,identifiers_json,sensitive_fields_json,confidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","query User($userId: ID!) { user(id:$userId){ email token } }","query",json_dumps(["userId"]),json_dumps(["user","token"]),88,now))
        db.execute("INSERT OR REPLACE INTO js_dataflows(analysis_id,target,run_id,js_url,source_kind,sink_kind,confidence,snippet,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (analysis_id,target,run_id,"https://fixture.invalid/app.js","location.search","websocket",70,"const ws = new WebSocket(url)",now))

    def test_exact_registry_and_four_layer_grounding(self):
        self.assertEqual(set(STATIC_SPECIALIZED_FAMILIES), {"source_map_exposure","secret_exposure","graphql_authorization","graphql_data_exposure","websocket_authorization"})
        self.assertEqual(validate_static_specialized_collectors(), [])
        for family in STATIC_SPECIALIZED_FAMILIES:
            spec = get_detector_spec(family)
            self.assertTrue(spec.wstg_ids, family)
            self.assertTrue(spec.owasp_ids, family)
            self.assertTrue(spec.cwe_ids, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(spec.condition_signals, family)
            self.assertTrue(all(ref.url.startswith("https://") for ref in spec.writeups), family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)
        self.assertEqual(get_detector_spec("source_map_exposure").writeups[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2024-27257")
        self.assertEqual(get_detector_spec("source_map_exposure").writeups[0].relation, "exact")
        self.assertEqual(get_detector_spec("graphql_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-130_Sentry/")
        self.assertEqual(get_detector_spec("websocket_authorization").writeups[0].url, "https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/")

    def test_collector_emits_all_five_from_persisted_static_intelligence(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self._seed(db, "analysis-624", "run-624", "fixture.invalid")
                rows = collect_specialized_static_observations(db, "analysis-624", "fixture.invalid")
                self.assertEqual({row.family for row in rows}, set(STATIC_SPECIALIZED_FAMILIES))
                self.assertTrue(all("static-collector-specialized-v1" in row.rules for row in rows))
                self.assertTrue(all(row.support for row in rows))
            finally:
                db.close()

    def test_static_surfaces_do_not_promote_authorization_or_data_exposure_without_conditions(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                self._seed(db, "analysis-624", "run-624", "fixture.invalid")
                rows = collect_specialized_static_observations(db, "analysis-624", "fixture.invalid")
                by_family = {row.family: row for row in rows}
                for family in ("source_map_exposure", "graphql_authorization", "graphql_data_exposure", "websocket_authorization"):
                    row = by_family[family]
                    extraction = evaluate_family_detector(family, row.support, row.contradict, channel="candidate")
                    assessment = assess_admission(family, extraction["support"], extraction["contradict"])
                    self.assertFalse(assessment["admitted"], (family, assessment, extraction))
                secret = by_family["secret_exposure"]
                extraction = evaluate_family_detector("secret_exposure", secret.support, secret.contradict, channel="candidate")
                self.assertTrue(assess_admission("secret_exposure", extraction["support"], extraction["contradict"])["admitted"])
            finally:
                db.close()

    def test_placeholder_secret_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                now = utc_now(); aid="analysis-624-placeholder"; target="fixture.invalid"
                db.execute("INSERT OR REPLACE INTO secret_intelligence(analysis_id,target,run_id,js_url,secret_kind,value_fingerprint,confidence,assessment,reasons_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (aid,target,"run","https://fixture.invalid/app.js","api_key","placeholder",20,"likely_placeholder",json_dumps(["placeholder"]),now))
                row = collect_specialized_static_observations(db, aid, target)[0]
                extraction = evaluate_family_detector("secret_exposure", row.support, row.contradict, channel="candidate")
                assessment = assess_admission("secret_exposure", extraction["support"], extraction["contradict"])
                self.assertFalse(assessment["admitted"], (assessment, extraction))
                self.assertIn("placeholder", {str(x.get("type") or "") for x in extraction["contradict"]})
            finally:
                db.close()

    def test_orchestrator_physically_removes_specialized_static_blocks(self):
        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")
        self.assertIn("collect_specialized_static_observations(db, analysis_id, target)", source)
        self.assertNotIn("# Source maps.", source)
        self.assertNotIn("# Secret candidates.", source)
        self.assertNotIn("# GraphQL operations.", source)
        self.assertNotIn('elif sink == "websocket":', source)

    def test_static_pipeline_records_grounded_hypotheses_and_secret_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            paths = AppPaths.from_root(Path(td)); paths.ensure(); db = Database(paths.db)
            try:
                aid="analysis-624-pipeline"; run="run-624-pipeline"; target="fixture.invalid"
                self._seed(db, aid, run, target)
                _static_candidates(db, aid, run, target)
                hypotheses = db.all("SELECT bug_family,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?", (aid,))
                hidden = {str(row["bug_family"]) for row in hypotheses if "static-collector-specialized-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertTrue({"source_map_exposure","graphql_authorization","graphql_data_exposure","websocket_authorization"}.issubset(hidden), hypotheses)
                candidates = db.all("SELECT bug_family,rule_ids_json FROM bug_candidates WHERE analysis_id=?", (aid,))
                specialized = {str(row["bug_family"]) for row in candidates if "static-collector-specialized-v1" in json.loads(row["rule_ids_json"] or "[]")}
                self.assertIn("secret_exposure", specialized, candidates)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
'''
(ROOT / "tests" / "test_specialized_static_collectors_v6240.py").write_text(test, encoding="utf-8")

doc = '''# Analysis Engine 6.24 — Specialized Static Physical Collectors

Analysis 6.24 physically decomposes the remaining static-family ownership from `bug_candidates._static_candidates()` for Source Map Exposure, Secret Exposure, GraphQL Authorization, GraphQL Data Exposure, and WebSocket Authorization.

Unlike the raw collectors, these collectors legitimately extract target evidence from persisted static-intelligence tables (`source_map_intelligence`, `secret_intelligence`, `graphql_intelligence`, and `js_dataflows`). WSTG, OWASP, CWE, and write-ups remain knowledge only and never become target evidence.

Promotion boundaries remain strict:

- Source maps: a `.map` reference or internal-looking paths remain a hypothesis until meaningful source content and verified public reachability are present. Grounding includes WSTG-CONF-04, OWASP A01:2025, CWE-200, and CVE-2024-27257 (IBM OpenPages source-map information exposure).
- Secrets: a redacted pattern in production client JavaScript requires non-placeholder credential evidence; placeholder classification blocks promotion. Grounding includes WSTG-CONF-04, OWASP A07:2025, CWE-798/CWE-200, and GHSL-2026-037 Wekan.
- GraphQL authorization: operation + identifier are only surfaces; resolver/object authorization failure is required. Grounding includes WSTG-APIT-02/ATHZ-02, API1:2023/A01:2025, CWE-862/863, and the concrete Sentry cross-organization authorization failure GHSL-2025-130 as an adjacent object-boundary case.
- GraphQL data exposure: sensitive fields in client operations are schema clues only; actual data crossing the caller's field policy is required. Grounding includes WSTG-APIT-03, API3:2023/A01:2025, CWE-200, and GHSL-2026-035 Wekan.
- WebSocket authorization: WebSocket construction is only a channel surface; channel/identity scope plus observed authorization failure is required. Grounding includes WSTG-CLNT-10/ATHZ-02, A01:2025, CWE-862/863, and the exact GHSL-2025-118 Outline WebSocket authentication-bypass case.

No active subscription, credential validation, object probing, cross-tenant access, or network requests are introduced by this change.
'''
(ROOT / "docs" / "ANALYSIS_ENGINE_6_24_SPECIALIZED_STATIC_COLLECTORS.md").write_text(doc, encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
entries: set[str] = set()
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.add(rel.strip())
entries.update({"app/static_family_collectors.py", "tests/test_specialized_static_collectors_v6240.py", "docs/ANALYSIS_ENGINE_6_24_SPECIALIZED_STATIC_COLLECTORS.md"})
manifest.write_text("\n".join(f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(entries)) + "\n", encoding="utf-8")
