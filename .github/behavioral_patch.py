from __future__ import annotations

import hashlib
from pathlib import Path


behavioral_path = Path("app/behavioral_intelligence.py")
text = behavioral_path.read_text(encoding="utf-8")
start = text.index("\ndef generate_behavioral_candidates(")
end = text.index("\ndef behavioral_summary(", start)
replacement = '''
def generate_behavioral_candidates(db: Database, analysis_id: str, run_id: str) -> dict[str, int]:
    """Route behavioral observations through canonical hypothesis admission.

    Behavioral diffs are valuable target context, but a boundary transition,
    response-shape change, or protocol heuristic is not itself a vulnerability
    condition. Preserve those observations in the hypothesis ledger and create
    a Candidate only when the canonical Family Reasoning contract admits the
    combined target-specific evidence.
    """
    # Import lazily to avoid module cycles during CLI startup.
    from bug_candidates import BUG_FAMILIES, _insert_candidate
    from hypothesis_admission import mark_promoted, record_hypothesis

    counts = Counter()

    def emit(
        *,
        target: str,
        endpoint: str,
        source_ref: str,
        family: str,
        variant: str,
        likelihood: int,
        evidence_strength: int,
        impact_potential: int,
        support: list[dict[str, Any]],
        contradict: list[dict[str, Any]],
        missing: list[str],
        rule_ids: list[str],
        summary: str,
    ) -> bool:
        hypothesis = record_hypothesis(
            db,
            analysis_id=analysis_id,
            source_run_id=run_id,
            target=target,
            alert_id=None,
            asset="",
            endpoint=endpoint,
            source_ref=source_ref,
            family=family,
            variant=variant,
            support=support,
            contradict=contradict,
            missing=missing,
            rule_ids=rule_ids,
            summary=summary,
        )
        assessment = hypothesis["assessment"]
        if not bool(assessment.get("admitted")):
            return False

        admitted_support = list(hypothesis["support"])
        admitted_contradict = list(hypothesis["contradict"])
        admitted_missing = list(hypothesis["missing"])
        admitted_rules = list(hypothesis["rule_ids"])
        independent = {
            str(item.get("source_group") or item.get("source") or item.get("type") or "rule")
            for item in admitted_support
        }
        if len(admitted_support) < 2 or len(independent) < 2:
            return False

        candidate_id = _insert_candidate(
            db,
            analysis_id=analysis_id,
            source_run_id=run_id,
            target=target,
            alert_id=None,
            asset="",
            endpoint=endpoint,
            source_ref=source_ref,
            family=family,
            variant=variant,
            likelihood=likelihood,
            evidence_strength=evidence_strength,
            impact_potential=impact_potential,
            support=admitted_support,
            contradict=admitted_contradict,
            missing=admitted_missing,
            rule_ids=admitted_rules,
            summary=summary,
        )
        mark_promoted(db, analysis_id, hypothesis["hypothesis_fingerprint"], candidate_id)
        counts[family] += 1
        return True

    boundary_rows = db.all(
        "SELECT * FROM authentication_boundary_diffs WHERE analysis_id=? AND transition='boundary_regression'",
        (analysis_id,),
    )
    for row in boundary_rows:
        endpoint = str(row["endpoint"])
        support = [
            {"type": "authentication_boundary_regression", "source": "behavioral_diff", "source_group": "behavioral_boundary", "weight": 30, "text": f"Stored boundary changed from {row['previous_boundary']} to {row['current_boundary']}"},
            {"type": "cross_run_confirmation", "source": "analysis_history", "source_group": "temporal", "weight": 14, "text": f"The transition was observed across analysis runs {row['previous_analysis_id']} and {analysis_id}"},
        ]
        emit(
            target=str(row["target"]), endpoint=endpoint,
            source_ref=f"boundary-diff:{analysis_id}:{sha256_text(endpoint)[:12]}",
            family="authentication_session", variant="boundary_regression",
            likelihood=_clamp(58 + parse_int(row["confidence"], 0) * 0.35),
            evidence_strength=_clamp(58 + parse_int(row["confidence"], 0) * 0.32),
            impact_potential=BUG_FAMILIES["authentication_session"]["impact"], support=support,
            contradict=[{"type": "stored_observation_only", "source": "safety", "source_group": "validation", "weight": -5, "text": "No active validation was performed; the transition may reflect routing, deployment or observation context."}],
            missing=["Expected anonymous and authenticated behavior", "Whether response content changed with the boundary", "Scope-authorized reproduction context"],
            rule_ids=["behavioral-auth-boundary-regression"],
            summary="Stored observations suggest an authentication boundary became more permissive. This remains a behavioral hypothesis until family-specific vulnerability evidence exists.",
        )

    shape_rows = db.all(
        "SELECT * FROM response_shape_diffs WHERE analysis_id=? AND transition IN ('protected_to_data','error_to_data','sensitive_expansion')",
        (analysis_id,),
    )
    for row in shape_rows:
        endpoint = str(row["endpoint"])
        sensitive = _loads(row["sensitive_added_json"], [])
        support = [
            {"type": "structural_response_diff", "source": "behavioral_diff", "source_group": "response_shape", "weight": 24, "text": f"Stored response shape transition: {row['transition']}"},
            {"type": "cross_run_confirmation", "source": "analysis_history", "source_group": "temporal", "weight": 12, "text": "The structural change was calculated across two stored analysis runs"},
        ]
        if sensitive:
            support.append({"type": "sensitive_fields_added", "source": "response_shape", "source_group": "sensitive_shape", "weight": 20, "text": f"Sensitive-looking fields appeared: {', '.join(map(str, sensitive[:8]))}"})
        emit(
            target=str(row["target"]), endpoint=endpoint,
            source_ref=f"shape-diff:{analysis_id}:{sha256_text(endpoint)[:12]}",
            family="information_disclosure", variant=str(row["transition"]),
            likelihood=_clamp(45 + parse_int(row["confidence"], 0) * 0.38 + (8 if sensitive else 0)),
            evidence_strength=_clamp(48 + parse_int(row["confidence"], 0) * 0.38),
            impact_potential=BUG_FAMILIES["information_disclosure"]["impact"] + (8 if sensitive else 0), support=support,
            contradict=[{"type": "shape_not_value", "source": "safety", "source_group": "validation", "weight": -4, "text": "Only redacted structure was compared; field values and intended disclosure are unknown."}],
            missing=["Intended public response schema", "Authentication context for both observations", "Whether added fields contain real sensitive data"],
            rule_ids=["behavioral-structural-response-diff"],
            summary="The stored response structure became more data-rich or exposed sensitive-looking fields. This remains a behavioral hypothesis until actual sensitive visibility is established.",
        )

    protocol_rows = db.all(
        "SELECT * FROM protocol_findings WHERE analysis_id=? AND severity IN ('high','critical')",
        (analysis_id,),
    )
    for row in protocol_rows:
        protocol = str(row["protocol"])
        kind = str(row["kind"])
        family = "websocket_authorization" if protocol == "websocket" else "graphql_authorization" if protocol == "graphql" else "sensitive_caching" if protocol == "cache" else "open_redirect" if protocol == "oauth_oidc" and "callback" in kind else ""
        if not family:
            continue
        if family in {"graphql_authorization", "websocket_authorization", "sensitive_caching"}:
            continue
        support = [
            {"type": "protocol_specific_finding", "source": f"{protocol}_engine", "source_group": protocol, "weight": 22, "text": str(row["summary"])},
            {"type": "stored_protocol_evidence", "source": "semantic_intelligence", "source_group": "protocol_evidence", "weight": 10, "text": "The finding is based on stored protocol-specific evidence"},
        ]
        emit(
            target=str(row["target"]), endpoint=str(row["entity"]),
            source_ref=f"protocol:{row['finding_id']}", family=family, variant=kind,
            likelihood=_clamp(35 + parse_int(row["confidence"], 0) * 0.42),
            evidence_strength=_clamp(40 + parse_int(row["confidence"], 0) * 0.35),
            impact_potential=BUG_FAMILIES[family]["impact"], support=support,
            contradict=[{"type": "no_active_validation", "source": "safety", "source_group": "validation", "weight": -6, "text": "No active protocol validation was performed."}],
            missing=["Expected protocol policy", "Authorized behavioral comparison", "Server-side enforcement evidence"],
            rule_ids=[f"behavioral-protocol-{protocol}-{kind}"],
            summary=f"The {protocol} engine produced high-priority stored protocol context. It remains a hypothesis until the family evidence contract is satisfied.",
        )
    return dict(counts)

'''
behavioral_path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


test_path = Path("tests/test_behavioral_v45.py")
test_text = test_path.read_text(encoding="utf-8")
old_start = test_text.index("    def test_behavioral_candidates_are_unverified_and_capped(self):")
old_end = test_text.index("    def test_behavioral_summary_and_dashboard_route(self):", old_start)
test_replacement = '''    def test_behavioral_diffs_are_hidden_until_family_admission(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                candidates = [dict(row) for row in db.all(
                    "SELECT * FROM bug_candidates WHERE analysis_id=? AND (source_ref LIKE 'boundary-diff:%' OR source_ref LIKE 'shape-diff:%' OR source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                self.assertEqual(candidates, [])

                hypotheses = [dict(row) for row in db.all(
                    "SELECT * FROM analysis_hypotheses WHERE analysis_id=? AND (source_ref LIKE 'boundary-diff:%' OR source_ref LIKE 'shape-diff:%' OR source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                self.assertGreaterEqual(len(hypotheses), 2)
                families = {row["bug_family"] for row in hypotheses}
                self.assertIn("authentication_session", families)
                self.assertIn("information_disclosure", families)
                for row in hypotheses:
                    admission = json.loads(row["admission_json"])
                    self.assertFalse(admission["admitted"], row["bug_family"])
                    self.assertNotEqual(row["state"], "promoted")
            finally:
                db.close()

    def test_behavioral_candidate_paths_cannot_bypass_admission(self):
        with tempfile.TemporaryDirectory() as td:
            paths, db, _, _, second = self.fixture(td)
            try:
                rows = [dict(row) for row in db.all(
                    "SELECT c.candidate_id,c.source_ref,h.admission_json,h.state "
                    "FROM bug_candidates c LEFT JOIN analysis_hypotheses h "
                    "ON h.analysis_id=c.analysis_id AND h.promoted_candidate_id=c.candidate_id "
                    "WHERE c.analysis_id=? AND (c.source_ref LIKE 'boundary-diff:%' OR c.source_ref LIKE 'shape-diff:%' OR c.source_ref LIKE 'protocol:%')",
                    (second["analysis_id"],),
                )]
                for row in rows:
                    self.assertTrue(row["admission_json"], row["candidate_id"])
                    admission = json.loads(row["admission_json"])
                    self.assertTrue(admission["admitted"], row["candidate_id"])
                    self.assertEqual(row["state"], "promoted")
            finally:
                db.close()

'''
test_path.write_text(test_text[:old_start] + test_replacement + test_text[old_end:], encoding="utf-8")


# Update hashes for changed tracked files without changing manifest coverage.
manifest = Path("MANIFEST.sha256")
lines = manifest.read_text(encoding="utf-8").splitlines()
hashes = {
    p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (behavioral_path, test_path)
}
seen: set[str] = set()
out: list[str] = []
for line in lines:
    replaced = False
    for rel, digest in hashes.items():
        if line.endswith("  " + rel):
            out.append(f"{digest}  {rel}")
            seen.add(rel)
            replaced = True
            break
    if not replaced:
        out.append(line)
missing = set(hashes) - seen
if missing:
    raise SystemExit(f"Manifest entries missing for changed files: {sorted(missing)}")
manifest.write_text("\n".join(out) + "\n", encoding="utf-8")

# One-shot automation artifacts must not remain in the final branch.
Path(".github/workflows/behavioral-admission-patch.yml").unlink(missing_ok=True)
Path(".github/behavioral_patch.py").unlink(missing_ok=True)
