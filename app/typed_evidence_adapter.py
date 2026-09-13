from __future__ import annotations

"""Offline adapter from Validation Runner observations to canonical target evidence.

The passive-live executor remains observation-only. This module is the explicit
bridge that validates a completed execution artifact, derives a small set of
family-scoped typed signals, persists provenance-preserving ``evidence_records``,
and feeds those signals back through the existing hypothesis/admission path.

Safety/trust properties:
- no network transport is imported or invoked here;
- only completed, fresh, redacted Validation Runner executions are accepted;
- one execution is one evidence root, regardless of how many derived signals it
  contains, so a single request sequence cannot satisfy an independent-source
  requirement by itself;
- execution application is idempotent and artifact mutation after application
  fails closed;
- adapters never mark a vulnerability confirmed. Canonical Family Reasoning and
  Admission remain the only authority that can admit/promote a Potential Finding.
"""

import datetime as dt
import json
from pathlib import Path
from typing import Any, Mapping

from core import Database, ReconError, json_dumps, sha256_text, utc_now
from family_reasoning import FAMILY_REASONING


TYPED_EVIDENCE_ADAPTER_VERSION = "1.0.0"
TYPED_EVIDENCE_ADAPTER_RULE_VERSION = "2026.09.14.1"
TYPED_EVIDENCE_ADAPTER_SCHEMA_VERSION = 1
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
ADAPTER_CONFIDENCE_CEILING = 85
ADAPTER_TRUST_SCORE_CEILING = 85
ADAPTER_OBSERVATION_QUALITY_CEILING = 90
CONTROLLED_CORS_ORIGIN = "https://safe-validation.invalid"
SUPPORTED_FAMILIES = frozenset(
    {
        "cors_misconfiguration",
        "sensitive_caching",
        "information_disclosure",
        "source_map_exposure",
    }
)
_DIRECT_TYPES = frozenset({"untrusted_origin_allowed", "source_map_publicly_reachable"})
PROMOTION_BRIDGE_FAMILIES = frozenset({"cors_misconfiguration", "source_map_exposure"})


def ensure_typed_evidence_adapter_schema(db: Database) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS typed_evidence_adapter_runs (
          execution_id TEXT PRIMARY KEY,
          analysis_id TEXT NOT NULL,
          hypothesis_id TEXT NOT NULL,
          source_run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          family TEXT NOT NULL,
          artifact_hash TEXT NOT NULL,
          evidence_count INTEGER NOT NULL DEFAULT 0,
          support_count INTEGER NOT NULL DEFAULT 0,
          contradiction_count INTEGER NOT NULL DEFAULT 0,
          admission_state TEXT NOT NULL DEFAULT '',
          admitted INTEGER NOT NULL DEFAULT 0,
          candidate_id TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('typed_evidence_adapter_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(TYPED_EVIDENCE_ADAPTER_SCHEMA_VERSION),),
    )


def _loads(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    try:
        parsed = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return default
    return parsed if isinstance(parsed, type(default)) else default


def _parse_time(value: Any) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise ReconError("Typed evidence adapter requires a timestamped execution artifact")
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconError(f"Invalid Validation Runner timestamp: {text}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _resolve_run_dir(paths: Any, db: Database, run_id: str, target: str) -> tuple[str, Path]:
    run_id = str(run_id or "").strip()
    target = str(target or "").strip()
    if not run_id:
        raise ReconError("validation runner-adapt requires --run-id RUN_ID")
    if target:
        row = db.one(
            "SELECT target,run_dir FROM run_targets WHERE run_id=? AND target=?",
            (run_id, target),
        )
        if not row:
            raise ReconError(f"Run target not found: {run_id} / {target}")
    else:
        rows = db.all(
            "SELECT target,run_dir FROM run_targets WHERE run_id=? ORDER BY target",
            (run_id,),
        )
        if len(rows) != 1:
            if not rows:
                raise ReconError(f"Run not found: {run_id}")
            raise ReconError("validation runner-adapt requires --target when the run has multiple targets")
        row = rows[0]
    selected_target = str(row["target"] or "")
    raw_dir = str(row["run_dir"] or "")
    if not raw_dir:
        raise ReconError(f"Run directory unavailable for {run_id} / {selected_target}")
    run_dir = Path(raw_dir).expanduser()
    if not run_dir.is_absolute():
        run_dir = (paths.root / run_dir).resolve()
    run_dir = run_dir.resolve()
    output_root = paths.output.resolve()
    try:
        run_dir.relative_to(output_root)
    except ValueError as exc:
        raise ReconError(f"Run directory is outside the output root: {run_dir}") from exc
    return selected_target, run_dir


def _load_execution(run_dir: Path, execution_id: str) -> dict[str, Any]:
    execution_id = str(execution_id or "").strip()
    if not execution_id:
        raise ReconError("validation runner-adapt requires --execution-id VEX-...")
    path = run_dir / "validation-runner-executions.jsonl"
    if path.is_symlink():
        raise ReconError(f"Refusing symlinked Validation Runner execution log: {path}")
    if not path.exists() or not path.is_file():
        raise ReconError(f"Validation Runner execution log not found: {path}")
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ReconError("Validation Runner execution log exceeds the adapter safety limit")
    matches: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            if index > 5000:
                raise ReconError("Validation Runner execution log exceeds 5000 records")
            text = line.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ReconError(f"Invalid Validation Runner execution JSONL at line {index}") from exc
            if isinstance(value, Mapping) and str(value.get("execution_id") or "") == execution_id:
                matches.append(dict(value))
    if len(matches) != 1:
        raise ReconError(
            f"Validation Runner execution must exist exactly once: {execution_id} (found {len(matches)})"
        )
    return matches[0]


def _headers(observation: Mapping[str, Any]) -> dict[str, str]:
    raw = observation.get("headers")
    if not isinstance(raw, Mapping):
        return {}
    return {str(key).strip().lower(): str(value or "").strip() for key, value in raw.items()}


def _sensitive_metadata(observation: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    keys = sorted({str(value).strip() for value in list(observation.get("sensitive_key_names") or []) if str(value).strip()})[:100]
    categories = sorted({str(value).strip() for value in list(observation.get("sensitive_pattern_categories") or []) if str(value).strip()})[:50]
    return keys, categories


def _signal(
    execution: Mapping[str, Any],
    observation: Mapping[str, Any],
    signal_type: str,
    *,
    polarity: str,
    weight: int,
    text: str,
) -> dict[str, Any]:
    execution_id = str(execution.get("execution_id") or "")
    return {
        "type": signal_type,
        "polarity": polarity,
        "source": "validation_runner_typed_adapter",
        "source_group": f"validation_execution:{execution_id}",
        "weight": int(weight),
        "text": text,
        "family_scope": str(execution.get("family") or ""),
        "adapter_version": TYPED_EVIDENCE_ADAPTER_VERSION,
        "adapter_rule_version": TYPED_EVIDENCE_ADAPTER_RULE_VERSION,
        "execution_id": execution_id,
        "contract_id": str(execution.get("contract_id") or ""),
        "observation_sequence": int(observation.get("sequence") or 0),
        "observed_at": str(observation.get("observed_at") or execution.get("finished_at") or ""),
        "method": str(observation.get("method") or ""),
        "url": str(observation.get("url") or ""),
        "confidence_ceiling": ADAPTER_CONFIDENCE_CEILING,
        "raw_body_stored": False,
    }


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    key = (str(item.get("polarity") or ""), str(item.get("type") or ""))
    if any((str(row.get("polarity") or ""), str(row.get("type") or "")) == key for row in items):
        return
    items.append(item)


def _cors_signals(execution: Mapping[str, Any], observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    for observation in observations:
        headers = _headers(observation)
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        method = str(observation.get("method") or "").upper()
        status = int(observation.get("status_code") or 0)
        keys, categories = _sensitive_metadata(observation)
        if acao:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "cors_header",
                    polarity="support",
                    weight=20,
                    text="The approved passive-live response includes a CORS policy header.",
                ),
            )
        if acao in {"*", CONTROLLED_CORS_ORIGIN}:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "untrusted_origin_allowed",
                    polarity="support",
                    weight=52,
                    text="The approved controlled Origin is accepted by the stored CORS response policy; this is CORS behavior evidence, not proof of sensitive cross-origin readability.",
                ),
            )
        if keys or categories:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "sensitive_context",
                    polarity="support",
                    weight=18,
                    text="Redacted response-shape metadata contains sensitive-key/category markers; no raw values are retained.",
                ),
            )
        if method == "GET" and status > 0 and not str(observation.get("error") or "") and not acao:
            _append_unique(
                contradict,
                _signal(
                    execution,
                    observation,
                    "cross_origin_read_blocked",
                    polarity="contradict",
                    weight=-44,
                    text="The controlled-Origin GET response omits Access-Control-Allow-Origin, so browser cross-origin read permission is not established.",
                ),
            )
        if acac in {"false", "0", "no"}:
            _append_unique(
                contradict,
                _signal(
                    execution,
                    observation,
                    "credentials_disabled",
                    polarity="contradict",
                    weight=-26,
                    text="The stored CORS response explicitly disables credentialed cross-origin access.",
                ),
            )
    return support, contradict


def _cache_signals(execution: Mapping[str, Any], observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    for observation in observations:
        headers = _headers(observation)
        cache_control = headers.get("cache-control", "")
        vary = headers.get("vary", "")
        cache_surface = bool(cache_control or vary or headers.get("age") or headers.get("etag"))
        keys, categories = _sensitive_metadata(observation)
        if cache_surface:
            _append_unique(
                support,
                _signal(execution, observation, "cache_header", polarity="support", weight=20,
                        text="The approved passive-live response contains cache-policy metadata."),
            )
        if keys or categories:
            _append_unique(
                support,
                _signal(execution, observation, "sensitive_context", polarity="support", weight=18,
                        text="Redacted response-shape metadata contains sensitive-key/category markers; this does not prove cross-user cache exposure."),
            )
        lower_cc = cache_control.lower()
        if "no-store" in lower_cc or "private" in lower_cc:
            _append_unique(
                contradict,
                _signal(execution, observation, "private_cache_control_observed", polarity="contradict", weight=-44,
                        text="The stored cache policy contains private/no-store controls."),
            )
        if any(token in vary.lower() for token in ("authorization", "cookie")):
            _append_unique(
                contradict,
                _signal(execution, observation, "user_specific_vary_observed", polarity="contradict", weight=-32,
                        text="The stored Vary policy includes Authorization or Cookie, indicating user-specific cache-key separation."),
            )
    return support, contradict


def _information_disclosure_signals(execution: Mapping[str, Any], observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        keys, categories = _sensitive_metadata(observation)
        if not (keys or categories):
            continue
        _append_unique(
            support,
            _signal(execution, observation, "sensitive_marker", polarity="support", weight=18,
                    text="Redacted response-shape metadata contains sensitive-looking field/category markers."),
        )
        _append_unique(
            support,
            _signal(execution, observation, "stored_evidence", polarity="support", weight=12,
                    text="The approved passive-live observation preserves a bounded response shape/hash as stored target evidence."),
        )
    # Visibility intent is not present in the executor artifact. Deliberately do
    # not synthesize sensitive_response_observed/private_field_publicly_observed.
    return support, []


def _source_map_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
    existing_support_types: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    contradict: list[dict[str, Any]] = []
    for observation in observations:
        url = str(observation.get("url") or "").lower()
        if not url.endswith(".map"):
            continue
        status = int(observation.get("status_code") or 0)
        shape = observation.get("response_shape")
        map_shape = isinstance(shape, Mapping) and "sources" in shape
        if 200 <= status < 300 and map_shape and "internal_sources" in existing_support_types:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "source_map_publicly_reachable",
                    polarity="support",
                    weight=44,
                    text="The approved anonymous GET retrieved a source-map-shaped response, while independent stored analysis already records internal source structure.",
                ),
            )
        elif status in {404, 410}:
            _append_unique(
                contradict,
                _signal(execution, observation, "source_map_not_public", polarity="contradict", weight=-40,
                        text="The approved anonymous source-map request returned a not-found/gone response."),
            )
    return support, contradict


def _derive_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
    existing_support_types: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    family = str(execution.get("family") or "")
    if family == "cors_misconfiguration":
        return _cors_signals(execution, observations)
    if family == "sensitive_caching":
        return _cache_signals(execution, observations)
    if family == "information_disclosure":
        return _information_disclosure_signals(execution, observations)
    if family == "source_map_exposure":
        return _source_map_signals(execution, observations, existing_support_types)
    raise ReconError(f"No typed evidence adapter is registered for family: {family}")


def _validate_execution(
    execution: Mapping[str, Any],
    *,
    run_id: str,
    target: str,
    hypothesis: Mapping[str, Any],
    max_age_seconds: int,
) -> list[dict[str, Any]]:
    family = str(execution.get("family") or "").strip()
    if family not in SUPPORTED_FAMILIES:
        raise ReconError(f"Typed evidence adapter does not support family: {family or '<empty>'}")
    policy = FAMILY_REASONING.get(family) or {}
    if str(policy.get("validation_level") or "") != "passive_live":
        raise ReconError(f"Family is not currently passive_live: {family}")
    if str(execution.get("status") or "") != "completed":
        raise ReconError("Only completed Validation Runner executions can be adapted")
    if not bool(execution.get("observation_only")) or not bool(execution.get("requires_evidence_adapter")):
        raise ReconError("Execution artifact does not carry the expected observation-only adapter contract")
    if bool(execution.get("raw_bodies_stored")):
        raise ReconError("Execution artifact claims raw response bodies were stored")
    expected = {
        "run_id": run_id,
        "target": target,
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
        "family": str(hypothesis.get("bug_family") or ""),
    }
    for key, value in expected.items():
        if str(execution.get(key) or "") != value:
            raise ReconError(f"Validation Runner execution {key} mismatch")
    if str(hypothesis.get("source_run_id") or "") != run_id:
        raise ReconError("Hypothesis source run does not match the Validation Runner execution")

    finished = _parse_time(execution.get("finished_at"))
    now = dt.datetime.now(dt.timezone.utc)
    if max_age_seconds <= 0:
        raise ReconError("Typed evidence adapter freshness window must be positive")
    age = (now - finished).total_seconds()
    if age < -300 or age > max_age_seconds:
        raise ReconError(
            f"Validation Runner execution is outside the evidence freshness window: {int(age)}s"
        )

    raw_observations = execution.get("observations")
    if not isinstance(raw_observations, list) or not raw_observations:
        raise ReconError("Completed Validation Runner execution contains no observations")
    observations: list[dict[str, Any]] = []
    for raw in raw_observations[:10]:
        if not isinstance(raw, Mapping):
            raise ReconError("Validation Runner execution contains an invalid observation")
        item = dict(raw)
        if bool(item.get("raw_body_stored")):
            raise ReconError("Validation Runner observation claims a raw response body was stored")
        observed = _parse_time(item.get("observed_at"))
        if abs((observed - finished).total_seconds()) > max(max_age_seconds, 3600):
            raise ReconError("Observation timestamp is inconsistent with the execution freshness window")
        observations.append(item)
    return observations


def _persist_evidence(
    db: Database,
    *,
    execution: Mapping[str, Any],
    hypothesis: Mapping[str, Any],
    items: list[dict[str, Any]],
) -> list[str]:
    now = utc_now()
    execution_id = str(execution.get("execution_id") or "")
    root = sha256_text(
        "|".join(
            [
                "typed-validation-root",
                execution_id,
                str(execution.get("family") or ""),
                str(execution.get("target") or ""),
            ]
        )
    )
    evidence_ids: list[str] = []
    for item in items:
        canonical = {
            "execution_id": execution_id,
            "family": str(execution.get("family") or ""),
            "type": str(item.get("type") or ""),
            "polarity": str(item.get("polarity") or ""),
            "sequence": int(item.get("observation_sequence") or 0),
            "observed_at": str(item.get("observed_at") or ""),
            "url": str(item.get("url") or ""),
            "method": str(item.get("method") or ""),
            "rule_version": TYPED_EVIDENCE_ADAPTER_RULE_VERSION,
        }
        integrity = sha256_text(json_dumps(canonical))
        evidence_id = "EVD-" + integrity[:16].upper()
        evidence_ids.append(evidence_id)
        observed_at = str(item.get("observed_at") or now)
        polarity = str(item.get("polarity") or "support")
        db.execute(
            """INSERT OR IGNORE INTO evidence_records(
            evidence_id,analysis_id,source_run_id,target,evidence_type,polarity,source_kind,source_tool,source_artifact,
            parser_name,parser_version,source_group,root_fingerprint,trust_score,observation_quality,directness,summary,
            raw_reference,integrity_hash,first_seen,last_seen,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                str(hypothesis.get("analysis_id") or ""),
                str(hypothesis.get("source_run_id") or ""),
                str(hypothesis.get("target") or ""),
                str(item.get("type") or ""),
                polarity,
                "passive_live_validation",
                "validation_runner",
                "validation-runner-executions.jsonl",
                "typed_evidence_adapter",
                TYPED_EVIDENCE_ADAPTER_VERSION,
                str(item.get("source_group") or f"validation_execution:{execution_id}"),
                root,
                ADAPTER_TRUST_SCORE_CEILING,
                ADAPTER_OBSERVATION_QUALITY_CEILING,
                "direct" if str(item.get("type") or "") in _DIRECT_TYPES else "contextual",
                str(item.get("text") or "")[:2000],
                f"validation_execution:{execution_id}:observation:{int(item.get('observation_sequence') or 0)}",
                integrity,
                observed_at,
                observed_at,
                now,
            ),
        )
        db.execute("UPDATE evidence_records SET last_seen=? WHERE evidence_id=?", (now, evidence_id))
    return evidence_ids


def adapt_validation_runner_execution(
    paths: Any,
    db: Database,
    *,
    scan_run_id: str,
    execution_id: str,
    target: str = "",
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    actor: str = "analyst",
) -> dict[str, Any]:
    """Apply one completed Validation Runner execution exactly once."""

    ensure_typed_evidence_adapter_schema(db)
    run_id = str(scan_run_id or "").strip()
    selected_target, run_dir = _resolve_run_dir(paths, db, run_id, target)
    execution = _load_execution(run_dir, execution_id)
    artifact_hash = sha256_text(json_dumps(execution))

    previous = db.one(
        "SELECT * FROM typed_evidence_adapter_runs WHERE execution_id=?",
        (str(execution_id),),
    )
    if previous:
        if str(previous["artifact_hash"] or "") != artifact_hash:
            raise ReconError("Previously adapted execution artifact has changed; refusing mutable evidence")
        return {
            "version": TYPED_EVIDENCE_ADAPTER_VERSION,
            "rule_version": TYPED_EVIDENCE_ADAPTER_RULE_VERSION,
            "status": "already_applied",
            "execution_id": str(execution_id),
            "analysis_id": str(previous["analysis_id"]),
            "hypothesis_id": str(previous["hypothesis_id"]),
            "family": str(previous["family"]),
            "target": str(previous["target"]),
            "evidence_count": int(previous["evidence_count"] or 0),
            "admission_state": str(previous["admission_state"] or ""),
            "admitted": bool(previous["admitted"]),
            "candidate_id": str(previous["candidate_id"] or ""),
            "network_requests_executed_by_adapter": 0,
            "vulnerability_confirmed": False,
        }

    hypothesis_id = str(execution.get("hypothesis_id") or "").strip()
    hypothesis_row = db.one("SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?", (hypothesis_id,))
    if not hypothesis_row:
        raise ReconError(f"Analysis hypothesis not found for execution: {hypothesis_id or '<empty>'}")
    hypothesis = dict(hypothesis_row)
    observations = _validate_execution(
        execution,
        run_id=run_id,
        target=selected_target,
        hypothesis=hypothesis,
        max_age_seconds=max_age_seconds,
    )

    existing_support = _loads(hypothesis.get("supporting_evidence_json"), [])
    existing_support_types = {
        str(item.get("type") or "")
        for item in existing_support
        if isinstance(item, Mapping) and str(item.get("type") or "")
    }
    support, contradict = _derive_signals(execution, observations, existing_support_types)
    all_items = [*support, *contradict]

    family = str(execution.get("family") or "")
    with db.transaction():
        evidence_ids = _persist_evidence(
            db,
            execution=execution,
            hypothesis=hypothesis,
            items=all_items,
        )

        if all_items:
            common = {
                "analysis_id": str(hypothesis.get("analysis_id") or ""),
                "source_run_id": run_id,
                "target": selected_target,
                "alert_id": hypothesis.get("alert_id"),
                "asset": str(hypothesis.get("asset") or ""),
                "endpoint": str(hypothesis.get("endpoint") or ""),
                "source_ref": str(hypothesis.get("source_ref") or f"validation-execution:{execution_id}"),
                "family": family,
                "variant": str(hypothesis.get("bug_variant") or "typed_passive_live"),
                "support": support,
                "contradict": contradict,
                "missing": [str(value) for value in _loads(hypothesis.get("missing_evidence_json"), []) if str(value)],
                "rule_ids": [
                    *[str(value) for value in _loads(hypothesis.get("rule_ids_json"), []) if str(value)],
                    "typed-evidence-adapter-passive-live",
                ],
                "summary": str(hypothesis.get("summary") or f"{family} hypothesis enriched by typed passive-live evidence."),
            }
            if family in PROMOTION_BRIDGE_FAMILIES:
                # The bridge itself records the hypothesis first and creates a
                # Potential Finding only if canonical Admission returns admitted.
                import bug_candidates_family21 as candidate_bridge

                candidate_bridge._promote_static_family_result(
                    db,
                    analysis_id=common["analysis_id"],
                    run_id=run_id,
                    target=selected_target,
                    endpoint=common["endpoint"],
                    source_ref=common["source_ref"],
                    family=family,
                    dedicated={
                        "family": family,
                        "variant": common["variant"],
                        "support": support,
                        "contradict": contradict,
                        "missing": common["missing"],
                        "rule_ids": common["rule_ids"],
                        "summary": common["summary"],
                        "direct": any(str(item.get("type") or "") in _DIRECT_TYPES for item in support),
                    },
                    confidence=ADAPTER_CONFIDENCE_CEILING,
                )
            else:
                # Cache/disclosure metadata can enrich or contradict a hypothesis
                # but cannot create a new Potential Finding through this adapter.
                from hypothesis_admission import record_hypothesis

                record_hypothesis(db, **common)

        updated_row = db.one("SELECT * FROM analysis_hypotheses WHERE hypothesis_id=?", (hypothesis_id,))
        updated = dict(updated_row) if updated_row else hypothesis
        admission = _loads(updated.get("admission_json"), {})
        admitted = bool(admission.get("admitted"))
        admission_state = str(admission.get("state") or updated.get("state") or "")
        candidate_id = str(updated.get("promoted_candidate_id") or "")

        if candidate_id:
            by_id = {evidence_id: item for evidence_id, item in zip(evidence_ids, all_items)}
            for evidence_id in evidence_ids:
                item = by_id[evidence_id]
                polarity = str(item.get("polarity") or "support")
                db.execute(
                    "INSERT OR REPLACE INTO candidate_evidence_links(candidate_id,evidence_id,polarity,weight,relation,created_at) VALUES(?,?,?,?,?,?)",
                    (
                        candidate_id,
                        evidence_id,
                        polarity,
                        max(1, min(100, abs(int(item.get("weight") or 1)))),
                        "typed_validation_adapter",
                        utc_now(),
                    ),
                )

        status = "applied" if all_items else "no_typed_signal"
        db.execute(
            """INSERT INTO typed_evidence_adapter_runs(
            execution_id,analysis_id,hypothesis_id,source_run_id,target,family,artifact_hash,evidence_count,
            support_count,contradiction_count,admission_state,admitted,candidate_id,status,applied_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(execution_id),
                str(hypothesis.get("analysis_id") or ""),
                hypothesis_id,
                run_id,
                selected_target,
                family,
                artifact_hash,
                len(evidence_ids),
                len(support),
                len(contradict),
                admission_state,
                int(admitted),
                candidate_id,
                status,
                utc_now(),
            ),
        )
        db.audit(
            "validation_runner_typed_evidence_adapted",
            actor=actor,
            target=selected_target,
            entity_type="validation_execution",
            entity_value=str(execution_id),
            details={
                "analysis_id": str(hypothesis.get("analysis_id") or ""),
                "hypothesis_id": hypothesis_id,
                "family": family,
                "support_types": [str(item.get("type") or "") for item in support],
                "contradiction_types": [str(item.get("type") or "") for item in contradict],
                "admitted": admitted,
                "candidate_id": candidate_id,
                "network_requests_executed_by_adapter": 0,
            },
        )

    return {
        "version": TYPED_EVIDENCE_ADAPTER_VERSION,
        "rule_version": TYPED_EVIDENCE_ADAPTER_RULE_VERSION,
        "status": status,
        "execution_id": str(execution_id),
        "analysis_id": str(hypothesis.get("analysis_id") or ""),
        "hypothesis_id": hypothesis_id,
        "family": family,
        "target": selected_target,
        "support_types": [str(item.get("type") or "") for item in support],
        "contradiction_types": [str(item.get("type") or "") for item in contradict],
        "evidence_ids": evidence_ids,
        "evidence_count": len(evidence_ids),
        "admission_state": admission_state,
        "admitted": admitted,
        "candidate_id": candidate_id,
        "network_requests_executed_by_adapter": 0,
        "raw_bodies_stored": False,
        "vulnerability_confirmed": False,
        "potential_finding_semantics_only": True,
    }
