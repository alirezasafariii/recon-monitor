from __future__ import annotations

"""State-versioned confirmation for volatile recon changes.

The legacy event confirmation counter is event-driven: it only advances when a
new change event is emitted. That makes ``A -> B -> B`` stall at one
observation, while a later ``B -> C`` can reuse the same subject-level counter.

This module keeps confirmation as a successful-run state machine instead:

* identity is ``subject_key + state_version``;
* one successful scan contributes at most one observation of a state;
* a different state_version always resets the count to one;
* observations remain provisional until the target run finishes successfully;
* an unchanged second observation emits a synthetic confirmed event so
  ``confirmed_only`` alerting has an event to consume;
* failed/interrupted runs never advance the committed confirmation state.

Only volatile DNS and HTTP fingerprint changes are routed through this layer.
All other event categories keep the established behavior.
"""

from pathlib import Path
from typing import Any, Mapping

from core import json_dumps, safe_json_loads, sha256_text, utc_now


STABLE_CONFIRMATION_SCHEMA_VERSION = 1
VOLATILE_CATEGORIES = {"dns_change", "fingerprint_change"}


def ensure_stable_confirmation_schema(db: Any) -> None:
    db.conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS stable_change_state (
          target TEXT NOT NULL,
          subject_key TEXT NOT NULL,
          category TEXT NOT NULL,
          state_version TEXT NOT NULL,
          occurrences INTEGER NOT NULL DEFAULT 1,
          confirmation_state TEXT NOT NULL DEFAULT 'observed',
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          last_run_id TEXT NOT NULL,
          event_templates_json TEXT NOT NULL DEFAULT '[]',
          PRIMARY KEY(target,subject_key)
        );
        CREATE INDEX IF NOT EXISTS idx_stable_change_state_target_category
          ON stable_change_state(target,category,confirmation_state);

        CREATE TABLE IF NOT EXISTS stable_change_run_state (
          run_id TEXT NOT NULL,
          target TEXT NOT NULL,
          subject_key TEXT NOT NULL,
          category TEXT NOT NULL,
          state_version TEXT NOT NULL,
          occurrences INTEGER NOT NULL DEFAULT 1,
          confirmation_state TEXT NOT NULL DEFAULT 'observed',
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          event_templates_json TEXT NOT NULL DEFAULT '[]',
          PRIMARY KEY(run_id,target,subject_key)
        );
        CREATE INDEX IF NOT EXISTS idx_stable_change_run_target_category
          ON stable_change_run_state(run_id,target,category,confirmation_state);
        """
    )
    db.execute(
        "INSERT INTO schema_meta(key,value) VALUES('stable_confirmation_schema_version',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(STABLE_CONFIRMATION_SCHEMA_VERSION),),
    )


def discard_stale_stable_change_runs(db: Any, target: str, keep_run_id: str) -> None:
    db.execute(
        "DELETE FROM stable_change_run_state WHERE target=? AND run_id<>?",
        (target, keep_run_id),
    )


def _templates(value: Any) -> list[dict[str, Any]]:
    rows = safe_json_loads(value, [], expected_type=list)
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _append_template(
    templates: list[dict[str, Any]],
    template: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    result = [dict(row) for row in templates]
    if not template:
        return result
    candidate = dict(template)
    dedup_key = str(candidate.get("dedup_key") or "")
    for row in result:
        if dedup_key and str(row.get("dedup_key") or "") == dedup_key:
            return result
    result.append(candidate)
    return result


def observe_stable_change_state(
    db: Any,
    *,
    run_id: str,
    target: str,
    subject_key: str,
    category: str,
    state_version: str,
    confirmations: int,
    immediately_confirmed: bool,
    event_template: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Record one provisional observation for a state in the current run."""

    now = utc_now()
    threshold = max(1, int(confirmations or 1))
    provisional = db.one(
        "SELECT * FROM stable_change_run_state "
        "WHERE run_id=? AND target=? AND subject_key=?",
        (run_id, target, subject_key),
    )

    if provisional is not None:
        same_state = str(provisional["state_version"]) == state_version
        if same_state:
            occurrences = int(provisional["occurrences"])
            confirmation_state = str(provisional["confirmation_state"])
            first_seen = str(provisional["first_seen"])
            templates = _append_template(
                _templates(provisional["event_templates_json"]),
                event_template,
            )
            transitioned = False
        else:
            occurrences = 1
            confirmation_state = (
                "confirmed"
                if immediately_confirmed or occurrences >= threshold
                else "observed"
            )
            first_seen = now
            templates = _append_template([], event_template)
            transitioned = confirmation_state == "confirmed"
    else:
        committed = db.one(
            "SELECT * FROM stable_change_state WHERE target=? AND subject_key=?",
            (target, subject_key),
        )
        same_state = bool(
            committed is not None
            and str(committed["state_version"]) == state_version
        )
        if same_state:
            previous_count = int(committed["occurrences"])
            previous_state = str(committed["confirmation_state"])
            occurrences = previous_count + 1
            confirmation_state = (
                "confirmed"
                if immediately_confirmed or occurrences >= threshold
                else "observed"
            )
            first_seen = str(committed["first_seen"])
            templates = _append_template(
                _templates(committed["event_templates_json"]),
                event_template,
            )
            transitioned = (
                confirmation_state == "confirmed"
                and previous_state != "confirmed"
            )
        else:
            occurrences = 1
            confirmation_state = (
                "confirmed"
                if immediately_confirmed or occurrences >= threshold
                else "observed"
            )
            first_seen = now
            templates = _append_template([], event_template)
            transitioned = confirmation_state == "confirmed"

    db.execute(
        """
        INSERT INTO stable_change_run_state(
          run_id,target,subject_key,category,state_version,occurrences,
          confirmation_state,first_seen,last_seen,event_templates_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(run_id,target,subject_key) DO UPDATE SET
          category=excluded.category,
          state_version=excluded.state_version,
          occurrences=excluded.occurrences,
          confirmation_state=excluded.confirmation_state,
          first_seen=excluded.first_seen,
          last_seen=excluded.last_seen,
          event_templates_json=excluded.event_templates_json
        """,
        (
            run_id,
            target,
            subject_key,
            category,
            state_version,
            occurrences,
            confirmation_state,
            first_seen,
            now,
            json_dumps(templates),
        ),
    )
    return {
        "subject_key": subject_key,
        "state_version": state_version,
        "occurrences": occurrences,
        "confirmation_state": confirmation_state,
        "transitioned": transitioned,
        "templates": templates,
    }


def finalize_stable_change_run(db: Any, run_id: str, target: str, status: str) -> None:
    """Promote provisional observations only for a successful target run."""

    rows = db.all(
        "SELECT * FROM stable_change_run_state WHERE run_id=? AND target=?",
        (run_id, target),
    )
    if status == "success":
        for row in rows:
            db.execute(
                """
                INSERT INTO stable_change_state(
                  target,subject_key,category,state_version,occurrences,
                  confirmation_state,first_seen,last_seen,last_run_id,event_templates_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(target,subject_key) DO UPDATE SET
                  category=excluded.category,
                  state_version=excluded.state_version,
                  occurrences=excluded.occurrences,
                  confirmation_state=excluded.confirmation_state,
                  first_seen=excluded.first_seen,
                  last_seen=excluded.last_seen,
                  last_run_id=excluded.last_run_id,
                  event_templates_json=excluded.event_templates_json
                """,
                (
                    target,
                    str(row["subject_key"]),
                    str(row["category"]),
                    str(row["state_version"]),
                    int(row["occurrences"]),
                    str(row["confirmation_state"]),
                    str(row["first_seen"]),
                    str(row["last_seen"]),
                    run_id,
                    str(row["event_templates_json"]),
                ),
            )
    db.execute(
        "DELETE FROM stable_change_run_state WHERE run_id=? AND target=?",
        (run_id, target),
    )


def _baseline(ctx: Any) -> bool:
    row = ctx.db.one(
        "SELECT baseline FROM run_targets WHERE run_id=? AND target=?",
        (ctx.run_id, ctx.policy.name),
    )
    return bool(row and row["baseline"])


def _state_identity(
    ctx: Any,
    category: str,
    item: str,
    details: Mapping[str, Any],
) -> tuple[str, str] | None:
    if category == "fingerprint_change":
        row = ctx.db.one(
            "SELECT fingerprint_hash FROM fingerprints WHERE target=? AND url=?",
            (ctx.policy.name, item),
        )
        state_version = str(row["fingerprint_hash"] or "") if row else ""
        if not state_version:
            state_version = sha256_text(json_dumps(details.get("new", {})))
        return f"fingerprint:{item}", state_version

    if category == "dns_change":
        host = str(details.get("host") or "").strip()
        rrtype = str(details.get("rrtype") or "").strip().upper()
        if not host or not rrtype:
            return None
        rows = ctx.db.all(
            "SELECT value FROM dns_records "
            "WHERE target=? AND host=? AND rrtype=? AND is_current=1 "
            "ORDER BY value",
            (ctx.policy.name, host, rrtype),
        )
        values = [str(row["value"]) for row in rows]
        state_version = sha256_text(json_dumps(values))
        return f"dns:{host}:{rrtype}", state_version

    return None


def _event_template(
    ctx: Any,
    category: str,
    item: str,
    title: str,
    details: Mapping[str, Any],
    subject_key: str,
    state_version: str,
) -> dict[str, Any]:
    import stages

    score, severity, reasons, change_class = stages.explain_risk(
        category, item, details
    )
    if not ctx.policy.analysis.get("semantic_change_classification", True):
        change_class = category
    if not ctx.policy.analysis.get("explainable_risk", True):
        reasons = []
    dedup_key = sha256_text(
        json_dumps(
            [
                category,
                subject_key,
                state_version,
                item,
                str(details.get("action") or ""),
            ]
        )
    )[:32]
    return {
        "category": category,
        "change_class": change_class,
        "item": item,
        "title": title,
        "details": dict(details),
        "risk_score": score,
        "risk_reasons": reasons,
        "severity": severity,
        "dedup_key": dedup_key,
    }


def _write_event(
    ctx: Any,
    template: Mapping[str, Any],
    *,
    observation_count: int,
    confirmation_state: str,
    confirmation_transition: bool = False,
) -> None:
    details = dict(template.get("details") or {})
    if confirmation_transition:
        details["confirmation_transition"] = "observed_to_confirmed"

    occurrence, legacy_state = ctx.db.observe_event(
        ctx.policy.name,
        str(template["dedup_key"]),
        str(template["category"]),
        str(template["item"]),
        str(template["change_class"]),
        ctx.run_id,
        details,
        confirmations=max(
            1,
            int(ctx.policy.analysis.get("stable_confirmations", 2) or 2),
        ),
        immediately_confirmed=confirmation_state == "confirmed",
    )
    event = {
        "ts": utc_now(),
        "run_id": ctx.run_id,
        "target": ctx.policy.name,
        "category": str(template["category"]),
        "change_class": str(template["change_class"]),
        "confirmation_state": confirmation_state,
        "observation_count": observation_count,
        "item": str(template["item"]),
        "title": str(template["title"]),
        "details": details,
        "risk_score": int(template["risk_score"]),
        "risk_reasons": list(template.get("risk_reasons") or []),
        "severity": str(template["severity"]),
        "dedup_key": str(template["dedup_key"]),
    }
    incident_id = ctx.db.correlate_event(
        ctx.policy.name,
        str(template["dedup_key"]),
        str(template["category"]),
        str(template["item"]),
        str(template["title"]),
        str(template["severity"]),
        int(template["risk_score"]),
        ctx.run_id,
        details,
    )
    event["incident_id"] = incident_id
    event["legacy_observation_count"] = occurrence
    event["legacy_confirmation_state"] = legacy_state
    with ctx.events_path.open("a", encoding="utf-8") as handle:
        handle.write(json_dumps(event) + "\n")


def stable_emit_event(
    ctx: Any,
    category: str,
    item: str,
    title: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    import stages

    original = getattr(stages, "_STABLE_CONFIRMATION_ORIGINAL_EMIT", None)
    if category not in VOLATILE_CATEGORIES or original is None or _baseline(ctx):
        if original is not None:
            original(ctx, category, item, title, details)
        return

    payload = dict(details or {})
    ignore_rule = ctx.db.ignore_match(ctx.policy.name, category, item) or ctx.db.ignore_match(
        ctx.policy.name, "any", item
    )
    if ignore_rule:
        ctx.logger.info(
            "Event ignored by rule",
            target=ctx.policy.name,
            category=category,
            item=item,
            rule_id=ignore_rule,
        )
        return

    identity = _state_identity(ctx, category, item, payload)
    if identity is None:
        original(ctx, category, item, title, payload)
        return
    subject_key, state_version = identity
    template = _event_template(
        ctx,
        category,
        item,
        title,
        payload,
        subject_key,
        state_version,
    )
    confirmations = max(
        1,
        int(ctx.policy.analysis.get("stable_confirmations", 2) or 2),
    )
    track_confirmation = bool(
        ctx.policy.analysis.get("track_confirmation_state", True)
    )
    immediate = (
        not track_confirmation
        or int(template["risk_score"]) >= 70
        or confirmations <= 1
    )
    observed = observe_stable_change_state(
        ctx.db,
        run_id=ctx.run_id,
        target=ctx.policy.name,
        subject_key=subject_key,
        category=category,
        state_version=state_version,
        confirmations=confirmations,
        immediately_confirmed=immediate,
        event_template=template,
    )
    _write_event(
        ctx,
        template,
        observation_count=int(observed["occurrences"]),
        confirmation_state=str(observed["confirmation_state"]),
    )


def _active_candidates(ctx: Any, category: str) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for row in ctx.db.all(
        "SELECT * FROM stable_change_state "
        "WHERE target=? AND category=? AND confirmation_state<>'confirmed'",
        (ctx.policy.name, category),
    ):
        candidates[str(row["subject_key"])] = dict(row)
    for row in ctx.db.all(
        "SELECT * FROM stable_change_run_state "
        "WHERE run_id=? AND target=? AND category=? AND confirmation_state<>'confirmed'",
        (ctx.run_id, ctx.policy.name, category),
    ):
        candidates[str(row["subject_key"])] = dict(row)
    return list(candidates.values())


def _emit_transition_templates(ctx: Any, observed: Mapping[str, Any]) -> None:
    if not bool(observed.get("transitioned")):
        return
    for template in list(observed.get("templates") or []):
        if not isinstance(template, Mapping):
            continue
        _write_event(
            ctx,
            template,
            observation_count=int(observed["occurrences"]),
            confirmation_state="confirmed",
            confirmation_transition=True,
        )


def _observe_pending_fingerprints(ctx: Any) -> None:
    if _baseline(ctx) or not bool(
        ctx.policy.analysis.get("track_confirmation_state", True)
    ):
        return
    confirmations = max(
        1,
        int(ctx.policy.analysis.get("stable_confirmations", 2) or 2),
    )
    for candidate in _active_candidates(ctx, "fingerprint_change"):
        item = ""
        templates = _templates(candidate.get("event_templates_json"))
        if templates:
            item = str(templates[0].get("item") or "")
        if not item:
            subject = str(candidate.get("subject_key") or "")
            item = subject[len("fingerprint:") :] if subject.startswith("fingerprint:") else ""
        if not item:
            continue
        row = ctx.db.one(
            "SELECT fingerprint_hash,last_run_id FROM fingerprints "
            "WHERE target=? AND url=?",
            (ctx.policy.name, item),
        )
        if row is None or str(row["last_run_id"] or "") != ctx.run_id:
            continue
        state_version = str(row["fingerprint_hash"] or "")
        if not state_version:
            continue
        observed = observe_stable_change_state(
            ctx.db,
            run_id=ctx.run_id,
            target=ctx.policy.name,
            subject_key=str(candidate["subject_key"]),
            category="fingerprint_change",
            state_version=state_version,
            confirmations=confirmations,
            immediately_confirmed=False,
        )
        _emit_transition_templates(ctx, observed)


def _read_hosts(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    }


def _observe_pending_dns(ctx: Any, metrics: Mapping[str, Any]) -> None:
    if _baseline(ctx) or not bool(
        ctx.policy.analysis.get("track_confirmation_state", True)
    ):
        return
    successful_rrtypes = {
        str(value).upper()
        for value in list(metrics.get("successful_rrtypes") or [])
    }
    if not successful_rrtypes:
        return
    normal_hosts = _read_hosts(ctx.current / "dns-filtered-hosts.txt")
    if not normal_hosts:
        normal_hosts = _read_hosts(ctx.current / "dns-input.txt")
    root_hosts = _read_hosts(ctx.current / "dns-root-hosts.txt") or set(
        ctx.policy.roots
    )
    confirmations = max(
        1,
        int(ctx.policy.analysis.get("stable_confirmations", 2) or 2),
    )

    for candidate in _active_candidates(ctx, "dns_change"):
        templates = _templates(candidate.get("event_templates_json"))
        details = dict(templates[0].get("details") or {}) if templates else {}
        host = str(details.get("host") or "").strip()
        rrtype = str(details.get("rrtype") or "").strip().upper()
        if not host or rrtype not in successful_rrtypes:
            continue
        queried_hosts = root_hosts if rrtype == "NS" else normal_hosts
        if host not in queried_hosts:
            continue
        rows = ctx.db.all(
            "SELECT value FROM dns_records "
            "WHERE target=? AND host=? AND rrtype=? AND is_current=1 "
            "ORDER BY value",
            (ctx.policy.name, host, rrtype),
        )
        values = [str(row["value"]) for row in rows]
        state_version = sha256_text(json_dumps(values))
        observed = observe_stable_change_state(
            ctx.db,
            run_id=ctx.run_id,
            target=ctx.policy.name,
            subject_key=str(candidate["subject_key"]),
            category="dns_change",
            state_version=state_version,
            confirmations=confirmations,
            immediately_confirmed=False,
        )
        _emit_transition_templates(ctx, observed)


def install_stable_confirmation() -> None:
    """Patch volatile stage/event hooks once after the stages module is loaded."""

    import stages

    if getattr(stages, "_STABLE_CONFIRMATION_INSTALLED", False):
        return
    stages._STABLE_CONFIRMATION_ORIGINAL_EMIT = stages.emit_event
    stages.emit_event = stable_emit_event

    original_fingerprint = stages.STAGE_FUNCTIONS.get("fingerprint")
    original_dns = stages.STAGE_FUNCTIONS.get("dns")

    if original_fingerprint is not None:
        def fingerprint_stage(ctx: Any) -> dict[str, Any]:
            metrics = original_fingerprint(ctx)
            _observe_pending_fingerprints(ctx)
            return metrics

        stages.STAGE_FUNCTIONS["fingerprint"] = fingerprint_stage

    if original_dns is not None:
        def dns_stage(ctx: Any) -> dict[str, Any]:
            metrics = original_dns(ctx)
            _observe_pending_dns(ctx, metrics)
            return metrics

        stages.STAGE_FUNCTIONS["dns"] = dns_stage

    stages._STABLE_CONFIRMATION_INSTALLED = True
