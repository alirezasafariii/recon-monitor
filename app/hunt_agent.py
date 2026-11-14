from __future__ import annotations

"""Persistent autonomous missions over the established Recon/Analysis engines."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from core import AppPaths, Config, Database, PolicySet, ReconError, atomic_write_text, utc_now
from hunt_planner import AIPlanner, RulesPlanner

AGENT_VERSION = "1.0.0"
ACTOR = "hunt-agent"


def install(db: Database) -> None:
    # Independent additive tables; the core schema stays at 18.
    db.execute("""CREATE TABLE IF NOT EXISTS hunt_missions (
        mission_id TEXT PRIMARY KEY, target TEXT NOT NULL, policy_hash TEXT NOT NULL,
        options_json TEXT NOT NULL, state_json TEXT NOT NULL, status TEXT NOT NULL,
        stop_requested INTEGER NOT NULL DEFAULT 0, started_at REAL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS hunt_steps (
        mission_id TEXT NOT NULL, step_number INTEGER NOT NULL, action_id TEXT NOT NULL,
        tool TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}',
        started_at TEXT NOT NULL, finished_at TEXT,
        PRIMARY KEY(mission_id,step_number))""")


def policy_for(paths: AppPaths, target: str):
    policies = PolicySet.load(paths)
    matches = [p for p in policies.targets if p.name == target]
    # The legacy Recon selector also matches roots. An exact name that is
    # another policy's root must not accidentally launch a multi-target Run.
    if len(matches) != 1 or len(policies.select(target)) != 1:
        raise ReconError("Mission requires exactly one configured target name")
    return matches[0]


def mission(db: Database, mission_id: str) -> dict:
    row = db.one("SELECT * FROM hunt_missions WHERE mission_id=?", (mission_id,))
    if not row:
        raise ReconError("Hunt mission not found")
    data = dict(row)
    data["options"] = json.loads(data.pop("options_json"))
    data["state"] = json.loads(data.pop("state_json"))
    data["steps"] = [dict(r) for r in db.all("SELECT * FROM hunt_steps WHERE mission_id=? ORDER BY step_number", (mission_id,))]
    for step in data["steps"]:
        step["result"] = json.loads(step.pop("result_json"))
    return data


def save(db: Database, data: dict, status: str) -> None:
    db.execute("UPDATE hunt_missions SET state_json=?,status=?,updated_at=? WHERE mission_id=?",
               (json.dumps(data["state"]), status, utc_now(), data["mission_id"]))


def create_mission(paths: AppPaths, db: Database, *, target: str, source_run: str = "",
                   offline: bool = False, allow_live: bool = False, planner: str = "ai",
                   max_steps: int | None = None, max_cases: int | None = None, max_runtime: int | None = None,
                   max_live_requests: int | None = None, browser_plan: str = "",
                   browser_active: bool = False, browser_verify: bool = False, browser_write: bool = False, browser_storage_state: str = "", browser_chromium: str = "") -> dict:
    install(db)
    policy = policy_for(paths, target)
    if planner not in {"ai", "rules"}:
        raise ReconError("Invalid planner")
    if offline and allow_live:
        raise ReconError("Offline missions cannot enable live validation")
    if offline and not source_run:
        row = db.one("SELECT run_id FROM run_targets WHERE target=? AND status<>'running' ORDER BY started_at DESC LIMIT 1", (target,))
        source_run = str(row[0]) if row else ""
    if source_run:
        row = db.one("SELECT status FROM run_targets WHERE run_id=? AND target=?", (source_run, target))
        if not row or row[0] == "running":
            raise ReconError("Source Run must belong to this target and must not be running")
    elif offline:
        raise ReconError("Offline missions require a stored Run for this target")
    if not offline and not Config(paths).authorized:
        raise ReconError("Network missions require the installation's authorization setting")
    options = dict(offline=offline, allow_live=allow_live, planner=planner)
    # Legacy max_* arguments are accepted for callers, but impose no quotas.
    if browser_plan:
        if offline or not browser_active or not policy.active_allowed(Config(paths), True):
            raise ReconError("Browser mission requires explicit browser active gates and a network mission")
        from xss_browser import read_plan, validate_plan
        source = Path(browser_plan).resolve()
        plan = read_plan(source)
        validate_plan(plan, policy)
        if any(t['input']['kind'] == 'form' or t.get('cleanup') for t in plan['tests']) and not browser_write:
            raise ReconError("Browser form workflows require --allow-browser-write")
        options["browser"] = {"path": str(source), "sha256": hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest(),
                              "verify": browser_verify, "write": browser_write,
                              "storage_state": browser_storage_state or None, "chromium": browser_chromium or None}
    state = {"source_run": source_run, "analysis_id": "", "cases": {}, "live_requests_reserved": 0,
             "collection_complete": bool(source_run and row[0] == "success")}
    mid = "HUNT-" + uuid.uuid4().hex[:16].upper()
    db.execute("INSERT INTO hunt_missions(mission_id,target,policy_hash,options_json,state_json,status,created_at,updated_at) VALUES(?,?,?,?,?,'ready',?,?)",
               (mid, target, policy.policy_hash(), json.dumps(options), json.dumps(state), utc_now(), utc_now()))
    db.audit("hunt_mission_created", actor=ACTOR, target=target, entity_type="hunt", entity_value=mid, details=options)
    return mission(db, mid)


@contextlib.contextmanager
def target_lock(paths: AppPaths, target: str):
    path = paths.state / ("hunt-" + hashlib.sha256(target.encode()).hexdigest()[:24] + ".lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReconError("Another hunt mission is already running for this target") from None
        yield
    finally:
        os.close(fd)


def check_policy(paths: AppPaths, data: dict) -> None:
    if policy_for(paths, data["target"]).policy_hash() != data["policy_hash"]:
        raise ReconError("Target policy changed; create a new mission with the updated scope")
    if not data["options"]["offline"] and not Config(paths).authorized:
        raise ReconError("Installation authorization is disabled")


def actions_for(db: Database, data: dict) -> list[dict]:
    state, options = data["state"], data["options"]
    done = {s["action_id"] for s in data["steps"] if s["status"] in {"completed", "partial", "failed", "uncertain"}}
    if not state["source_run"] or (state.get("collecting") and "recon" not in done):
        return [] if options["offline"] or "recon" in done else [{"id": "recon", "tool": "recon", "priority": 100}]
    if not state["analysis_id"]:
        return [] if "analysis" in done else [{"id": "analysis", "tool": "analysis", "priority": 100}]
    from correlation_engine import investigation_queue
    actions = []
    if options.get("browser") and "browser" not in done:
        actions.append({"id": "browser", "tool": "browser", "priority": 120})
    for item in investigation_queue(db, state["analysis_id"], target=data["target"], limit=None):
        aid = "investigate:" + str(item["cluster_id"])
        if aid not in done:
            actions.append({"id": aid, "tool": "investigate", "cluster_id": str(item["cluster_id"]),
                            "priority": int(item.get("queue_score") or 0),
                            "family": str(item.get("primary_family") or "unknown")[:80]})
    live_pending = set()
    if options["allow_live"] and not options["offline"]:
        from safe_validation import MAX_REQUESTS
        for cid in state["cases"]:
            for row in db.all("SELECT plan_id,plan_json FROM validation_plans WHERE case_id=? AND target=? AND level='passive_live' AND status='approved'", (cid, data["target"])):
                count = min(MAX_REQUESTS, len(json.loads(row[1]).get("requests", [])))
                if "live:" + row[0] not in done and count:
                    live_pending.add(cid)
                    actions.append({"id": "live:" + row[0], "tool": "live", "plan_id": row[0], "case_id": cid, "priority": 115})
    for cid, case in state["cases"].items():
        context = {k: case[k] for k in ("family", "coverage") if k in case}
        if "validate:" + cid not in done:
            actions.append({"id": "validate:" + cid, "tool": "validate", "case_id": cid, "priority": 110, **context})
        elif "report:" + cid not in done and cid not in live_pending:
            actions.append({"id": "report:" + cid, "tool": "report", "case_id": cid, "priority": 90, **context})
    return sorted(actions, key=lambda a: (-a["priority"], a["id"]))[:100]


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def collect(paths: AppPaths, db: Database, data: dict, remaining: float) -> dict:
    # Allocate before dispatch so an interrupted collection can resume the same
    # Run and its persisted request/byte budgets, never a fresh budget envelope.
    state = data["state"]
    if not state["source_run"]:
        from core import config_hash
        state["source_run"] = db.create_run(data["target"], 1, config_hash(Config(paths), PolicySet.load(paths)))
    state["collecting"] = True
    save(db, data, "running")
    directory = paths.output / "hunt-agent" / data["mission_id"]
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "collection.log"
    command = [sys.executable, str(paths.app / "recon_monitor.py"), "run", "--target=" + data["target"],
               "--resume", state["source_run"], "--no-progress"]
    with log.open("ab") as output:
        os.chmod(log, 0o600)
        process = subprocess.Popen(command, cwd=paths.root, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while process.poll() is None:
                if mission(db, data["mission_id"])["stop_requested"]:
                    raise InterruptedError("Collection stopped by mission control")
                time.sleep(.2)
        finally:
            _stop_process(process)
    state["collecting"] = False
    state["collection_complete"] = process.returncode == 0
    return {"source_run": state["source_run"], "exit_code": process.returncode,
            "collection_complete": process.returncode == 0, "log": str(log)}


def execute_action(paths: AppPaths, db: Database, data: dict, action: dict, remaining: float) -> dict:
    state, tool = data["state"], action["tool"]
    if tool == "recon":
        if data["options"]["offline"]:
            raise ReconError("Offline mission refused network collection")
        return collect(paths, db, data, remaining)
    if tool == "analysis":
        from analysis_engine import run_analysis
        result = run_analysis(paths, db, state["source_run"], data["target"])
        state["analysis_id"] = result["analysis_id"]
        return {"analysis_id": result["analysis_id"]}
    if tool == "investigate":
        from investigation_workflow import ensure_cluster_case
        result = ensure_cluster_case(db, analysis_id=state["analysis_id"], cluster_id=action["cluster_id"], target=data["target"], actor=ACTOR)
        cid = result["case_id"]
        state["cases"][cid] = {"cluster_id": action["cluster_id"], "family": action.get("family", "unknown"),
                               "coverage": result["evidence"]["coverage"]}
        return {"case_id": cid, "coverage": result["evidence"]["coverage"],
                "validation_level": result["validation"]["recommended_level"]}
    if tool == "browser":
        from xss_browser import read_plan, run as run_browser
        settings = data["options"]["browser"]
        source = Path(settings["path"])
        plan = read_plan(source)
        if hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest() != settings["sha256"]:
            raise ReconError("Browser plan changed; create a new mission")
        def control():
            if mission(db, data["mission_id"])["stop_requested"]:
                raise InterruptedError("Browser mission stopped")
        result = run_browser(paths, db, plan, analysis_id=state["analysis_id"],
            allow_active=True, verify=settings["verify"], allow_write=settings["write"], control=control,
            storage_state=settings.get("storage_state"), executable=settings.get("chromium"))
        if result["status"] != "completed":
            return {**result, "browser_incomplete": True}
        return result
    cid = action["case_id"]
    row = db.one("SELECT target FROM security_cases WHERE case_id=?", (cid,))
    if not row or row[0] != data["target"] or cid not in state["cases"]:
        raise ReconError("Case does not belong to this mission")
    if tool == "validate":
        from safe_validation import create_validation_plan, execute_validation_plan
        plan = create_validation_plan(paths, db, cid, requested_level="offline", actor=ACTOR)
        result = execute_validation_plan(paths, Config(paths), db, plan["plan_id"], actor=ACTOR)
        return {"case_id": cid, "validation_run": result["run_id"], "result": result["result"], "network_requests": 0}
    if tool == "live":
        if data["options"]["offline"] or not data["options"]["allow_live"]:
            raise ReconError("Mission does not permit live validation")
        from safe_validation import MAX_REQUESTS, execute_validation_plan
        row = db.one("SELECT case_id,target,level,status,plan_json FROM validation_plans WHERE plan_id=?", (action["plan_id"],))
        if not row or tuple(row)[:4] != (cid, data["target"], "passive_live", "approved"):
            raise ReconError("Only existing approved passive-live plans can be executed")
        reservation = min(MAX_REQUESTS, len(json.loads(row[4]).get("requests", [])))
        if not reservation:
            raise ReconError("Approved plan contains no executable requests")
        state["live_requests_reserved"] += reservation
        # Persist before dispatch; failures and interrupted requests retain their
        # reservation, including when the process is killed before returning.
        save(db, data, "running")
        result = execute_validation_plan(paths, Config(paths), db, action["plan_id"], allow_live=True, actor=ACTOR)
        return {"case_id": cid, "validation_run": result["run_id"], "result": result["result"], "network_requests": result.get("network_requests", 0)}
    if tool == "report":
        from workspace_v7 import build_evidence_linked_report
        result = build_evidence_linked_report(db, cid, actor=ACTOR)
        state["cases"][cid]["draft_id"] = result["draft_id"]
        return {"case_id": cid, "draft_id": result["draft_id"], "confirmed": result["confirmed"], "readiness": result["readiness"]}
    raise ReconError("Unknown agent tool")


def export_report(paths: AppPaths, db: Database, mid: str) -> dict:
    data = mission(db, mid)
    directory = paths.output / "hunt-agent" / mid
    directory.mkdir(parents=True, exist_ok=True)
    cases = []
    for cid, context in data["state"]["cases"].items():
        row = db.one("SELECT body_json,readiness_score FROM report_drafts WHERE draft_id=? AND case_id=?", (context.get("draft_id", ""), cid))
        cases.append({"case_id": cid, "draft": json.loads(row[0]) if row else None})
    payload = {"agent_version": AGENT_VERSION, "mission": data, "cases": cases,
               "notice": "Research drafts preserve evidence uncertainty. No platform submission or automatic analyst confirmation was performed."}
    path = directory / "mission.json"
    atomic_write_text(path, json.dumps(payload, indent=2) + "\n", 0o600)
    lines = ["# Hunt mission " + mid, "", "Status: " + data["status"], "Target: " + data["target"],
             "Source Run: " + data["state"]["source_run"], "", payload["notice"], "", "## Actions", ""]
    for step in data["steps"]:
        lines.append(f"- {step['step_number']}. {step['tool']}: {step['status']}")
    for item in cases:
        lines += ["", "## " + item["case_id"], "", "```json", json.dumps(item["draft"], indent=2), "```"]
    markdown = directory / "mission.md"
    atomic_write_text(markdown, "\n".join(lines) + "\n", 0o600)
    return {"mission_id": mid, "status": data["status"], "json": str(path), "markdown": str(markdown)}


def run_mission(paths: AppPaths, db: Database, mid: str, *, planner=None, progress=None) -> dict:
    data = mission(db, mid)
    if data["status"] in {"completed", "completed_with_gaps"}:
        return export_report(paths, db, mid)
    with target_lock(paths, data["target"]):
        try:
            check_policy(paths, data)
            planner = planner or (AIPlanner() if data["options"]["planner"] == "ai" else RulesPlanner())
        except Exception:
            save(db, data, "paused")
            export_report(paths, db, mid)
            raise
        started = data["started_at"] or time.time()
        db.execute("UPDATE hunt_missions SET started_at=?,stop_requested=0 WHERE mission_id=?", (started, mid))
        # A crashed live request is never automatically replayed. Other tools
        # are idempotent/offline, or resume the existing collection budget.
        db.execute("UPDATE hunt_steps SET status=CASE WHEN tool IN ('live','browser') THEN 'uncertain' ELSE 'interrupted' END,finished_at=? WHERE mission_id=? AND status='running'", (utc_now(), mid))
        save(db, data, "running")
        try:
            while True:
                data = mission(db, mid)
                check_policy(paths, data)
                remaining = float("inf")  # No mission lifetime quota.
                if data["stop_requested"]:
                    save(db, data, "paused")
                    break
                actions = actions_for(db, data)
                if not actions:
                    gaps = not data["state"].get("collection_complete", False) or any(s["status"] in {"partial", "failed", "uncertain"} for s in data["steps"])
                    status = "completed_with_gaps" if gaps else "completed"
                    save(db, data, status)
                    break
                history = []
                for step in data["steps"][-8:]:
                    observation = {"tool": step["tool"], "status": step["status"]}
                    result = step["result"]
                    if result.get("result") in {"strengthened", "weakened", "inconclusive", "manual_only"}:
                        observation["validation_result"] = result["result"]
                    for key in ("coverage", "readiness", "network_requests"):
                        if isinstance(result.get(key), (int, float)):
                            observation[key] = result[key]
                    if isinstance(result.get("collection_complete"), bool):
                        observation["collection_complete"] = result["collection_complete"]
                    history.append(observation)
                selected = planner.choose(actions, history, remaining)
                action = next((a for a in actions if a["id"] == selected), None)
                if action is None:
                    raise ReconError("Planner selected an action outside the offered set")
                # Stop and policy changes arriving during an AI call take effect
                # before tool dispatch. A decision never grants new permissions.
                check_policy(paths, data)
                if mission(db, mid)["stop_requested"]:
                    save(db, data, "paused")
                    break
                remaining = float("inf")  # No mission lifetime quota.
                number = len(data["steps"]) + 1
                if progress:
                    progress(f"HUNT {mid} step {number}: {action['tool']}")
                db.execute("INSERT INTO hunt_steps(mission_id,step_number,action_id,tool,status,started_at) VALUES(?,?,?,?,'running',?)", (mid, number, action["id"], action["tool"], utc_now()))
                try:
                    result = execute_action(paths, db, data, action, remaining)
                    status = "partial" if (action["tool"] == "recon" and not result.get("collection_complete")) or result.get("browser_incomplete") else "completed"
                except (KeyboardInterrupt, InterruptedError):
                    db.execute("UPDATE hunt_steps SET status=?,finished_at=? WHERE mission_id=? AND step_number=?",
                               ("uncertain" if action["tool"] in {"live", "browser"} else "interrupted", utc_now(), mid, number))
                    save(db, data, "paused")
                    break
                except Exception as exc:
                    result, status = {"error_type": type(exc).__name__, "error": "Tool failed; inspect its existing engine diagnostics."}, "failed"
                with db.transaction():
                    db.execute("UPDATE hunt_steps SET status=?,result_json=?,finished_at=? WHERE mission_id=? AND step_number=?", (status, json.dumps(result), utc_now(), mid, number))
                    save(db, data, "running")
                db.audit("hunt_step_finished", actor=ACTOR, target=data["target"], entity_type="hunt", entity_value=mid, details={"step": number, "tool": action["tool"], "status": status})
                if progress:
                    progress(f"HUNT {mid} step {number}: {status}")
        except KeyboardInterrupt:
            save(db, data, "paused")
        except Exception:
            save(db, data, "paused")
            export_report(paths, db, mid)
            raise
    return export_report(paths, db, mid)


def add_parser(subparsers):
    parser = subparsers.add_parser("agent", help="Run persistent autonomous bug bounty research missions")
    parser.add_argument("action", choices=["run", "resume", "status", "list", "stop", "report"])
    parser.add_argument("--browser-storage-state", default="")
    parser.add_argument("--browser-chromium", default="")
    parser.add_argument("--browser-plan", default="", help="Reviewed XSS browser plan; frozen by hash")
    parser.add_argument("--allow-browser-active", action="store_true")
    parser.add_argument("--verify-browser-execution", action="store_true")
    parser.add_argument("--allow-browser-write", action="store_true")
    parser.add_argument("--target", default="")
    parser.add_argument("--mission", default="")
    parser.add_argument("--run", dest="source_run", default="")
    parser.add_argument("--offline", action="store_true", help="Use stored evidence; no target requests")
    parser.add_argument("--allow-live", action="store_true", help="Execute existing approved passive-live plans")
    parser.add_argument("--planner", choices=["ai", "rules"], default="ai")
    parser.add_argument("--max-steps", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--max-cases", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--max-runtime", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--max-live-requests", type=int, default=None, help=argparse.SUPPRESS)


def cli(paths: AppPaths, args) -> dict | list:
    if not paths.config.exists():
        raise ReconError("config.env not found. Run init first.")
    db = Database(paths.db)
    try:
        install(db)
        if args.action == "run":
            if not args.target:
                raise ReconError("agent run requires --target")
            data = create_mission(paths, db, target=args.target, source_run=args.source_run,
                                  offline=args.offline, allow_live=args.allow_live, planner=args.planner,
                                  max_steps=args.max_steps, max_cases=args.max_cases, max_runtime=args.max_runtime,
                                  max_live_requests=args.max_live_requests, browser_plan=args.browser_plan,
                                  browser_active=args.allow_browser_active,
                                  browser_verify=args.verify_browser_execution, browser_write=args.allow_browser_write,
                                  browser_storage_state=args.browser_storage_state, browser_chromium=args.browser_chromium)
            print("Hunt mission: " + data["mission_id"], flush=True)
            return run_mission(paths, db, data["mission_id"], progress=lambda value: print(value, file=sys.stderr, flush=True))
        if args.action == "list":
            return [dict(r) for r in db.all("SELECT mission_id,target,status,created_at,updated_at FROM hunt_missions ORDER BY created_at DESC LIMIT 100")]
        if not args.mission:
            raise ReconError("This agent action requires --mission")
        data = mission(db, args.mission)
        if args.action == "resume":
            return run_mission(paths, db, args.mission, progress=lambda value: print(value, file=sys.stderr, flush=True))
        if args.action == "stop":
            db.execute("UPDATE hunt_missions SET stop_requested=1,updated_at=? WHERE mission_id=?", (utc_now(), args.mission))
            return {"mission_id": args.mission, "stop_requested": True}
        if args.action == "report":
            return export_report(paths, db, args.mission)
        return data
    finally:
        db.close()
