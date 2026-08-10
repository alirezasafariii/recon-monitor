#!/usr/bin/env python3
from __future__ import annotations

"""Recon Monitor CLI compatibility surface with Investigation Queue access.

The established CLI implementation remains in ``recon_monitor_core``.  This
module preserves every existing command and adds ``analysis investigation-queue``
inside the current Analysis command family.
"""

import sys
from typing import Any

import recon_monitor_core as _base
from correlation_engine import (
    CORRELATION_ENGINE_VERSION,
    CORRELATION_RULE_VERSION,
    investigation_queue,
)
from meta_ranker import META_RANKER_VERSION, META_RANKER_RULE_VERSION


INVESTIGATION_CLI_VERSION = "1.0.0"

for _name, _value in vars(_base).items():
    if _name not in {
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__file__",
        "__cached__",
        "__builtins__",
    }:
        globals()[_name] = _value


_ORIGINAL_BUILD_PARSER = getattr(_base, "_VI_ORIGINAL_BUILD_PARSER", _base.build_parser)
_ORIGINAL_MAIN = getattr(_base, "_VI_ORIGINAL_MAIN", _base.main)
_base._VI_ORIGINAL_BUILD_PARSER = _ORIGINAL_BUILD_PARSER
_base._VI_ORIGINAL_MAIN = _ORIGINAL_MAIN


def _analysis_parser(parser: Any) -> Any:
    for action in getattr(parser, "_actions", []):
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and "analysis" in choices:
            return choices["analysis"]
    raise RuntimeError("Analysis CLI parser is unavailable")


def build_parser():
    parser = _ORIGINAL_BUILD_PARSER()
    analysis_parser = _analysis_parser(parser)
    for action in getattr(analysis_parser, "_actions", []):
        if getattr(action, "dest", "") != "action":
            continue
        choices = list(getattr(action, "choices", []) or [])
        if "investigation-queue" not in choices:
            choices.append("investigation-queue")
            action.choices = choices
        break
    return parser


def _latest_analysis_id(db: Any) -> str:
    row = db.one(
        "SELECT id FROM analysis_runs WHERE status='success' "
        "ORDER BY COALESCE(finished_at,started_at) DESC LIMIT 1"
    )
    return str(row["id"]) if row else ""


def investigation_queue_cli_payload(
    db: Any,
    *,
    analysis_id: str = "",
    target: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    selected_analysis = str(analysis_id or "").strip() or _latest_analysis_id(db)
    bounded_limit = max(1, min(500, int(limit or 20)))
    items = (
        investigation_queue(
            db,
            selected_analysis,
            target=str(target or "").strip() or None,
            limit=bounded_limit,
        )
        if selected_analysis
        else []
    )
    return {
        "cli_version": INVESTIGATION_CLI_VERSION,
        "analysis_id": selected_analysis,
        "target": str(target or "").strip() or None,
        "count": len(items),
        "items": items,
        "engines": {
            "meta_ranker": {
                "version": META_RANKER_VERSION,
                "rule_version": META_RANKER_RULE_VERSION,
            },
            "correlation": {
                "version": CORRELATION_ENGINE_VERSION,
                "rule_version": CORRELATION_RULE_VERSION,
            },
        },
        "safety": {
            "status": "investigation_queue_not_confirmed",
            "queue_is_not_vulnerability_confirmation": True,
            "correlation_cannot_satisfy_admission": True,
            "target_evidence_confidence_uses_target_observations_only": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    translated = _base.translate_legacy_args(raw_argv)
    if len(translated) >= 2 and translated[0] == "analysis" and translated[1] == "investigation-queue":
        parser = build_parser()
        args = parser.parse_args(translated)
        paths = _base.AppPaths.from_root(_base.ROOT_DIR)
        paths.ensure()
        if not paths.config.exists():
            raise _base.ReconError("config.env not found. Run ./recon-monitor.sh init")
        db = _base.Database(paths.db)
        try:
            payload = investigation_queue_cli_payload(
                db,
                analysis_id=str(args.analysis_id or ""),
                target=str(args.target or ""),
                limit=int(args.limit or 20),
            )
        finally:
            db.close()
        print(_base.json_dumps(payload, pretty=True))
        return 0
    return _ORIGINAL_MAIN(argv)


# Existing main() calls build_parser() through its module globals.  Point that
# lookup at the compatibility parser so help/validation includes the new action
# while every existing command keeps its original implementation.
_base.build_parser = build_parser


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except _base.ReconError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
