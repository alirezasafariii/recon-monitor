from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from raw_recon_corpus import ROOT

PLAN = ROOT / "benchmarks/raw/sources/v6_literal_capture_plan.json"
FEAS = ROOT / "benchmarks/raw/sources/v6_literal_capture_feasibility.json"
LINKED = ROOT / "benchmarks/raw/sources/v6_literal_linked_summary.json"
OUTPUT = ROOT / "benchmarks/raw/sources/v6_remaining_capture_index.tsv"


def main() -> int:
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    feas = json.loads(FEAS.read_text(encoding="utf-8"))
    linked = json.loads(LINKED.read_text(encoding="utf-8"))
    frows = {str(row.get("family") or ""): row for row in feas.get("families") or [] if isinstance(row, Mapping)}
    lrows = linked.get("families") if isinstance(linked.get("families"), Mapping) else linked
    if not isinstance(lrows, Mapping):
        lrows = {}
    reqs = [row for row in plan.get("requirements") or [] if isinstance(row, Mapping)]
    families = sorted({str(row.get("family") or "") for row in reqs if not bool(row.get("evidence_present"))})
    lines = ["family\ttier\tsource_root\tsource_project\tcanonical_reference\tlinked_success\thas_change_artifact"]
    for family in families:
        rows = [row for row in reqs if str(row.get("family") or "") == family]
        row = rows[0]
        fr = frows.get(family, {})
        lr = lrows.get(family) if isinstance(lrows.get(family), Mapping) else {}
        values = [
            family,
            str(fr.get("feasibility_tier") or ""),
            str(row.get("source_root") or ""),
            str(row.get("source_project") or ""),
            str(row.get("canonical_source_reference") or fr.get("canonical_reference") or ""),
            str(fr.get("successful_link_snapshot_count") or len(lr.get("successful_resources") or [])),
            str(bool(fr.get("has_change_artifact"))).lower(),
        ]
        lines.append("\t".join(value.replace("\t", " ").replace("\n", " ") for value in values))
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"indexed {len(families)} remaining families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
