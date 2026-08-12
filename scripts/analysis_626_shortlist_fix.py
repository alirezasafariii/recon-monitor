from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app" / "raw_recon_v4_shortlist.py"
text = PATH.read_text(encoding="utf-8")

replacements = {
    'DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"\n': 'DEFAULT_OUTPUT = ROOT / "benchmarks" / "raw" / "sources" / "v4_shortlist.json"\nDEFAULT_SUPPLEMENT = ROOT / "benchmarks" / "raw" / "sources" / "v4_primary_supplement.json"\n',
    '    "business_logic": (("business logic", "workflow", "state transition", "sequence", "process flow"), ("bypass", "invariant", "price", "value", "limit", "step", "transition")),\n': '    "business_logic": (("business logic", "workflow", "state transition", "sequence", "process flow", "payment status", "digital products", "download"), ("bypass", "invariant", "price", "value", "limit", "step", "transition", "payment status", "status check", "proper payment")),\n',
    '    "race_condition": (("race condition", "race", "concurrent", "simultaneous", "parallel", "atomic"), ("double", "duplicate", "single-use", "single use", "balance", "redeem", "claim", "transfer")),\n': '    "race_condition": (("race condition", "race", "concurrent", "simultaneous", "parallel", "atomic", "time-of-check", "time of check", "toctou"), ("double", "duplicate", "single-use", "single use", "balance", "redeem", "claim", "transfer", "time-of-check", "time of check", "toctou", "file upload", "overwrite")),\n',
    '    "sensitive_business_flow_abuse": (("automation", "bot", "scalp", "abuse", "business flow", "reservation", "booking", "signup", "redeem", "coupon", "purchase"), ("limit", "frequency", "bulk", "multiple", "unrestricted", "rate", "bypass")),\n': '    "sensitive_business_flow_abuse": (("automation", "bot", "scalp", "abuse", "business flow", "reservation", "booking", "signup", "redeem", "coupon", "purchase", "password reset", "flood"), ("limit", "frequency", "bulk", "multiple", "unrestricted", "rate", "bypass", "flood control", "flooding")),\n',
    'def build_shortlist(candidates: Mapping[str, Any]) -> dict[str, Any]:\n    pools = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}\n': 'def build_shortlist(candidates: Mapping[str, Any], supplemental: Mapping[str, Any] | None = None) -> dict[str, Any]:\n    raw_pools = candidates.get("candidates_by_family") if isinstance(candidates.get("candidates_by_family"), Mapping) else {}\n    pools: dict[str, list[dict[str, Any]]] = {\n        str(family): [dict(row) for row in rows if isinstance(row, Mapping)]\n        for family, rows in raw_pools.items()\n        if isinstance(rows, list)\n    }\n    if supplemental is not None:\n        for raw in supplemental.get("selected") or []:\n            if not isinstance(raw, Mapping):\n                continue\n            row = dict(raw)\n            family = str(row.get("family") or "")\n            if family not in pools:\n                raise RuntimeError(f"supplement family is outside candidate registry: {family}")\n            if not bool(row.get("freshness_validated")):\n                raise RuntimeError(f"supplement source is not freshness-validated: {family}")\n            pools[family].append(row)\n',
    '    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))\n    args = parser.parse_args()\n    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))\n    report = build_shortlist(candidates)\n': '    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))\n    parser.add_argument("--supplement", default=str(DEFAULT_SUPPLEMENT))\n    args = parser.parse_args()\n    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))\n    supplement_path = Path(args.supplement)\n    supplemental = json.loads(supplement_path.read_text(encoding="utf-8")) if supplement_path.exists() else None\n    report = build_shortlist(candidates, supplemental)\n',
}

for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f"Analysis 6.26 shortlist patch marker missing: {old[:120]!r}")
    text = text.replace(old, new, 1)

PATH.write_text(text, encoding="utf-8")
