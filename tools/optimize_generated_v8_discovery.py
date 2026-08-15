from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app/raw_recon_v8_source_discovery.py"


def main() -> int:
    text = PATH.read_text(encoding="utf-8")
    pools_anchor = '    pools = report.get("candidates_by_family") if isinstance(report.get("candidates_by_family"), Mapping) else {}\n'
    call_anchor = '            check = check_candidate(row)\n'
    if '    prior_index = exposure_index()\n' not in text:
        if pools_anchor not in text:
            raise RuntimeError("v8 discovery pool anchor missing")
        text = text.replace(pools_anchor, pools_anchor + '    prior_index = exposure_index()\n', 1)
    if call_anchor in text:
        text = text.replace(call_anchor, '            check = check_candidate(row, index=prior_index)\n')
    if 'check_candidate(row, index=prior_index)' not in text:
        raise RuntimeError("v8 discovery cached-firewall rewrite failed")
    PATH.write_text(text, encoding="utf-8")
    print("v8 discovery firewall index cached once per discovery run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
