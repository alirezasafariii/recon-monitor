from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "app/analysis_632_evidence.py"

text = PATH.read_text(encoding="utf-8")
old = "from family_detectors.registry import DETECTOR_SPECS\nfrom hypothesis_admission import FAMILY_ADMISSION_POLICIES\n"
new = "from hypothesis_admission import FAMILY_ADMISSION_POLICIES\n\n\ndef _detector_specs():\n    # Lazy import avoids package __init__ -> execution -> reconstruction cycle.\n    from family_detectors.registry import DETECTOR_SPECS\n    return DETECTOR_SPECS\n"
if old not in text:
    raise RuntimeError("Analysis 6.32 lazy-registry import anchor missing")
text = text.replace(old, new, 1)
text = text.replace("DETECTOR_SPECS[family]", "_detector_specs()[family]")
text = text.replace("for family, spec in DETECTOR_SPECS.items():", "for family, spec in _detector_specs().items():")
PATH.write_text(text, encoding="utf-8")
print("Analysis 6.32 detector registry import made lazy")
