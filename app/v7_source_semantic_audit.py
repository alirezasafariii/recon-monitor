from __future__ import annotations

import re
from typing import Any, Mapping

from raw_recon_v5_source_audit import AUDIT_RULE_VERSION, AUDIT_VERSION, audit_row as _audit_row

VERSION = "1.0.0"
RULE_VERSION = "2026.08.14.6.32.v7.10"

# Syntax-only normalizations. They do not add a security concept that is absent
# from the source; they normalize punctuation/casing/common identifier spelling
# before the existing strict family audit runs.
_NORMALIZATIONS: tuple[tuple[str, str], ...] = (
    (r"\bman[- ]in[- ]the[- ]middle\b", "man in the middle"),
    (r"\bmachine[- ]in[- ]the[- ]middle\b", "man in the middle"),
    (r"\bmitm\b", "man in the middle"),
    (r"\bhttpclient\b", "http client"),
    (r"\bhttps\s+client\b", "http client"),
    (r"\bhttps\s+fetch\s+client\b", "http client"),
    (r"\bshell[- ]injection\b", "shell injection"),
    (r"\bos[- ]command\b", "os command"),
    (r"\bcross[- ]tenant\b", "cross tenant"),
    (r"\bcross[- ]origin\b", "cross origin"),
    (r"\bsource[- ]map\b", "source map"),
    (r"\bserver[- ]side\b", "server side"),
)


def normalize_source_text(value: Any) -> str:
    text = str(value or "")
    for pattern, replacement in _NORMALIZATIONS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def normalized_row(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in ("summary", "description", "patch_text"):
        if key in result:
            result[key] = normalize_source_text(result.get(key))
    return result


def audit_row(family: str, row: Mapping[str, Any]):
    return _audit_row(family, normalized_row(row))


__all__ = [
    "VERSION",
    "RULE_VERSION",
    "AUDIT_VERSION",
    "AUDIT_RULE_VERSION",
    "normalize_source_text",
    "normalized_row",
    "audit_row",
]
