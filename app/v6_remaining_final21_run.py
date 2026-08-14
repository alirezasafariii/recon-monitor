from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import v6_remaining_final21_collector as collector


def _norm(value: str) -> str:
    value = re.sub(r"[`*_#~]+", "", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip().casefold()


def _display_norm(value: str) -> str:
    value = re.sub(r"[`*_#~]+", "", value)
    return re.sub(r"\s+", " ", value).strip()


def normalized_require(source: collector.Source, *needles: str) -> None:
    haystack = _norm(source.text)
    missing = [needle for needle in needles if _norm(needle) not in haystack]
    if missing:
        raise RuntimeError(f"missing normalized markers in {source.reference}: {missing}")


def normalized_excerpt(source: collector.Source, needle: str, width: int = 800) -> str:
    normalized = _display_norm(source.text)
    folded = normalized.casefold()
    pos = folded.find(_norm(needle))
    matched_len = len(_display_norm(needle))
    if pos < 0:
        # Excerpt lookup may tolerate wording inflection only after the source has
        # already passed the strict require() markers for that family. Anchor on
        # the longest real token from the requested phrase; never synthesize text.
        tokens = sorted(
            {token for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9-]{3,}", _display_norm(needle))},
            key=len,
            reverse=True,
        )
        for token in tokens:
            candidate = folded.find(token.casefold())
            if candidate >= 0:
                pos = candidate
                matched_len = len(token)
                break
    if pos < 0:
        raise RuntimeError(f"normalized marker not found in {source.reference}: {needle!r}")
    start = max(0, pos - 120)
    end = min(len(normalized), pos + matched_len + width)
    return normalized[start:end]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the final Analysis 6.31 collector with normalized source-marker excerpts")
    parser.add_argument("output", nargs="?", type=Path, default=Path("captured-final21"))
    args = parser.parse_args()
    collector.require = normalized_require
    collector.excerpt = normalized_excerpt
    result = collector.collect(args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
