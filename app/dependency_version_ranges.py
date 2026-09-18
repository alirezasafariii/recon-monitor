from __future__ import annotations

"""Fail-closed affected-version range evaluation for dependency advisories.

Recon Monitor keeps observed component versions exact and fail-closed. Generic
numeric releases retain ecosystem-neutral ordering. SemVer-compatible
ecosystems may additionally evaluate exact prerelease/build versions when the
range branch explicitly admits that prerelease release line. Advisory range
boundaries may be richer. This module evaluates only syntax whose ordering
semantics are explicit for the advisory ecosystem.

Unsupported syntax never becomes a positive match. For union expressions, a
fully understood branch may safely produce a positive match even when another
union branch is unsupported; a conjunction is never partially evaluated.
"""

import re
from typing import Iterable

DEPENDENCY_VERSION_RANGE_VERSION = "1.3.0"
DEPENDENCY_VERSION_RANGE_RULE_VERSION = "2026.09.19.1"

SEMVER_ECOSYSTEMS = frozenset(
    {
        "actions",
        "composer",
        "erlang",
        "go",
        "npm",
        "nuget",
        "pub",
        "rust",
        "swift",
    }
)
PEP440_ECOSYSTEMS = frozenset({"pip"})
RUBYGEMS_ECOSYSTEMS = frozenset({"rubygems"})
MAVEN_ECOSYSTEMS = frozenset({"maven"})

_RELEASE_RE = re.compile(r"^v?(\d+(?:\.\d+){0,7})$", re.I)
_COMPARATOR_CLAUSE_RE = re.compile(
    r"^(<=|>=|!=|==|=|<|>)?\s*(\S+)\s*$"
)
_EXPLICIT_COMPARATOR_RE = re.compile(
    r"(<=|>=|!=|==|=|<|>)\s*([^\s,]+)"
)
_SEMVER_RE = re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z.-]+))?"
    r"(?:\+([0-9A-Za-z.-]+))?$"
)
_LOOSE_SEMVER_LABEL_RE = re.compile(
    r"^v?(\d+(?:\.\d+){0,2})"
    r"(?:[-._]?([A-Za-z][0-9A-Za-z.-]*))"
    r"(?:\+([0-9A-Za-z.-]+))?$",
    re.I,
)
_COMPOSER_LABEL_RE = re.compile(
    r"^v?(\d+(?:\.\d+){0,3})"
    r"(?:[-._]?([A-Za-z][0-9A-Za-z.-]*))"
    r"(?:\+([0-9A-Za-z.-]+))?$",
    re.I,
)
_PEP440_IMPLICIT_POST_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)-(\d+(?:\.\d+)*)$",
    re.I,
)
_PEP440_P_POST_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)(?:[._-]?p)(\d+(?:\.\d+)*)$",
    re.I,
)
_PEP440_RE = re.compile(
    r"^v?"
    r"(?:(\d+)!)?"
    r"(\d+(?:\.\d+)*)"
    r"(?:(?:[-_.]?)(a|b|c|rc|alpha|beta|pre|preview)(?:[-_.]?)(\d*))?"
    r"(?:(?:[-_.]?)(post|rev|r)(?:[-_.]?)(\d*))?"
    r"(?:(?:[-_.]?)dev(?:[-_.]?)(\d*))?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
    re.I,
)
_RUBYGEMS_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)"
    r"(?:(?:[._-]?)(pre|alpha|a|beta|b|rc)(?:[._-]?)(\d*))?$",
    re.I,
)
_MAVEN_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)(?:[._-](.+))?$",
    re.I,
)
_WILDCARD_RE = re.compile(
    r"^v?(\d+(?:\.\d+)*)(?:\.(x|X|\*))$"
)
_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")
_MAVEN_INTERVAL_RE = re.compile(
    r"^\s*(\[|\()\s*([^,]*)\s*,\s*([^\]\)]*)\s*(\]|\))\s*$"
)

_PRE_LABELS = {
    "a": "a",
    "alpha": "a",
    "b": "b",
    "beta": "b",
    "c": "rc",
    "rc": "rc",
    "pre": "rc",
    "preview": "rc",
}
_MAVEN_PRE = {
    "alpha",
    "a",
    "beta",
    "b",
    "milestone",
    "m",
    "rc",
    "cr",
    "snapshot",
}
_MAVEN_EQUAL = {"ga", "final", "release"}
_MAVEN_POST = {"sp"}


def normalize_ecosystem(value: str) -> str:
    return str(value or "").strip().lower()


def _release_tuple(value: str) -> tuple[int, ...] | None:
    match = _RELEASE_RE.fullmatch(str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_release(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def _semver_identifiers(value: str) -> tuple[str, ...] | None:
    text = str(value or "")
    if not text:
        return ()
    parts = tuple(text.split("."))
    if not parts or any(
        not part or re.fullmatch(r"[0-9A-Za-z-]+", part) is None
        for part in parts
    ):
        return None
    return parts


def _compare_semver_identifiers(
    left: tuple[str, ...],
    right: tuple[str, ...],
) -> int:
    for left_part, right_part in zip(left, right):
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            left_value = int(left_part)
            right_value = int(right_part)
            if left_value < right_value:
                return -1
            if left_value > right_value:
                return 1
            continue
        if left_numeric != right_numeric:
            # SemVer numeric identifiers always have lower precedence than
            # non-numeric identifiers.
            return -1 if left_numeric else 1
        if left_part < right_part:
            return -1
        if left_part > right_part:
            return 1
    if len(left) < len(right):
        return -1
    if len(left) > len(right):
        return 1
    return 0


def _known_loose_semver_stage(
    label: str,
) -> tuple[int, tuple[str, ...]] | None:
    text = str(label or "").strip()
    lowered = text.lower()
    if re.match(
        r"^(alpha|a|beta|b|rc|pre|preview|dev|milestone|m)(?:[._-]?\d.*)?$",
        lowered,
        re.I,
    ):
        identifiers = _semver_identifiers(
            re.sub(r"[_]+", ".", lowered)
        )
        return (-1, identifiers) if identifiers is not None else None
    if re.match(r"^(patch|p|pl)(?:[._-]?\d.*)?$", lowered, re.I):
        identifiers = _semver_identifiers(
            re.sub(r"[_]+", ".", lowered)
        )
        return (1, identifiers) if identifiers is not None else None
    return None


def _semver_value(
    value: str,
    ecosystem: str,
) -> tuple[tuple[int, ...], int, tuple[str, ...]] | None:
    """Parse only version forms whose precedence is explicit to this matcher.

    stage is -1 for prerelease, 0 for stable and 1 for recognized post-release
    labels retained for backward-compatible Composer/legacy boundary handling.
    Build metadata is intentionally ignored by precedence.
    """

    text = str(value or "").strip()
    ecosystem = normalize_ecosystem(ecosystem)

    release = _release_tuple(text)
    if release is not None:
        return release, 0, ()

    match = _SEMVER_RE.fullmatch(text)
    if match:
        release = tuple(int(match.group(index)) for index in (1, 2, 3))
        prerelease = str(match.group(4) or "")
        if not prerelease:
            return release, 0, ()
        identifiers = _semver_identifiers(prerelease)
        if identifiers is None:
            return None
        return release, -1, identifiers

    label_match = (
        _COMPOSER_LABEL_RE.fullmatch(text)
        if ecosystem == "composer"
        else _LOOSE_SEMVER_LABEL_RE.fullmatch(text)
    )
    if not label_match:
        return None
    release = tuple(
        int(part) for part in str(label_match.group(1)).split(".")
    )
    stage = _known_loose_semver_stage(
        str(label_match.group(2) or "")
    )
    if stage is None:
        return None
    relative, identifiers = stage
    return release, relative, identifiers


def _compare_semver_values(
    left_text: str,
    right_text: str,
    ecosystem: str,
) -> int | None:
    left = _semver_value(left_text, ecosystem)
    right = _semver_value(right_text, ecosystem)
    if left is None or right is None:
        return None
    left_release, left_stage, left_identifiers = left
    right_release, right_stage, right_identifiers = right
    release_cmp = _compare_release(left_release, right_release)
    if release_cmp:
        return release_cmp
    if left_stage < right_stage:
        return -1
    if left_stage > right_stage:
        return 1
    if left_stage == 0:
        return 0
    return _compare_semver_identifiers(
        left_identifiers,
        right_identifiers,
    )


def _semver_release_for_shorthand(
    value: str,
    ecosystem: str,
) -> tuple[int, ...] | None:
    release = _release_tuple(value)
    if release is not None:
        return release
    parsed = _semver_value(value, ecosystem)
    if parsed is None:
        return None
    return parsed[0]


def _semver_branch_has_prerelease_anchor(
    branch: str,
    observed_release: tuple[int, ...],
    ecosystem: str,
) -> bool:
    text = str(branch or "").strip()
    candidates: list[str] = []
    if text.startswith("^"):
        candidates.append(text[1:].strip())
    elif text.startswith("~") and not text.startswith("~="):
        candidates.append(text[1:].strip())
    else:
        hyphen = _HYPHEN_RE.fullmatch(text)
        if hyphen:
            candidates.extend([hyphen.group(1), hyphen.group(2)])
        else:
            for part in _split_comparator_conjunction(text) or ():
                match = _COMPARATOR_CLAUSE_RE.fullmatch(part)
                if match:
                    candidates.append(str(match.group(2) or ""))

    for candidate in candidates:
        parsed = _semver_value(candidate, ecosystem)
        if parsed is None:
            continue
        release, stage, _identifiers = parsed
        if stage == -1 and _compare_release(
            release,
            observed_release,
        ) == 0:
            return True
    return False


def _semver_boundary(value: str) -> tuple[tuple[int, ...], int] | None:
    text = str(value or "").strip()
    match = _SEMVER_RE.fullmatch(text)
    if match:
        release = tuple(int(match.group(index)) for index in (1, 2, 3))
        # Relative to a stable release with the same numeric release:
        # prerelease < stable; build metadata does not affect precedence.
        relative_to_stable = -1 if match.group(4) else 0
        return release, relative_to_stable

    loose = _LOOSE_SEMVER_LABEL_RE.fullmatch(text)
    if not loose:
        return None
    release = tuple(int(part) for part in loose.group(1).split("."))
    release = release + (0,) * (3 - len(release))
    label = str(loose.group(2) or "").lower()
    pre_match = re.match(
        r"^(alpha|a|beta|b|rc|pre|preview|dev|milestone|m)(?:[._-]?\d.*)?$",
        label,
        re.I,
    )
    if pre_match:
        return release, -1
    post_match = re.match(r"^(patch|p|pl)(?:[._-]?\d.*)?$", label, re.I)
    if post_match:
        return release, 1
    return None


def _composer_boundary(value: str) -> tuple[tuple[int, ...], int] | None:
    match = _COMPOSER_LABEL_RE.fullmatch(str(value or "").strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    label = str(match.group(2) or "").lower()
    if re.match(
        r"^(alpha|a|beta|b|rc|pre|preview|dev)(?:[._-]?\d.*)?$",
        label,
        re.I,
    ):
        return release, -1
    if re.match(r"^(patch|p|pl)(?:[._-]?\d.*)?$", label, re.I):
        return release, 1
    return None


def _pep440_boundary(value: str) -> tuple[int, tuple[int, ...], int] | None:
    text = str(value or "").strip()

    implicit_post = _PEP440_IMPLICIT_POST_RE.fullmatch(text)
    if implicit_post:
        release = tuple(int(part) for part in implicit_post.group(1).split("."))
        return 0, release, 1

    p_post = _PEP440_P_POST_RE.fullmatch(text)
    if p_post:
        release = tuple(int(part) for part in p_post.group(1).split("."))
        return 0, release, 1

    match = _PEP440_RE.fullmatch(text)
    if not match:
        return None
    epoch = int(match.group(1) or 0)
    release = tuple(int(part) for part in match.group(2).split("."))
    pre = _PRE_LABELS.get(str(match.group(3) or "").lower())
    post = str(match.group(5) or "").lower()
    dev_present = match.group(7) is not None
    if post:
        relative_to_stable = 1
    elif pre or dev_present:
        relative_to_stable = -1
    else:
        relative_to_stable = 0
    return epoch, release, relative_to_stable

def _rubygems_boundary(value: str) -> tuple[tuple[int, ...], int] | None:
    text = str(value or "").strip()
    match = _RUBYGEMS_RE.fullmatch(text)
    if match:
        release = tuple(int(part) for part in match.group(1).split("."))
        relative_to_stable = -1 if match.group(2) else 0
        return release, relative_to_stable

    broad = re.fullmatch(
        r"^v?(\d+(?:\.\d+)*)(?:[._-](.*[A-Za-z].*))$",
        text,
        re.I,
    )
    if not broad:
        return None
    release = tuple(int(part) for part in broad.group(1).split("."))
    # Gem::Version considers alphabetic segments prerelease markers relative
    # to the corresponding numeric release.
    return release, -1


def _maven_boundary(value: str) -> tuple[tuple[int, ...], int] | None:
    match = _MAVEN_RE.fullmatch(str(value or "").strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    qualifier = str(match.group(2) or "").lower()
    if not qualifier:
        return release, 0

    qualifier_head_match = re.match(r"^([a-z]+)", qualifier, re.I)
    qualifier_head = (
        qualifier_head_match.group(1).lower()
        if qualifier_head_match
        else qualifier
    )
    if qualifier_head in _MAVEN_EQUAL:
        relative_to_stable = 0
    elif qualifier_head in _MAVEN_PRE:
        relative_to_stable = -1
    elif qualifier_head in _MAVEN_POST:
        relative_to_stable = 1
    else:
        # Maven ComparableVersion sorts unknown qualifiers after the exact
        # release qualifier. Relative to an observed stable numeric release,
        # such a qualifier is later.
        relative_to_stable = 1
    return release, relative_to_stable


def _compare_stable_observed_to_boundary(
    observed: tuple[int, ...],
    boundary_text: str,
    ecosystem: str,
) -> int | None:
    boundary_release = _release_tuple(boundary_text)
    if boundary_release is not None:
        return _compare_release(observed, boundary_release)

    ecosystem = normalize_ecosystem(ecosystem)
    if ecosystem == "composer":
        parsed = _composer_boundary(boundary_text)
        if parsed is not None:
            release, relative = parsed
            release_cmp = _compare_release(observed, release)
            if release_cmp:
                return release_cmp
            return -relative

    if ecosystem in SEMVER_ECOSYSTEMS:
        parsed = _semver_boundary(boundary_text)
        if parsed is None:
            return None
        release, relative = parsed
        release_cmp = _compare_release(observed, release)
        if release_cmp:
            return release_cmp
        # boundary relative=-1 means boundary < stable observed.
        return -relative

    if ecosystem in PEP440_ECOSYSTEMS:
        parsed = _pep440_boundary(boundary_text)
        if parsed is None:
            return None
        epoch, release, relative = parsed
        if epoch > 0:
            return -1
        release_cmp = _compare_release(observed, release)
        if release_cmp:
            return release_cmp
        return -relative

    if ecosystem in RUBYGEMS_ECOSYSTEMS:
        parsed = _rubygems_boundary(boundary_text)
        if parsed is None:
            return None
        release, relative = parsed
        release_cmp = _compare_release(observed, release)
        if release_cmp:
            return release_cmp
        return -relative

    if ecosystem in MAVEN_ECOSYSTEMS:
        parsed = _maven_boundary(boundary_text)
        if parsed is None:
            return None
        release, relative = parsed
        release_cmp = _compare_release(observed, release)
        if release_cmp:
            return release_cmp
        return -relative

    return None


def _operator_matches(comparison: int, operator: str) -> bool:
    if operator in {"", "=", "=="}:
        return comparison == 0
    if operator == "!=":
        return comparison != 0
    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    return False


def _boundary_supported(boundary: str, ecosystem: str) -> bool:
    probe = (1, 2, 3)
    return _compare_stable_observed_to_boundary(
        probe,
        boundary,
        ecosystem,
    ) is not None


def _split_comparator_conjunction(branch: str) -> list[str] | None:
    text = str(branch or "").strip()
    if not text:
        return None
    if "," in text:
        parts = [part.strip() for part in text.split(",") if part.strip()]
        return parts or None

    matches = list(_EXPLICIT_COMPARATOR_RE.finditer(text))
    if len(matches) >= 2:
        consumed = "".join(match.group(0) for match in matches)
        compact_text = re.sub(r"\s+", "", text)
        compact_consumed = re.sub(r"\s+", "", consumed)
        if compact_text == compact_consumed:
            return [match.group(0).strip() for match in matches]

    return [text]


def _wildcard_bounds(value: str) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    match = _WILDCARD_RE.fullmatch(str(value or "").strip())
    if not match:
        return None
    prefix = tuple(int(part) for part in match.group(1).split("."))
    if not prefix:
        return None
    lower = prefix + (0,)
    upper_prefix = list(prefix)
    upper_prefix[-1] += 1
    upper = tuple(upper_prefix) + (0,)
    return lower, upper


def _caret_bounds(
    value: str,
    ecosystem: str = "",
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _semver_release_for_shorthand(value, ecosystem)
    if release is None or len(release) > 3:
        return None
    padded = release + (0,) * (3 - len(release))
    major, minor, patch = padded
    lower = padded
    if major > 0:
        upper = (major + 1, 0, 0)
    elif minor > 0:
        upper = (0, minor + 1, 0)
    elif patch > 0:
        upper = (0, 0, patch + 1)
    elif len(release) == 1:
        upper = (1, 0, 0)
    elif len(release) == 2:
        upper = (0, 1, 0)
    else:
        upper = (0, 0, 1)
    return lower, upper


def _tilde_bounds(
    value: str,
    ecosystem: str = "",
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _semver_release_for_shorthand(value, ecosystem)
    if release is None or len(release) > 3:
        return None
    padded = release + (0,) * (3 - len(release))
    lower = padded
    if len(release) <= 1:
        upper = (padded[0] + 1, 0, 0)
    else:
        upper = (padded[0], padded[1] + 1, 0)
    return lower, upper


def _compatible_release_bounds(
    value: str,
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _release_tuple(value)
    if release is None or len(release) < 2:
        return None
    lower = release
    prefix = list(release[:-1])
    prefix[-1] += 1
    upper = tuple(prefix) + (0,)
    return lower, upper


def _pessimistic_rubygems_bounds(
    value: str,
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _release_tuple(value)
    if release is None:
        return None
    lower = release
    if len(release) == 1:
        upper = (release[0] + 1, 0)
    else:
        prefix = list(release[:-1])
        prefix[-1] += 1
        upper = tuple(prefix) + (0,)
    return lower, upper


def _release_in_bounds(
    observed: tuple[int, ...],
    lower: tuple[int, ...],
    upper: tuple[int, ...],
) -> bool:
    return _compare_release(observed, lower) >= 0 and _compare_release(
        observed, upper
    ) < 0


def _special_branch_supported(branch: str, ecosystem: str) -> bool:
    text = str(branch or "").strip()
    ecosystem = normalize_ecosystem(ecosystem)

    if ecosystem in SEMVER_ECOSYSTEMS:
        if text.startswith("^"):
            return _caret_bounds(
                text[1:].strip(),
                ecosystem,
            ) is not None
        if text.startswith("~") and not text.startswith("~="):
            return _tilde_bounds(
                text[1:].strip(),
                ecosystem,
            ) is not None
        if _WILDCARD_RE.fullmatch(text):
            return True
        hyphen = _HYPHEN_RE.fullmatch(text)
        if hyphen:
            return (
                _boundary_supported(hyphen.group(1), ecosystem)
                and _boundary_supported(hyphen.group(2), ecosystem)
            )

    if ecosystem in PEP440_ECOSYSTEMS and text.startswith("~="):
        return _compatible_release_bounds(text[2:].strip()) is not None

    if ecosystem in RUBYGEMS_ECOSYSTEMS and text.startswith("~>"):
        return _pessimistic_rubygems_bounds(text[2:].strip()) is not None

    if ecosystem in MAVEN_ECOSYSTEMS:
        interval = _MAVEN_INTERVAL_RE.fullmatch(text)
        if interval:
            lower = interval.group(2).strip()
            upper = interval.group(3).strip()
            return (
                (not lower or _boundary_supported(lower, ecosystem))
                and (not upper or _boundary_supported(upper, ecosystem))
            )

    return False


def _special_branch_matches(
    observed: tuple[int, ...],
    branch: str,
    ecosystem: str,
) -> bool | None:
    text = str(branch or "").strip()
    ecosystem = normalize_ecosystem(ecosystem)

    if ecosystem in SEMVER_ECOSYSTEMS:
        if text.startswith("^"):
            bounds = _caret_bounds(text[1:].strip(), ecosystem)
            return (
                _release_in_bounds(observed, *bounds)
                if bounds is not None
                else None
            )
        if text.startswith("~") and not text.startswith("~="):
            bounds = _tilde_bounds(text[1:].strip(), ecosystem)
            return (
                _release_in_bounds(observed, *bounds)
                if bounds is not None
                else None
            )
        wildcard = _wildcard_bounds(text)
        if wildcard is not None:
            return _release_in_bounds(observed, *wildcard)
        hyphen = _HYPHEN_RE.fullmatch(text)
        if hyphen:
            low_cmp = _compare_stable_observed_to_boundary(
                observed,
                hyphen.group(1),
                ecosystem,
            )
            high_cmp = _compare_stable_observed_to_boundary(
                observed,
                hyphen.group(2),
                ecosystem,
            )
            if low_cmp is None or high_cmp is None:
                return None
            return low_cmp >= 0 and high_cmp <= 0

    if ecosystem in PEP440_ECOSYSTEMS and text.startswith("~="):
        bounds = _compatible_release_bounds(text[2:].strip())
        return (
            _release_in_bounds(observed, *bounds)
            if bounds is not None
            else None
        )

    if ecosystem in RUBYGEMS_ECOSYSTEMS and text.startswith("~>"):
        bounds = _pessimistic_rubygems_bounds(text[2:].strip())
        return (
            _release_in_bounds(observed, *bounds)
            if bounds is not None
            else None
        )

    if ecosystem in MAVEN_ECOSYSTEMS:
        interval = _MAVEN_INTERVAL_RE.fullmatch(text)
        if interval:
            lower = interval.group(2).strip()
            upper = interval.group(3).strip()
            if lower:
                low_cmp = _compare_stable_observed_to_boundary(
                    observed, lower, ecosystem
                )
                if low_cmp is None:
                    return None
                if interval.group(1) == "[":
                    if low_cmp < 0:
                        return False
                elif low_cmp <= 0:
                    return False
            if upper:
                high_cmp = _compare_stable_observed_to_boundary(
                    observed, upper, ecosystem
                )
                if high_cmp is None:
                    return None
                if interval.group(4) == "]":
                    if high_cmp > 0:
                        return False
                elif high_cmp >= 0:
                    return False
            return True

    return None


def _comparator_branch_supported(branch: str, ecosystem: str) -> bool:
    parts = _split_comparator_conjunction(branch)
    if not parts:
        return False
    for part in parts:
        if _special_branch_supported(part, ecosystem):
            continue
        match = _COMPARATOR_CLAUSE_RE.fullmatch(part)
        if not match:
            return False
        operator = str(match.group(1) or "")
        boundary = str(match.group(2) or "")
        if operator in {"", "=", "=="}:
            if _WILDCARD_RE.fullmatch(boundary):
                if normalize_ecosystem(ecosystem) not in (
                    SEMVER_ECOSYSTEMS
                    | PEP440_ECOSYSTEMS
                    | RUBYGEMS_ECOSYSTEMS
                ):
                    return False
                continue
        if not _boundary_supported(boundary, ecosystem):
            return False
    return True


def _comparator_branch_matches(
    observed: tuple[int, ...],
    branch: str,
    ecosystem: str,
) -> bool | None:
    whole_special = _special_branch_matches(
        observed,
        branch,
        ecosystem,
    )
    if whole_special is not None:
        return whole_special

    parts = _split_comparator_conjunction(branch)
    if not parts:
        return None
    for part in parts:
        special = _special_branch_matches(observed, part, ecosystem)
        if special is not None:
            if not special:
                return False
            continue

        match = _COMPARATOR_CLAUSE_RE.fullmatch(part)
        if not match:
            return None
        operator = str(match.group(1) or "")
        boundary = str(match.group(2) or "")

        wildcard = _wildcard_bounds(boundary)
        if (
            operator in {"", "=", "=="}
            and wildcard is not None
            and normalize_ecosystem(ecosystem)
            in (SEMVER_ECOSYSTEMS | PEP440_ECOSYSTEMS | RUBYGEMS_ECOSYSTEMS)
        ):
            if not _release_in_bounds(observed, *wildcard):
                return False
            continue

        comparison = _compare_stable_observed_to_boundary(
            observed,
            boundary,
            ecosystem,
        )
        if comparison is None:
            return None
        if not _operator_matches(comparison, operator):
            return False
    return True


def _semver_special_branch_matches_version(
    version: str,
    branch: str,
    ecosystem: str,
) -> bool | None:
    parsed_observed = _semver_value(version, ecosystem)
    if parsed_observed is None:
        return None
    observed_release, observed_stage, _ = parsed_observed
    text = str(branch or "").strip()

    if text.startswith("^"):
        raw_lower = text[1:].strip()
        bounds = _caret_bounds(raw_lower, ecosystem)
        if bounds is None:
            return None
        lower_cmp = _compare_semver_values(
            version,
            raw_lower,
            ecosystem,
        )
        upper_text = ".".join(str(part) for part in bounds[1])
        upper_cmp = _compare_semver_values(
            version,
            upper_text,
            ecosystem,
        )
        if lower_cmp is None or upper_cmp is None:
            return None
        if (
            observed_stage == -1
            and not _semver_branch_has_prerelease_anchor(
                text,
                observed_release,
                ecosystem,
            )
        ):
            return False
        return lower_cmp >= 0 and upper_cmp < 0

    if text.startswith("~") and not text.startswith("~="):
        raw_lower = text[1:].strip()
        bounds = _tilde_bounds(raw_lower, ecosystem)
        if bounds is None:
            return None
        lower_cmp = _compare_semver_values(
            version,
            raw_lower,
            ecosystem,
        )
        upper_text = ".".join(str(part) for part in bounds[1])
        upper_cmp = _compare_semver_values(
            version,
            upper_text,
            ecosystem,
        )
        if lower_cmp is None or upper_cmp is None:
            return None
        if (
            observed_stage == -1
            and not _semver_branch_has_prerelease_anchor(
                text,
                observed_release,
                ecosystem,
            )
        ):
            return False
        return lower_cmp >= 0 and upper_cmp < 0

    wildcard = _wildcard_bounds(text)
    if wildcard is not None:
        # A wildcard branch carries no prerelease comparator. Excluding an
        # observed prerelease is conservative and follows SemVer range tools'
        # default prerelease admission rule.
        if observed_stage == -1:
            return False
        return _release_in_bounds(
            observed_release,
            *wildcard,
        )

    hyphen = _HYPHEN_RE.fullmatch(text)
    if hyphen:
        low_cmp = _compare_semver_values(
            version,
            hyphen.group(1),
            ecosystem,
        )
        high_cmp = _compare_semver_values(
            version,
            hyphen.group(2),
            ecosystem,
        )
        if low_cmp is None or high_cmp is None:
            return None
        if (
            observed_stage == -1
            and not _semver_branch_has_prerelease_anchor(
                text,
                observed_release,
                ecosystem,
            )
        ):
            return False
        return low_cmp >= 0 and high_cmp <= 0

    return None


def _semver_comparator_branch_matches_version(
    version: str,
    branch: str,
    ecosystem: str,
) -> bool | None:
    parsed_observed = _semver_value(version, ecosystem)
    if parsed_observed is None:
        return None
    observed_release, observed_stage, _ = parsed_observed

    whole_special = _semver_special_branch_matches_version(
        version,
        branch,
        ecosystem,
    )
    if whole_special is not None:
        return whole_special

    parts = _split_comparator_conjunction(branch)
    if not parts:
        return None

    if (
        observed_stage == -1
        and not _semver_branch_has_prerelease_anchor(
            branch,
            observed_release,
            ecosystem,
        )
    ):
        return False

    for part in parts:
        special = _semver_special_branch_matches_version(
            version,
            part,
            ecosystem,
        )
        if special is not None:
            if not special:
                return False
            continue

        match = _COMPARATOR_CLAUSE_RE.fullmatch(part)
        if not match:
            return None
        operator = str(match.group(1) or "")
        boundary = str(match.group(2) or "")

        wildcard = _wildcard_bounds(boundary)
        if operator in {"", "=", "=="} and wildcard is not None:
            if observed_stage == -1:
                return False
            if not _release_in_bounds(
                observed_release,
                *wildcard,
            ):
                return False
            continue

        comparison = _compare_semver_values(
            version,
            boundary,
            ecosystem,
        )
        if comparison is None:
            return None
        if not _operator_matches(comparison, operator):
            return False
    return True


def _union_branches(expression: str) -> list[str]:
    return [
        branch.strip()
        for branch in str(expression or "").split("||")
        if branch.strip()
    ]


def range_expression_capability(expression: str, ecosystem: str = "") -> str:
    branches = _union_branches(expression)
    if not branches:
        return "none"
    supported = sum(
        1
        for branch in branches
        if _comparator_branch_supported(branch, ecosystem)
        or _special_branch_supported(branch, ecosystem)
    )
    if supported == len(branches):
        return "full"
    if supported:
        return "partial"
    return "none"


def range_expression_supported(expression: str, ecosystem: str = "") -> bool:
    return range_expression_capability(expression, ecosystem) == "full"


def version_matches_range(
    version: str,
    expression: str,
    ecosystem: str = "",
) -> bool:
    observed = _release_tuple(version)
    ecosystem = normalize_ecosystem(ecosystem)

    if observed is not None:
        for branch in _union_branches(expression):
            if not (
                _comparator_branch_supported(branch, ecosystem)
                or _special_branch_supported(branch, ecosystem)
            ):
                continue
            result = _comparator_branch_matches(
                observed,
                branch,
                ecosystem,
            )
            if result is True:
                return True
        return False

    # Rich observed-version ordering is intentionally limited to ecosystems
    # whose SemVer-compatible precedence is explicit here. Other qualified
    # package versions remain unknown rather than being coerced into a numeric
    # approximation.
    if ecosystem not in SEMVER_ECOSYSTEMS:
        return False
    if _semver_value(version, ecosystem) is None:
        return False

    for branch in _union_branches(expression):
        if not (
            _comparator_branch_supported(branch, ecosystem)
            or _special_branch_supported(branch, ecosystem)
        ):
            continue
        result = _semver_comparator_branch_matches_version(
            version,
            branch,
            ecosystem,
        )
        if result is True:
            return True
    return False


def range_support_summary(
    rows: Iterable[tuple[str, str]],
) -> dict[str, int]:
    summary = {"full": 0, "partial": 0, "none": 0}
    for ecosystem, expression in rows:
        capability = range_expression_capability(expression, ecosystem)
        summary[capability] = summary.get(capability, 0) + 1
    return summary


__all__ = [
    "DEPENDENCY_VERSION_RANGE_VERSION",
    "DEPENDENCY_VERSION_RANGE_RULE_VERSION",
    "MAVEN_ECOSYSTEMS",
    "PEP440_ECOSYSTEMS",
    "RUBYGEMS_ECOSYSTEMS",
    "SEMVER_ECOSYSTEMS",
    "normalize_ecosystem",
    "range_expression_capability",
    "range_expression_supported",
    "range_support_summary",
    "version_matches_range",
]