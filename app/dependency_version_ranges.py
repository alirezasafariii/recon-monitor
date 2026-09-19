from __future__ import annotations

"""Fail-closed affected-version range evaluation for dependency advisories.

Recon Monitor deliberately keeps the observed component version contract narrow:
the target-side version must be an exact numeric release or a strict SemVer
release/prerelease. Advisory range boundaries may be richer. Prerelease target
versions are evaluated only for SemVer-compatible ecosystems and only when the
range branch explicitly admits that prerelease tuple. This module evaluates
only syntax whose ordering semantics are explicit for the advisory ecosystem.

Unsupported syntax never becomes a positive match. For union expressions, a
fully understood branch may safely produce a positive match even when another
union branch is unsupported; a conjunction is never partially evaluated.
"""

import re
from typing import Iterable

DEPENDENCY_VERSION_RANGE_VERSION = "1.3.1"
DEPENDENCY_VERSION_RANGE_RULE_VERSION = "2026.09.19.2"

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



def _strict_semver(
    value: str,
) -> tuple[tuple[int, int, int], tuple[str, ...] | None] | None:
    match = _SEMVER_RE.fullmatch(str(value or "").strip())
    if not match:
        return None
    core = tuple(str(match.group(index)) for index in (1, 2, 3))
    if any(len(item) > 1 and item.startswith("0") for item in core):
        return None
    release = tuple(int(item) for item in core)

    raw_prerelease = str(match.group(4) or "")
    prerelease: tuple[str, ...] | None = None
    if raw_prerelease:
        prerelease = tuple(raw_prerelease.split("."))
        if (
            not prerelease
            or any(not item for item in prerelease)
            or any(
                item.isdigit() and len(item) > 1 and item.startswith("0")
                for item in prerelease
            )
        ):
            return None

    raw_build = str(match.group(5) or "")
    if raw_build and any(not item for item in raw_build.split(".")):
        return None
    return release, prerelease

def _compare_semver_identifiers(
    left: tuple[str, ...] | None,
    right: tuple[str, ...] | None,
) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return 1
    if right is None:
        return -1
    for left_item, right_item in zip(left, right):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            left_value = int(left_item)
            right_value = int(right_item)
            return -1 if left_value < right_value else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_item < right_item else 1
    if len(left) == len(right):
        return 0
    return -1 if len(left) < len(right) else 1


def _compare_semver(
    left: tuple[tuple[int, int, int], tuple[str, ...] | None],
    right: tuple[tuple[int, int, int], tuple[str, ...] | None],
) -> int:
    release_cmp = _compare_release(left[0], right[0])
    if release_cmp:
        return release_cmp
    return _compare_semver_identifiers(left[1], right[1])


def observed_version_supported(value: str) -> bool:
    text = str(value or "").strip()
    return _release_tuple(text) is not None or _strict_semver(text) is not None


def _observed_prerelease(
    value: str,
    ecosystem: str,
) -> tuple[tuple[int, int, int], tuple[str, ...]] | None:
    if normalize_ecosystem(ecosystem) not in SEMVER_ECOSYSTEMS:
        return None
    parsed = _strict_semver(value)
    if parsed is None or parsed[1] is None:
        return None
    return parsed[0], parsed[1]


def _compare_observed_to_boundary(
    observed_text: str,
    boundary_text: str,
    ecosystem: str,
) -> int | None:
    observed_release = _release_tuple(observed_text)
    if observed_release is not None:
        return _compare_stable_observed_to_boundary(
            observed_release,
            boundary_text,
            ecosystem,
        )

    ecosystem = normalize_ecosystem(ecosystem)
    if ecosystem not in SEMVER_ECOSYSTEMS:
        return None
    observed_semver = _strict_semver(observed_text)
    if observed_semver is None:
        return None

    boundary_semver = _strict_semver(boundary_text)
    if boundary_semver is not None:
        return _compare_semver(observed_semver, boundary_semver)

    boundary_release = _release_tuple(boundary_text)
    if boundary_release is not None and len(boundary_release) <= 3:
        padded = boundary_release + (0,) * (3 - len(boundary_release))
        return _compare_semver(observed_semver, (padded, None))
    return None


def _branch_explicitly_admits_prerelease(
    observed_text: str,
    branch: str,
    ecosystem: str,
) -> bool:
    observed = _observed_prerelease(observed_text, ecosystem)
    if observed is None:
        return True
    observed_release = observed[0]
    text = str(branch or "").strip()

    hyphen = _HYPHEN_RE.fullmatch(text)
    if hyphen:
        for boundary in (hyphen.group(1), hyphen.group(2)):
            parsed = _strict_semver(boundary)
            if parsed is not None and parsed[1] is not None and parsed[0] == observed_release:
                return True
        return False

    parts = _split_comparator_conjunction(text)
    if not parts:
        return False
    for part in parts:
        match = _COMPARATOR_CLAUSE_RE.fullmatch(part)
        if not match:
            continue
        parsed = _strict_semver(str(match.group(2) or ""))
        if parsed is not None and parsed[1] is not None and parsed[0] == observed_release:
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



def _caret_bounds(value: str) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _release_tuple(value)
    if release is None:
        semver = _strict_semver(value)
        release = semver[0] if semver is not None else None
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


def _tilde_bounds(value: str) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    release = _release_tuple(value)
    if release is None:
        semver = _strict_semver(value)
        release = semver[0] if semver is not None else None
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


def _npm_hyphen_partial_bounds(
    lower_text: str,
    upper_text: str,
) -> tuple[tuple[int, int, int] | None, tuple[int, int, int] | None]:
    """Normalize partial numeric npm hyphen endpoints.

    npm/node-semver zero-fills a partial lower endpoint. A partial upper
    endpoint includes the written prefix, which is equivalent for stable
    observed releases to an exclusive bound at the next prefix.
    """

    lower_release = _release_tuple(lower_text)
    upper_release = _release_tuple(upper_text)

    lower: tuple[int, int, int] | None = None
    if lower_release is not None and 1 <= len(lower_release) < 3:
        padded_lower = lower_release + (0,) * (3 - len(lower_release))
        lower = (padded_lower[0], padded_lower[1], padded_lower[2])

    upper: tuple[int, int, int] | None = None
    if upper_release is not None and len(upper_release) == 1:
        upper = (upper_release[0] + 1, 0, 0)
    elif upper_release is not None and len(upper_release) == 2:
        upper = (upper_release[0], upper_release[1] + 1, 0)

    return lower, upper


def _special_branch_supported(branch: str, ecosystem: str) -> bool:
    text = str(branch or "").strip()
    ecosystem = normalize_ecosystem(ecosystem)

    if ecosystem in SEMVER_ECOSYSTEMS:
        if text.startswith("^"):
            return _caret_bounds(text[1:].strip()) is not None
        if text.startswith("~") and not text.startswith("~="):
            return _tilde_bounds(text[1:].strip()) is not None
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
    observed_text: str,
    branch: str,
    ecosystem: str,
) -> bool | None:
    text = str(branch or "").strip()
    ecosystem = normalize_ecosystem(ecosystem)
    observed_release = _release_tuple(observed_text)
    observed_semver = (
        _strict_semver(observed_text)
        if ecosystem in SEMVER_ECOSYSTEMS
        else None
    )
    if observed_release is None and observed_semver is None:
        return None

    if ecosystem in SEMVER_ECOSYSTEMS:
        if text.startswith("^"):
            lower_text = text[1:].strip()
            bounds = _caret_bounds(lower_text)
            if bounds is None:
                return None
            if _strict_semver(lower_text) is not None:
                low_cmp = _compare_observed_to_boundary(
                    observed_text, lower_text, ecosystem
                )
                high_cmp = _compare_observed_to_boundary(
                    observed_text, ".".join(str(item) for item in bounds[1]), ecosystem
                )
                if low_cmp is None or high_cmp is None:
                    return None
                if not _branch_explicitly_admits_prerelease(
                    observed_text, f">={lower_text}", ecosystem
                ):
                    return False
                return low_cmp >= 0 and high_cmp < 0
            if observed_semver is not None and observed_semver[1] is not None:
                return False
            release = observed_release if observed_release is not None else observed_semver[0]
            return _release_in_bounds(release, *bounds)
        if text.startswith("~") and not text.startswith("~="):
            lower_text = text[1:].strip()
            bounds = _tilde_bounds(lower_text)
            if bounds is None:
                return None
            if _strict_semver(lower_text) is not None:
                low_cmp = _compare_observed_to_boundary(
                    observed_text, lower_text, ecosystem
                )
                high_cmp = _compare_observed_to_boundary(
                    observed_text, ".".join(str(item) for item in bounds[1]), ecosystem
                )
                if low_cmp is None or high_cmp is None:
                    return None
                if not _branch_explicitly_admits_prerelease(
                    observed_text, f">={lower_text}", ecosystem
                ):
                    return False
                return low_cmp >= 0 and high_cmp < 0
            if observed_semver is not None and observed_semver[1] is not None:
                return False
            release = observed_release if observed_release is not None else observed_semver[0]
            return _release_in_bounds(release, *bounds)
        wildcard = _wildcard_bounds(text)
        if wildcard is not None:
            if observed_semver is not None and observed_semver[1] is not None:
                return False
            release = observed_release if observed_release is not None else observed_semver[0]
            return _release_in_bounds(release, *wildcard)
        hyphen = _HYPHEN_RE.fullmatch(text)
        if hyphen:
            lower_text = hyphen.group(1)
            upper_text = hyphen.group(2)

            if ecosystem == "npm":
                partial_lower, partial_upper = _npm_hyphen_partial_bounds(
                    lower_text,
                    upper_text,
                )
                if partial_lower is not None or partial_upper is not None:
                    if (
                        observed_semver is not None
                        and observed_semver[1] is not None
                        and not _branch_explicitly_admits_prerelease(
                            observed_text,
                            text,
                            ecosystem,
                        )
                    ):
                        return False
                    release = (
                        observed_release
                        if observed_release is not None
                        else observed_semver[0]
                    )
                    if partial_lower is not None:
                        lower_ok = _compare_release(
                            release,
                            partial_lower,
                        ) >= 0
                    else:
                        low_cmp = _compare_observed_to_boundary(
                            observed_text,
                            lower_text,
                            ecosystem,
                        )
                        if low_cmp is None:
                            return None
                        lower_ok = low_cmp >= 0

                    if partial_upper is not None:
                        upper_ok = _compare_release(
                            release,
                            partial_upper,
                        ) < 0
                    else:
                        high_cmp = _compare_observed_to_boundary(
                            observed_text,
                            upper_text,
                            ecosystem,
                        )
                        if high_cmp is None:
                            return None
                        upper_ok = high_cmp <= 0
                    return lower_ok and upper_ok

            low_cmp = _compare_observed_to_boundary(
                observed_text,
                lower_text,
                ecosystem,
            )
            high_cmp = _compare_observed_to_boundary(
                observed_text,
                upper_text,
                ecosystem,
            )
            if low_cmp is None or high_cmp is None:
                return None
            if not _branch_explicitly_admits_prerelease(
                observed_text,
                text,
                ecosystem,
            ):
                return False
            return low_cmp >= 0 and high_cmp <= 0

    if ecosystem in PEP440_ECOSYSTEMS and text.startswith("~="):
        bounds = _compatible_release_bounds(text[2:].strip())
        return (
            _release_in_bounds(observed_release, *bounds)
            if bounds is not None and observed_release is not None
            else None
        )

    if ecosystem in RUBYGEMS_ECOSYSTEMS and text.startswith("~>"):
        bounds = _pessimistic_rubygems_bounds(text[2:].strip())
        return (
            _release_in_bounds(observed_release, *bounds)
            if bounds is not None and observed_release is not None
            else None
        )

    if ecosystem in MAVEN_ECOSYSTEMS:
        interval = _MAVEN_INTERVAL_RE.fullmatch(text)
        if interval and observed_release is not None:
            lower = interval.group(2).strip()
            upper = interval.group(3).strip()
            if lower:
                low_cmp = _compare_stable_observed_to_boundary(
                    observed_release, lower, ecosystem
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
                    observed_release, upper, ecosystem
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
    observed_text: str,
    branch: str,
    ecosystem: str,
) -> bool | None:
    whole_special = _special_branch_matches(
        observed_text,
        branch,
        ecosystem,
    )
    if whole_special is not None:
        return whole_special

    parts = _split_comparator_conjunction(branch)
    if not parts:
        return None
    for part in parts:
        special = _special_branch_matches(observed_text, part, ecosystem)
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
            observed_release = _release_tuple(observed_text)
            if observed_release is None:
                return False
            if not _release_in_bounds(observed_release, *wildcard):
                return False
            continue

        comparison = _compare_observed_to_boundary(
            observed_text,
            boundary,
            ecosystem,
        )
        if comparison is None:
            return None
        if not _operator_matches(comparison, operator):
            return False

    if not _branch_explicitly_admits_prerelease(
        observed_text,
        branch,
        ecosystem,
    ):
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
    observed_text = str(version or "").strip()
    if not observed_version_supported(observed_text):
        return False
    if (
        _release_tuple(observed_text) is None
        and _strict_semver(observed_text) is not None
        and normalize_ecosystem(ecosystem) not in SEMVER_ECOSYSTEMS
    ):
        return False

    for branch in _union_branches(expression):
        if not (
            _comparator_branch_supported(branch, ecosystem)
            or _special_branch_supported(branch, ecosystem)
        ):
            continue
        result = _comparator_branch_matches(observed_text, branch, ecosystem)
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
    "observed_version_supported",
    "range_expression_capability",
    "range_expression_supported",
    "range_support_summary",
    "version_matches_range",
]
