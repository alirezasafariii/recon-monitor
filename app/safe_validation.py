from __future__ import annotations

"""Compatibility surface for Safe Validation with pinned network transport.

The established validation/case/import implementation remains in
``safe_validation_core``. Only the live transport hook is replaced. Dynamic
proxies preserve existing unit-test patch points and downstream imports.
"""

from typing import Any

import safe_validation_core as _core
from safe_transport import SAFE_TRANSPORT_VERSION, perform_pinned_request

for _name, _value in vars(_core).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_ORIGINAL_VALIDATION_LEVEL_FOR_FAMILY = validation_level_for_family


def _validation_level_for_family_proxy(family: str) -> str:
    return globals()["validation_level_for_family"](family)


def _perform_request(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return perform_pinned_request(
        item,
        policy,
        safe_methods=_core.SAFE_METHODS,
        url_safety=_core._url_safety,
        observation=_core._observation,
        max_response_bytes=_core.MAX_RESPONSE_BYTES,
        validation_version=_core.VALIDATION_VERSION,
    )


def _perform_request_proxy(
    item: dict[str, Any],
    policy: TargetPolicy,
) -> tuple[dict[str, Any], str]:
    return globals()["_perform_request"](item, policy)


# Functions defined in safe_validation_core retain that module as their globals.
# Route the two patchable hooks back through this compatibility surface.
_core.validation_level_for_family = _validation_level_for_family_proxy
_core._perform_request = _perform_request_proxy

__all__ = [name for name in globals() if not name.startswith("__")]
