from __future__ import annotations

import urllib.parse
from typing import Any

from core import ReconError, TargetPolicy, normalize_host, normalize_url


WORKER_SCOPE_VERSION = 1
WORKER_CAPABILITIES = ("http_head", "download_url")


def worker_scope_snapshot(policy: TargetPolicy) -> dict[str, Any]:
    """Transfer effective scope rules without target headers or other secrets."""
    return {
        "version": WORKER_SCOPE_VERSION,
        "target": policy.name,
        "roots": list(policy.roots),
        "include": list(policy.include),
        "exclude": list(policy.exclude),
    }


class WorkerScopePolicy:
    def __init__(self, policy: TargetPolicy) -> None:
        self.target = policy.name
        self._policy = policy

    def url_in_scope(self, url: str) -> bool:
        normalized = normalize_url(url)
        if not normalized:
            return False
        host = normalize_host(urllib.parse.urlsplit(normalized).hostname or "")
        # Keep the worker's declared-root boundary even for permissive include
        # expressions, then apply the same include/exclude rules as local work.
        within_roots = any(host == root or host.endswith("." + root) for root in self._policy.roots)
        return within_roots and self._policy.url_in_scope(normalized)


def task_scope_policy(payload: dict[str, Any]) -> WorkerScopePolicy:
    scope = payload.get("scope_policy")
    if not isinstance(scope, dict):
        raise ReconError("Remote task requires a versioned scope policy")
    if type(scope.get("version")) is not int or scope["version"] != WORKER_SCOPE_VERSION:
        raise ReconError("Unsupported remote task scope policy version")
    if not isinstance(scope.get("target"), str) or not scope["target"].strip():
        raise ReconError("Remote task scope policy requires a target")
    for field in ("roots", "include", "exclude"):
        values = scope.get(field)
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ReconError(f"Remote task scope policy requires a string list: {field}")
        if field != "exclude" and not values:
            # TargetPolicy supplies default include rules when they are absent;
            # a transferred policy must contain its actual effective rules.
            raise ReconError(f"Remote task scope policy cannot have empty {field}")
    policy = TargetPolicy.from_dict({
        "name": scope["target"],
        "roots": scope["roots"],
        "include": scope["include"],
        "exclude": scope["exclude"],
    })
    return WorkerScopePolicy(policy)


def worker_supports_scope(metadata: Any) -> bool:
    if not isinstance(metadata, dict):
        return False
    versions = metadata.get("scope_policy_versions")
    return isinstance(versions, list) and any(
        type(version) is int and version == WORKER_SCOPE_VERSION for version in versions
    )
