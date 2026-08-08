from __future__ import annotations

from typing import Any

from core import Config, PolicySet, TargetPolicy, json_dumps


def target_plan(policy: TargetPolicy, config: Config, *, allow_active: bool = False) -> dict[str, Any]:
    active_allowed = policy.active_allowed(config, allow_active)
    modules = dict(policy.modules)
    for name in ("ports", "nuclei"):
        if modules.get(name) and not active_allowed:
            modules[name] = False
    return {
        "name": policy.name,
        "roots": policy.roots,
        "include": policy.include,
        "exclude": policy.exclude,
        "modules": modules,
        "active_gate_satisfied": active_allowed,
        "headers": sorted(policy.headers),
        "limits": {
            "request_rate_per_second": policy.limits.request_rate,
            "dns_rate_per_second": policy.limits.dns_rate,
            "crawl_depth": policy.limits.crawl_depth,
            "max_urls": policy.limits.max_urls,
            "max_js_files": policy.limits.max_js_files,
            "max_js_bytes": policy.limits.max_js_bytes,
            "max_runtime_minutes": policy.limits.max_runtime_minutes,
            "max_http_requests": policy.limits.max_http_requests,
            "max_dns_queries": policy.limits.max_dns_queries,
            "max_download_mb": policy.limits.max_download_mb,
            "max_new_assets": policy.limits.max_new_assets,
            "workers": {
                "dns": policy.limits.dns_workers,
                "http": policy.limits.http_workers,
                "javascript": policy.limits.js_workers,
                "screenshots": policy.limits.screenshot_workers,
            },
        },
        "safe_endpoint_validation": bool(policy.modules.get("endpoint_validation")),
    }


def build_plan(policies: PolicySet, config: Config, selector: str | None = None, *, allow_active: bool = False) -> dict[str, Any]:
    targets = policies.select(selector)
    return {
        "dry_run": True,
        "authorization_confirmed": config.authorized,
        "target_count": len(targets),
        "targets": [target_plan(target, config, allow_active=allow_active) for target in targets],
        "message": "No network requests were sent.",
    }


def format_plan(plan: dict[str, Any]) -> str:
    lines = ["Recon Monitor dry-run / scope preview", "=" * 40, ""]
    for target in plan["targets"]:
        lines.extend([
            f"Target: {target['name']}",
            f"Roots: {', '.join(target['roots'])}",
            f"Include rules: {len(target['include'])}",
            f"Exclude rules: {len(target['exclude'])}",
            "Enabled modules:",
        ])
        for name, enabled in target["modules"].items():
            lines.append(f"  {'[on ]' if enabled else '[off]'} {name}")
        limits = target["limits"]
        lines.extend([
            "Budgets:",
            f"  Runtime: {limits['max_runtime_minutes']} minutes",
            f"  HTTP requests: {limits['max_http_requests']}",
            f"  DNS queries: {limits['max_dns_queries']}",
            f"  Downloads: {limits['max_download_mb']} MiB",
            f"  New assets: {limits['max_new_assets']}",
            f"  Request rate: {limits['request_rate_per_second']}/s",
            f"  Crawl depth: {limits['crawl_depth']}",
            "",
        ])
    lines.append(str(plan.get("message", "")))
    return "\n".join(lines)
