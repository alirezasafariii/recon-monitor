from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

from raw_recon_corpus import ROOT
import raw_recon_v4_source_discovery as v4
from raw_recon_v5_nvd_discovery import (
    _cwes,
    _description,
    _project_identity,
    _references,
    _severity,
    prior_cve_exposure,
)
from raw_recon_v5_source_discovery import exposure_index

VERSION = "1.2.0"
RULE_VERSION = "2026.08.13.6.29"
OUTPUT = ROOT / "benchmarks/raw/sources/v5_exact_source_supplement.json"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EXACT_SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "dom_xss": {
        "cve": "CVE-2025-63418",
        "project_any": ("cpe:selfbest/selfbest",),
        "groups": (
            ("dom-based cross-site scripting", "dom-based xss"),
            ("direct dom manipulation", "client-side code"),
            ("sanitization", "content security policy"),
        ),
    },
    "graphql_authorization": {
        "cve": "CVE-2026-41522",
        "project_any": ("dfir-iris/iris-web",),
        "groups": (
            ("graphql endpoint", "graphql"),
            ("authorization checks", "verifying the caller has access"),
            ("unauthorized", "arbitrary case", "regardless of role"),
        ),
    },
    "graphql_data_exposure": {
        "cve": "CVE-2026-59262",
        "project_any": ("toeverything/AFFiNE", "toeverything/affine"),
        "groups": (
            ("graphql field", "graphql"),
            ("restricted content timelines", "private pages"),
            ("user names", "emails", "timestamps"),
        ),
    },
    "improper_inventory_management": {
        "cve": "CVE-2025-59034",
        "project_any": ("indico/indico", "cpe:cern/indico"),
        "groups": (
            ("legacy api",),
            ("retrieve user details", "retrieve profile details"),
            ("without having admin permissions", "broken access check"),
        ),
    },
    "postmessage_trust": {
        "cve": "CVE-2025-66500",
        "project_any": ("cpe:foxit/pdf_editor_cloud",),
        "groups": (
            ("postmessage",),
            ("fails to validate the message origin", "message origin"),
            ("externalpath", "script source", "arbitrary javascript"),
        ),
    },
    "sensitive_business_flow_abuse": {
        "cve": "CVE-2026-25043",
        "project_any": ("Budibase/budibase", "budibase/budibase", "cpe:budibase/budibase"),
        "groups": (
            ("password reset", "forgot password"),
            ("absence of rate limiting", "captcha", "abuse prevention"),
            ("repeatedly trigger", "hundreds of password reset emails"),
        ),
    },
    "software_supply_chain_failure": {
        "cve": "CVE-2026-34841",
        "project_any": ("usebruno/bruno",),
        "groups": (
            ("supply chain attack", "supply-chain attack"),
            ("compromised versions", "compromised"),
            ("hidden dependency", "remote access trojan", "rat"),
        ),
    },
    "source_map_exposure": {
        "cve": "CVE-2024-38327",
        "project_any": ("cpe:ibm/analytics_content_hub",),
        "groups": (
            ("source map",),
            ("exposed javascript", "information exposure"),
            ("read and debug javascript", "application's api"),
        ),
    },
    "unsafe_api_consumption": {
        "cve": "CVE-2026-31798",
        "project_any": ("jumpserver/jumpserver", "cpe:fit2cloud/jumpserver"),
        "groups": (
            ("custom sms api client", "custom sms api"),
            ("improperly validates certificates", "validates certificates"),
            ("intercept the request", "verification code", "mfa/otp"),
        ),
    },
    "websocket_authorization": {
        "cve": "CVE-2026-11807",
        "project_any": ("cpe:redhat/ansible_automation_platform",),
        "groups": (
            ("websocket api", "websocket"),
            ("does not verify user permissions", "missing authorization"),
            ("arbitrary activation_id", "plaintext credentials", "oauth tokens"),
        ),
    },
}


def _fetch_exact_cve(cve_id: str) -> dict[str, Any]:
    query = urllib.parse.urlencode({"cveId": cve_id})
    request = urllib.request.Request(
        f"{NVD_CVE_API}?{query}",
        headers={
            "User-Agent": "Recon-Monitor-Analysis-6.29-Fresh-Blind-v5/1.0",
            "Accept": "application/json",
        },
    )
    response = None
    for attempt in range(3):
        try:
            response = urllib.request.urlopen(request, timeout=60)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in {403, 429} or attempt == 2:
                raise
            time.sleep(6.5 * (attempt + 1))
    if response is None:
        raise RuntimeError(f"unable to fetch exact NVD record for {cve_id}")
    with response:
        payload = json.load(response)
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, Mapping) else []
    matches = [
        dict(wrapper.get("cve"))
        for wrapper in vulnerabilities or []
        if isinstance(wrapper, Mapping)
        and isinstance(wrapper.get("cve"), Mapping)
        and str(wrapper["cve"].get("id") or "").strip().upper() == cve_id.upper()
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one NVD result for {cve_id}, got {len(matches)}")
    return matches[0]


def _load_exact_cves() -> dict[str, dict[str, Any]]:
    wanted = sorted({str(spec["cve"]).upper() for spec in EXACT_SOURCE_SPECS.values()})
    found: dict[str, dict[str, Any]] = {}
    for index, cve_id in enumerate(wanted):
        if index:
            time.sleep(6.2)
        found[cve_id] = _fetch_exact_cve(cve_id)
    return found


def _semantic_audit(description: str, groups: tuple[tuple[str, ...], ...]) -> tuple[list[list[str]], int]:
    text = description.lower()
    hits_by_group: list[list[str]] = []
    score = 0
    for group in groups:
        hits = sorted({phrase for phrase in group if phrase.lower() in text})
        hits_by_group.append(hits)
        if not hits:
            raise RuntimeError(f"exact source semantic group missing: {group}")
        score += 10 + len(hits)
    return hits_by_group, score


def build() -> dict[str, Any]:
    exact = _load_exact_cves()
    prior = exposure_index()
    prior_cves = prior_cve_exposure()
    grounding = v4._grounding_writeup_urls()
    selected: list[dict[str, Any]] = []
    used_cves: set[str] = set()
    used_projects: set[str] = set()

    for family in sorted(EXACT_SOURCE_SPECS):
        spec = EXACT_SOURCE_SPECS[family]
        cve_id = str(spec["cve"]).upper()
        cve = exact[cve_id]
        if cve_id in prior_cves or cve_id in prior["roots"]:
            raise RuntimeError(f"{family}: exact CVE was previously exposed: {cve_id}")
        if cve_id in used_cves:
            raise RuntimeError(f"{family}: duplicate exact CVE: {cve_id}")
        if str(cve.get("vulnStatus") or "").lower() == "rejected":
            raise RuntimeError(f"{family}: exact CVE is rejected: {cve_id}")

        description = _description(cve)
        if len(description) < 120:
            raise RuntimeError(f"{family}: exact CVE description is too short")
        hits, score = _semantic_audit(description, tuple(spec["groups"]))
        references = _references(cve)
        canonical_refs = {v4._canonical_url(url) for url in references if v4._canonical_url(url)}
        grounding_overlap = sorted(canonical_refs & grounding)
        prior_url_overlap = sorted(canonical_refs & prior["urls"])
        if grounding_overlap:
            raise RuntimeError(f"{family}: exact CVE reference overlaps detector grounding: {grounding_overlap}")
        if prior_url_overlap:
            raise RuntimeError(f"{family}: exact CVE reference was previously exposed: {prior_url_overlap}")

        _, aliases, identity_kind = _project_identity(cve, references)
        allowed = {str(value) for value in spec["project_any"]}
        alias_lookup = {value.lower(): value for value in aliases}
        matched_project = next((alias_lookup[value.lower()] for value in allowed if value.lower() in alias_lookup), "")
        if not matched_project:
            raise RuntimeError(
                f"{family}: exact source project identity mismatch; expected one of {sorted(allowed)}, aliases={aliases}"
            )
        if matched_project in prior["projects"]:
            raise RuntimeError(f"{family}: exact source project was previously exposed: {matched_project}")
        if matched_project in used_projects:
            raise RuntimeError(f"{family}: duplicate exact source project: {matched_project}")

        canonical_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if v4._canonical_url(canonical_url) in prior["urls"]:
            raise RuntimeError(f"{family}: exact NVD URL was previously exposed")
        repository_advisory = next((url for url in references if "/security/advisories/" in url), "")
        source_location = next(
            (url for url in references if v4._project_from_url(url).lower() == matched_project.lower()),
            "",
        )
        row = {
            "source_root": cve_id,
            "source_project": matched_project,
            "project_aliases": aliases,
            "project_identity_kind": identity_kind,
            "family": family,
            "matched_cwes": sorted(_cwes(cve)),
            "published_at": str(cve.get("published") or "").strip(),
            "updated_at": str(cve.get("lastModified") or "").strip(),
            "severity": _severity(cve),
            "summary": description.split(". ", 1)[0].strip(),
            "description": description,
            "repository_advisory_url": repository_advisory,
            "source_code_location": source_location,
            "canonical_advisory_url": canonical_url,
            "references": references,
            "source_kind": "nvd_json_2_0_exact_semantic_supplement",
            "advisory_source_type": "nvd",
            "freshness_validated": True,
            "freshness_scope": "all prior benchmark CVE IDs plus golden/raw selected project/URLs and detector grounding writeups",
            "selection_basis": "pre-registered exact CVE plus family-specific source-text contract before scoring",
            "exact_source_audit_passed": True,
            "source_family_audit_version": VERSION,
            "source_family_audit_rule_version": RULE_VERSION,
            "source_family_audit_group_hits": hits,
            "source_family_audit_score": score,
        }
        selected.append(row)
        used_cves.add(cve_id)
        used_projects.add(matched_project)

    if len(selected) != len(EXACT_SOURCE_SPECS):
        raise RuntimeError("v5 exact source supplement selection count mismatch")
    return {
        "version": VERSION,
        "rule_version": RULE_VERSION,
        "scoring_executed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
        "family_count": len(selected),
        "selected": selected,
    }


def main() -> int:
    report = build()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "family_count": report["family_count"],
        "families": [row["family"] for row in report["selected"]],
        "roots": [row["source_root"] for row in report["selected"]],
        "projects": [row["source_project"] for row in report["selected"]],
        "scoring_executed": report["scoring_executed"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())