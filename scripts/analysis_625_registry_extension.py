from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def insert_before(rel: str, marker: str, addition: str) -> None:
    text = read(rel)
    if marker not in text:
        raise SystemExit(f"marker not found in {rel}: {marker!r}")
    write(rel, text.replace(marker, addition + marker, 1))


def soften_historical_family_counts() -> None:
    """Preserve historical lineage tests while 6.25 owns the exact 36-family count.

    Older 6.x contracts were intended to prove complete coverage at that milestone,
    not permanently cap later registries at 31 families. Their set-equality and
    behavioral assertions stay intact; only literal cardinality caps are relaxed.
    """
    registry_names = (
        "FAMILY_ADMISSION_POLICIES",
        "FAMILY_EVIDENCE_EXTRACTOR_PROFILES",
        "FAMILY_EXTRACTION_IDENTITY_GATES",
        "FAMILY_REASONER_PROFILES",
        "FAMILY_IDENTITY_GATES",
        "DETECTOR_SPECS",
        "FAMILY_MODULES",
    )
    for path in (ROOT / "tests").glob("test_*.py"):
        # Current Analysis 6.25 owns the exact 36-family cardinality contract.
        if path.name == "test_owasp_top10_2025_completion_v6250.py":
            continue
        text = path.read_text(encoding="utf-8")
        updated = text
        for name in registry_names:
            updated = updated.replace(
                f"self.assertEqual(len({name}), 31)",
                f"self.assertGreaterEqual(len({name}), 31)",
            )
            updated = updated.replace(
                f"self.assertEqual(31, len({name}))",
                f"self.assertLessEqual(31, len({name}))",
            )
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def update_manifest() -> None:
    manifest = ROOT / "MANIFEST.sha256"
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            continue
        _, name = line.split("  ", 1)
        path = ROOT / name
        if path.is_file():
            rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")


# Analysis 6.8 evidence firewall: new families must have exact registry ownership.
gates = '''    "software_supply_chain_failure": (0,),\n    "cryptographic_failure": (0,),\n    "software_data_integrity_failure": (0,),\n    "security_logging_alerting_failure": (0,),\n    "exceptional_condition_mishandling": (0,),\n'''
insert_before(
    "app/family_evidence_extractors.py",
    "}\n\n\n@dataclass(frozen=True)\nclass FamilyEvidenceExtractorProfile:",
    gates,
)

extractor_profiles = '''    "software_supply_chain_failure": FamilyEvidenceExtractorProfile(("component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "stored_behavior"), "supply_chain_provenance_and_component_lifecycle"),\n    "cryptographic_failure": FamilyEvidenceExtractorProfile(("transport", "cryptography", "stored_source", "stored_behavior"), "cryptographic_control_failure"),\n    "software_data_integrity_failure": FamilyEvidenceExtractorProfile(("integrity", "serialization", "update_artifact", "stored_source", "stored_behavior"), "software_data_integrity_boundary"),\n    "security_logging_alerting_failure": FamilyEvidenceExtractorProfile(("logging", "audit", "telemetry", "configuration", "stored_behavior"), "security_event_logging_and_alerting"),\n    "exceptional_condition_mishandling": FamilyEvidenceExtractorProfile(("error_handling", "response_shape", "workflow", "stored_behavior"), "exception_fail_closed_behavior"),\n'''
insert_before(
    "app/family_evidence_extractors.py",
    "}\n\n\ndef _registry_errors() -> list[str]:",
    extractor_profiles,
)

# Analysis 6.7/6.8 family reasoners mirror the extractor identity gates exactly.
insert_before(
    "app/family_reasoners.py",
    "}\n\n\nFAMILY_REASONER_PROFILES: dict[str, FamilyReasonerProfile] = {",
    gates,
)

reasoner_profiles = '''    "software_supply_chain_failure": FamilyReasonerProfile(\n        "Does a deployed dependency, artifact, registry, or privileged build path rely on a vulnerable, unmaintained, untrusted, or compromised supply-chain component?",\n        (0.30, 0.50),\n        ("unsafe_api_consumption", "improper_inventory_management", "software_data_integrity_failure", "security_misconfiguration"),\n        confounder_penalty=0.22,\n    ),\n    "cryptographic_failure": FamilyReasonerProfile(\n        "Does a security-sensitive cryptographic or transport boundary actually use weak, predictable, reused, downgraded, or plaintext protection?",\n        (0.30, 0.50),\n        ("security_misconfiguration", "authentication_session", "secret_exposure", "sensitive_caching"),\n        confounder_penalty=0.20,\n    ),\n    "software_data_integrity_failure": FamilyReasonerProfile(\n        "Does untrusted code, update material, or serialized data cross an integrity boundary without effective authenticity/integrity verification?",\n        (0.28, 0.52),\n        ("software_supply_chain_failure", "mass_assignment", "command_injection", "unsafe_api_consumption"),\n        confounder_penalty=0.22,\n    ),\n    "security_logging_alerting_failure": FamilyReasonerProfile(\n        "Do stored logging, telemetry, or configuration artifacts show that a security event is missed, unsafe to log, not alerted, or not integrity-protected?",\n        (0.30, 0.50),\n        ("information_disclosure", "security_misconfiguration", "exceptional_condition_mishandling"),\n        confounder_penalty=0.20,\n    ),\n    "exceptional_condition_mishandling": FamilyReasonerProfile(\n        "Does an exceptional condition produce an unsafe fail-open, crash, state corruption, partial commit, or control-bypass outcome?",\n        (0.28, 0.52),\n        ("information_disclosure", "security_misconfiguration", "business_logic", "race_condition", "security_logging_alerting_failure"),\n        confounder_penalty=0.22,\n    ),\n'''
insert_before(
    "app/family_reasoners.py",
    "}\n\n\ndef _profile_errors() -> list[str]:",
    reasoner_profiles,
)

soften_historical_family_counts()
update_manifest()
