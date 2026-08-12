from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EPHEMERAL = {
    ".github/workflows/analysis-625-one-shot.yml",
    "scripts/analysis_625_cutover.py",
}
NEW_PERSISTENT = {
    "app/family_detectors/software_supply_chain_failure.py",
    "app/family_detectors/cryptographic_failure.py",
    "app/family_detectors/software_data_integrity_failure.py",
    "app/family_detectors/security_logging_alerting_failure.py",
    "app/family_detectors/exceptional_condition_mishandling.py",
    "app/raw_family_collectors/owasp_top10_2025.py",
    "tests/test_owasp_top10_2025_completion_v6250.py",
    "docs/ANALYSIS_ENGINE_6_25_OWASP_TOP10_COMPLETION.md",
}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, content: str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    if old not in text:
        raise SystemExit(f"anchor not found in {rel}: {old[:100]!r}")
    write(rel, text.replace(old, new, 1))


def insert_before_once(rel: str, marker: str, addition: str) -> None:
    text = read(rel)
    if marker not in text:
        raise SystemExit(f"marker not found in {rel}: {marker[:100]!r}")
    write(rel, text.replace(marker, addition + marker, 1))


def update_manifest() -> None:
    manifest = ROOT / "MANIFEST.sha256"
    names: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            continue
        _, name = line.split("  ", 1)
        if name and name not in EPHEMERAL:
            names.add(name)
    names.update(NEW_PERSISTENT)
    rows: list[str] = []
    for name in sorted(names):
        path = ROOT / name
        if not path.is_file() or name in EPHEMERAL:
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {name}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# 1) Standards: add the five missing OWASP Top 10:2025 categories as explicit
#    family profiles. WSTG is test-method grounding, OWASP is risk taxonomy,
#    CWE is weakness taxonomy. None of these are target evidence.
# ---------------------------------------------------------------------------
standards_profiles = r'''    'software_supply_chain_failure': {
        'principle': 'Dependency, build, registry, and artifact metadata are supply-chain surfaces; promotion requires observed untrusted, vulnerable, unmaintained, or compromised component/pipeline behavior.',
        'wstg': [
            _wstg('WSTG-CONF-01', 'Network and Application Platform Configuration'),
            _wstg('WSTG-CONF-02', 'Application Platform Configuration'),
        ],
        'cwe': [
            _cwe('CWE-1104', 'Use of Unmaintained Third Party Components', mapping='contextual', auto_assign=True, when_any=('unmaintained_component_confirmed', 'known_vulnerable_component_observed')),
            _cwe('CWE-1357', 'Reliance on Insufficiently Trustworthy Component', mapping='contextual', auto_assign=True, when_any=('untrusted_component_source', 'component_update_path_compromised')),
            _cwe('CWE-1395', 'Dependency on Vulnerable Third-Party Component', mapping='contextual', auto_assign=True, when_any=('known_vulnerable_component_observed',)),
        ],
    },
    'cryptographic_failure': {
        'principle': 'Crypto/TLS/key-generation markers are only surfaces; promotion requires observed weak, downgraded, predictable, reused, or plaintext handling of security-sensitive data.',
        'wstg': [
            _wstg('WSTG-CRYP-01', 'Weak Transport Layer Security'),
        ],
        'cwe': [
            _cwe('CWE-319', 'Cleartext Transmission of Sensitive Information', mapping='contextual', auto_assign=True, when_any=('plaintext_sensitive_transport',)),
            _cwe('CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm', mapping='contextual', auto_assign=True, when_any=('weak_crypto_algorithm_observed',)),
            _cwe('CWE-338', 'Use of Cryptographically Weak Pseudo-Random Number Generator', mapping='contextual', auto_assign=True, when_any=('predictable_randomness_observed',)),
            _cwe('CWE-757', 'Selection of Less-Secure Algorithm During Negotiation', mapping='contextual', auto_assign=True, when_any=('crypto_downgrade_observed', 'weak_tls_observed')),
        ],
    },
    'software_data_integrity_failure': {
        'principle': 'Update, serialization, plugin, and external-code boundaries are only surfaces; promotion requires observed missing integrity verification or unsafe trust of code/data.',
        'wstg': [
            _wstg('WSTG-CONF-02', 'Application Platform Configuration'),
        ],
        'cwe': [
            _cwe('CWE-345', 'Insufficient Verification of Data Authenticity', mapping='contextual', auto_assign=True, when_any=('integrity_check_missing', 'unsigned_serialized_data_trusted')),
            _cwe('CWE-494', 'Download of Code Without Integrity Check', mapping='contextual', auto_assign=True, when_any=('unsigned_update_accepted', 'integrity_check_missing')),
            _cwe('CWE-502', 'Deserialization of Untrusted Data', mapping='direct', auto_assign=True, when_any=('unsafe_deserialization_observed',)),
            _cwe('CWE-829', 'Inclusion of Functionality from Untrusted Control Sphere', mapping='contextual', auto_assign=True, when_any=('untrusted_code_executed',)),
        ],
    },
    'security_logging_alerting_failure': {
        'principle': 'Security-event and logging metadata are only surfaces; lack of visible logs is never inferred from an HTTP response. Promotion requires stored evidence of missing, unsafe, or ineffective security logging/alerting.',
        'wstg': [
            _wstg('WSTG-CONF-02', 'Application Platform Configuration'),
            _wstg('WSTG-ERRH-01', 'Improper Error Handling'),
        ],
        'cwe': [
            _cwe('CWE-117', 'Improper Output Neutralization for Logs', mapping='contextual', auto_assign=True, when_any=('log_injection_observed',)),
            _cwe('CWE-532', 'Insertion of Sensitive Information into Log File', mapping='contextual', auto_assign=True, when_any=('sensitive_data_logged',)),
            _cwe('CWE-778', 'Insufficient Logging', mapping='contextual', auto_assign=True, when_any=('security_event_not_logged', 'alerting_absent_observed')),
        ],
    },
    'exceptional_condition_mishandling': {
        'principle': 'Error/exception markers are only surfaces; promotion requires an observed fail-open, crash, partial commit, corrupted state, or other unsafe exceptional-condition outcome.',
        'wstg': [
            _wstg('WSTG-ERRH-01', 'Improper Error Handling'),
            _wstg('WSTG-ERRH-02', 'Stack Traces'),
        ],
        'cwe': [
            _cwe('CWE-248', 'Uncaught Exception', mapping='contextual', auto_assign=True, when_any=('unhandled_exception_observed', 'crash_on_exception')),
            _cwe('CWE-636', 'Not Failing Securely (Failing Open)', mapping='contextual', auto_assign=True, when_any=('fail_open_observed', 'exception_control_bypass')),
            _cwe('CWE-703', 'Improper Check or Handling of Exceptional Conditions', mapping='direct', auto_assign=True, when_any=('unhandled_exception_observed', 'state_corruption_after_error', 'partial_commit_after_error')),
            _cwe('CWE-755', 'Improper Handling of Exceptional Conditions', mapping='contextual', auto_assign=True, when_any=('unhandled_exception_observed', 'crash_on_exception')),
        ],
    },
'''
insert_before_once(
    "app/analysis_standards.py",
    "}\n\n\n# Analysis 6.19 makes OWASP taxonomy grounding",
    standards_profiles,
)

owasp_mappings = r'''    "software_supply_chain_failure": [
        _top10("A03:2025", "Software Supply Chain Failures", "A03_2025-Software_Supply_Chain_Failures"),
    ],
    "cryptographic_failure": [
        _top10("A04:2025", "Cryptographic Failures", "A04_2025-Cryptographic_Failures"),
    ],
    "software_data_integrity_failure": [
        _top10("A08:2025", "Software or Data Integrity Failures", "A08_2025-Software_or_Data_Integrity_Failures"),
    ],
    "security_logging_alerting_failure": [
        _top10("A09:2025", "Security Logging and Alerting Failures", "A09_2025-Security_Logging_and_Alerting_Failures"),
    ],
    "exceptional_condition_mishandling": [
        _top10("A10:2025", "Mishandling of Exceptional Conditions", "A10_2025-Mishandling_of_Exceptional_Conditions"),
    ],
'''
insert_before_once(
    "app/analysis_standards.py",
    "}\n\nif set(FAMILY_OWASP_MAPPINGS) != set(FAMILY_STANDARDS):",
    owasp_mappings,
)

# ---------------------------------------------------------------------------
# 2) Admission: all five new families require a real target condition. A03/A09
#    intentionally never infer absence from missing public evidence.
# ---------------------------------------------------------------------------
new_policies = r'''    "software_supply_chain_failure": {
        "required": [
            {"component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "component_fingerprint"},
            {"known_vulnerable_component_observed", "unmaintained_component_confirmed", "untrusted_component_source", "privileged_pipeline_executes_untrusted_code", "component_update_path_compromised"},
        ],
        "min_independent_sources": 2,
        "label": "component/build supply-chain surface + observed vulnerable, unmaintained, untrusted, or compromised dependency/pipeline condition",
        "blocking_contradictions": {"component_current_and_supported", "trusted_component_source", "pipeline_untrusted_code_isolated", "component_not_deployed"},
    },
    "cryptographic_failure": {
        "required": [
            {"cryptographic_surface", "transport_crypto_surface", "key_generation_surface", "sensitive_transport"},
            {"weak_crypto_algorithm_observed", "weak_tls_observed", "cryptographic_key_reuse", "predictable_randomness_observed", "crypto_downgrade_observed", "plaintext_sensitive_transport"},
        ],
        "min_independent_sources": 2,
        "label": "cryptographic/transport surface + observed weak, predictable, reused, downgraded, or plaintext security control",
        "blocking_contradictions": {"strong_tls_enforced", "approved_crypto_observed", "unique_nonce_observed", "secure_randomness_observed"},
    },
    "software_data_integrity_failure": {
        "required": [
            {"integrity_boundary", "update_artifact", "serialized_input", "external_code_dependency"},
            {"unsigned_update_accepted", "integrity_check_missing", "untrusted_code_executed", "unsafe_deserialization_observed", "unsigned_serialized_data_trusted"},
        ],
        "min_independent_sources": 2,
        "label": "code/data integrity boundary + observed missing verification or unsafe trust of update, code, or serialized data",
        "blocking_contradictions": {"signature_verified", "integrity_check_present", "trusted_repository_only", "safe_deserializer"},
    },
    "security_logging_alerting_failure": {
        "required": [
            {"auditable_security_event", "logging_surface", "security_control_event"},
            {"security_event_not_logged", "alerting_absent_observed", "sensitive_data_logged", "log_injection_observed", "log_integrity_missing"},
        ],
        "min_independent_sources": 2,
        "label": "auditable security/logging surface + stored evidence of missing, unsafe, or ineffective logging/alerting",
        "blocking_contradictions": {"security_event_logged", "alert_triggered", "log_encoding_present", "log_integrity_protected"},
    },
    "exceptional_condition_mishandling": {
        "required": [
            {"exception_surface", "abnormal_input_context", "transactional_operation"},
            {"unhandled_exception_observed", "fail_open_observed", "state_corruption_after_error", "partial_commit_after_error", "crash_on_exception", "exception_control_bypass"},
        ],
        "min_independent_sources": 2,
        "label": "exception/error surface + observed unsafe fail-open, crash, state, transaction, or control outcome",
        "blocking_contradictions": {"centralized_error_handling", "fail_closed_observed", "transaction_rollback_observed", "generic_error_response"},
    },
'''
insert_before_once(
    "app/hypothesis_admission.py",
    "}\n\n_STANDARD_GROUNDING_ERRORS = validate_family_standards(FAMILY_ADMISSION_POLICIES)",
    new_policies,
)

# ---------------------------------------------------------------------------
# 3) One physical detector module per family.
# ---------------------------------------------------------------------------
write("app/family_detectors/software_supply_chain_failure.py", '''from .base import make_spec, writeup\nSPEC = make_spec(\n    family="software_supply_chain_failure",\n    strategy="supply_chain_provenance_and_component_lifecycle",\n    surface_terms=("dependency", "package", "sbom", "lockfile", "workflow", "ci/cd", "artifact", "registry", "container", "component version"),\n    surface_fields=("package", "version", "dependency", "artifact", "repository", "image", "workflow", "sbom"),\n    confounders=("unsafe_api_consumption", "improper_inventory_management", "software_data_integrity_failure", "security_misconfiguration"),\n    expected_wstg=("WSTG-CONF-01", "WSTG-CONF-02"),\n    expected_cwe=("CWE-1104", "CWE-1357", "CWE-1395"),\n    writeups=(writeup(\n        "GHSL-2024-171 / QGIS Poisoned Pipeline Execution",\n        "https://securitylab.github.com/advisories/GHSL-2024-171_QGIS/",\n        "exact",\n        "Build/dependency metadata is only a surface; promotion requires evidence that untrusted or compromised supply-chain input can affect a privileged build, component, or update path.",\n    ),),\n)\n''')
write("app/family_detectors/cryptographic_failure.py", '''from .base import make_spec, writeup\nSPEC = make_spec(\n    family="cryptographic_failure",\n    strategy="cryptographic_control_failure",\n    surface_terms=("tls", "ssl", "cipher", "crypto", "encrypt", "decrypt", "hash", "md5", "sha1", "random", "nonce", "iv", "key"),\n    surface_fields=("cipher", "algorithm", "key", "nonce", "iv", "tls_version", "signature", "hash"),\n    confounders=("security_misconfiguration", "authentication_session", "secret_exposure", "sensitive_caching"),\n    expected_wstg=("WSTG-CRYP-01",),\n    expected_cwe=("CWE-319", "CWE-327", "CWE-338", "CWE-757"),\n    writeups=(writeup(\n        "GHSL-2021-1012 / keypair weak randomness duplicate RSA keys",\n        "https://securitylab.github.com/advisories/GHSL-2021-1012-keypair/",\n        "exact",\n        "Crypto API names are not findings; decisive evidence is an actually weak algorithm, predictable randomness, key reuse, downgrade, or plaintext handling of sensitive data.",\n    ),),\n)\n''')
write("app/family_detectors/software_data_integrity_failure.py", '''from .base import make_spec, writeup\nSPEC = make_spec(\n    family="software_data_integrity_failure",\n    strategy="software_data_integrity_boundary",\n    surface_terms=("update", "firmware", "artifact", "signature", "integrity", "deserialize", "serialized", "plugin", "module", "cdn"),\n    surface_fields=("artifact", "signature", "checksum", "payload", "serialized", "plugin", "module", "update_url"),\n    confounders=("software_supply_chain_failure", "mass_assignment", "command_injection", "unsafe_api_consumption"),\n    expected_wstg=("WSTG-CONF-02",),\n    expected_cwe=("CWE-345", "CWE-494", "CWE-502", "CWE-829"),\n    writeups=(writeup(\n        "GHSL-2024-301 / springboot-openai-chatgpt unsafe deserialization",\n        "https://securitylab.github.com/advisories/GHSL-2024-301_274056675_springboot-openai-chatgpt/",\n        "exact",\n        "Serialization or update functionality is only a trust surface; promotion requires evidence that untrusted code/data crosses the integrity boundary without effective authenticity/integrity verification.",\n    ),),\n)\n''')
write("app/family_detectors/security_logging_alerting_failure.py", '''from .base import make_spec, writeup\nSPEC = make_spec(\n    family="security_logging_alerting_failure",\n    strategy="security_event_logging_and_alerting",\n    surface_terms=("log", "logging", "audit", "alert", "monitor", "telemetry", "security event", "failed login"),\n    surface_fields=("log", "audit_log", "logger", "alert", "event", "telemetry", "monitoring"),\n    confounders=("information_disclosure", "security_misconfiguration", "exceptional_condition_mishandling"),\n    expected_wstg=("WSTG-CONF-02", "WSTG-ERRH-01"),\n    expected_cwe=("CWE-117", "CWE-532", "CWE-778"),\n    writeups=(writeup(\n        "GHSA-vqf5-2xx6-9wfm / GitHub token written to debug artifacts",\n        "https://github.com/advisories/GHSA-vqf5-2xx6-9wfm",\n        "exact",\n        "Do not infer missing monitoring from a public response; promotion requires stored logging/telemetry/config evidence such as a missed security event, absent alert, unsafe log content, or log-integrity failure.",\n        source="GitHub Advisory Database",\n    ),),\n)\n''')
write("app/family_detectors/exceptional_condition_mishandling.py", '''from .base import make_spec, writeup\nSPEC = make_spec(\n    family="exceptional_condition_mishandling",\n    strategy="exception_fail_closed_behavior",\n    surface_terms=("exception", "error", "panic", "crash", "rollback", "fail open", "timeout", "null pointer", "segmentation fault"),\n    surface_fields=("error", "exception", "status", "rollback", "transaction", "panic", "crash"),\n    confounders=("information_disclosure", "security_misconfiguration", "business_logic", "race_condition", "security_logging_alerting_failure"),\n    expected_wstg=("WSTG-ERRH-01", "WSTG-ERRH-02"),\n    expected_cwe=("CWE-248", "CWE-636", "CWE-703", "CWE-755"),\n    writeups=(writeup(\n        "GHSL-2023-116 / MySQL unsafe exceptional state transition",\n        "https://securitylab.github.com/advisories/GHSL-2023-116_MySQL/",\n        "adjacent_primary_case",\n        "Exception text alone is disclosure context; promotion requires an unsafe exceptional-condition outcome such as a crash, fail-open control path, corrupted state, or partial transaction effect.",\n    ),),\n)\n''')

# ---------------------------------------------------------------------------
# 4) Metadata-only physical raw collector for the five new families.
# ---------------------------------------------------------------------------
write("app/raw_family_collectors/owasp_top10_2025.py", '''from __future__ import annotations\n\nfrom typing import Any, Mapping\n\nfrom family_detectors.registry import DETECTOR_SPECS\nfrom raw_family_collectors.base import RawFamilyObservation\n\nOWASP_TOP10_2025_COLLECTOR_VERSION = "1.0.0"\nOWASP_TOP10_2025_COLLECTOR_RULE_VERSION = "2026.08.12.6.25"\nOWASP_TOP10_2025_FAMILIES = (\n    "software_supply_chain_failure",\n    "cryptographic_failure",\n    "software_data_integrity_failure",\n    "security_logging_alerting_failure",\n    "exceptional_condition_mishandling",\n)\n\nOWASP_TOP10_2025_OBSERVATIONS: dict[str, RawFamilyObservation] = {\n    "software_supply_chain_failure": RawFamilyObservation(\n        family="software_supply_chain_failure", variant="component_or_pipeline_trust", base=14, impact=88,\n        missing=("Exact affected deployed component/build path", "Observed vulnerable, unmaintained, untrusted, or compromised supply-chain condition", "Whether the component/pipeline condition reaches the target runtime or privileged build"),\n        rules=("raw-collector-owasp-top10-2025-v1", "candidate-supply-chain-surface", "admission-supply-chain-condition"),\n        summary="Stored component/build artifacts expose a supply-chain hypothesis; promotion requires a concrete vulnerable, unmaintained, untrusted, or compromised component/pipeline condition.",\n    ),\n    "cryptographic_failure": RawFamilyObservation(\n        family="cryptographic_failure", variant="cryptographic_control", base=16, impact=84,\n        missing=("Exact security-sensitive cryptographic purpose", "Observed weak/downgraded/predictable/reused/plaintext behavior", "Effective TLS/algorithm/key-generation control"),\n        rules=("raw-collector-owasp-top10-2025-v1", "candidate-crypto-surface", "admission-crypto-failure"),\n        summary="Stored crypto/TLS artifacts expose a cryptographic-control hypothesis; promotion requires an observed weak, predictable, reused, downgraded, or plaintext security condition.",\n    ),\n    "software_data_integrity_failure": RawFamilyObservation(\n        family="software_data_integrity_failure", variant="code_or_data_integrity", base=14, impact=90,\n        missing=("Exact code/data trust boundary", "Observed missing signature/integrity verification or unsafe deserialization/trust", "Whether untrusted code/data reaches an executable or security-sensitive sink"),\n        rules=("raw-collector-owasp-top10-2025-v1", "candidate-integrity-boundary", "admission-integrity-failure"),\n        summary="Stored update/serialization/plugin artifacts expose an integrity-boundary hypothesis; promotion requires a concrete missing-verification or unsafe-trust condition.",\n    ),\n    "security_logging_alerting_failure": RawFamilyObservation(\n        family="security_logging_alerting_failure", variant="security_event_visibility", base=10, impact=64,\n        missing=("Exact auditable security event", "Stored logging/telemetry evidence for missing/unsafe logging or alerting", "Expected detection/retention/integrity policy"),\n        rules=("raw-collector-owasp-top10-2025-v1", "candidate-security-logging", "admission-logging-alerting-failure"),\n        summary="Stored logging/telemetry artifacts expose a security-observability hypothesis; absence is never inferred from HTTP behavior and promotion requires concrete logging/alerting evidence.",\n    ),\n    "exceptional_condition_mishandling": RawFamilyObservation(\n        family="exceptional_condition_mishandling", variant="fail_closed_exception_handling", base=14, impact=82,\n        missing=("Exact exceptional/abnormal condition", "Observed fail-open, crash, partial commit, state corruption, or control bypass", "Expected fail-closed/rollback/recovery behavior"),\n        rules=("raw-collector-owasp-top10-2025-v1", "candidate-exception-surface", "admission-exception-outcome"),\n        summary="Stored exception/error artifacts expose an exceptional-condition hypothesis; promotion requires an observed unsafe fail-open, crash, state, transaction, or control outcome.",\n    ),\n}\n\n\ndef validate_owasp_top10_2025_collectors() -> list[str]:\n    errors: list[str] = []\n    if set(OWASP_TOP10_2025_OBSERVATIONS) != set(OWASP_TOP10_2025_FAMILIES):\n        errors.append("OWASP Top 10:2025 collector profile coverage drift")\n    for family in OWASP_TOP10_2025_FAMILIES:\n        observation = OWASP_TOP10_2025_OBSERVATIONS.get(family)\n        spec = DETECTOR_SPECS.get(family)\n        if spec is None:\n            errors.append(f"missing physical detector spec: {family}")\n            continue\n        if observation is None or observation.family != family:\n            errors.append(f"missing/mismatched collector metadata: {family}")\n            continue\n        if not observation.variant or observation.base <= 0 or not observation.rules:\n            errors.append(f"incomplete collector metadata: {family}")\n        if not spec.wstg_ids:\n            errors.append(f"detector lacks WSTG grounding: {family}")\n        if not spec.owasp_ids:\n            errors.append(f"detector lacks OWASP grounding: {family}")\n        if not spec.cwe_ids:\n            errors.append(f"detector lacks CWE grounding: {family}")\n        if not spec.writeups:\n            errors.append(f"detector lacks write-up grounding: {family}")\n        if any(ref.counts_as_target_evidence for ref in spec.writeups):\n            errors.append(f"write-up counted as target evidence: {family}")\n        if not spec.condition_signals:\n            errors.append(f"detector lacks condition contract: {family}")\n    return errors\n\n\ndef collect_owasp_top10_2025_observations(execution_map: Mapping[str, Mapping[str, Any]]) -> list[RawFamilyObservation]:\n    errors = validate_owasp_top10_2025_collectors()\n    if errors:\n        raise RuntimeError("Invalid Analysis 6.25 OWASP Top 10:2025 collector registry: " + "; ".join(errors))\n    return [\n        OWASP_TOP10_2025_OBSERVATIONS[family]\n        for family in OWASP_TOP10_2025_FAMILIES\n        if OWASP_TOP10_2025_OBSERVATIONS[family].packet_present(execution_map)\n    ]\n''')

# Export collector.
insert_before_once(
    "app/raw_family_collectors/__init__.py",
    "\n__all__ = [",
    '''\nfrom raw_family_collectors.owasp_top10_2025 import (\n    OWASP_TOP10_2025_COLLECTOR_RULE_VERSION,\n    OWASP_TOP10_2025_COLLECTOR_VERSION,\n    OWASP_TOP10_2025_FAMILIES,\n    OWASP_TOP10_2025_OBSERVATIONS,\n    collect_owasp_top10_2025_observations,\n    validate_owasp_top10_2025_collectors,\n)\n''',
)
replace_once(
    "app/raw_family_collectors/__init__.py",
    '    "validate_injection_collectors",\n]',
    '    "validate_injection_collectors",\n    "OWASP_TOP10_2025_COLLECTOR_VERSION",\n    "OWASP_TOP10_2025_COLLECTOR_RULE_VERSION",\n    "OWASP_TOP10_2025_FAMILIES",\n    "OWASP_TOP10_2025_OBSERVATIONS",\n    "collect_owasp_top10_2025_observations",\n    "validate_owasp_top10_2025_collectors",\n]',
)

# ---------------------------------------------------------------------------
# 5) Candidate registry/orchestration.
# ---------------------------------------------------------------------------
replace_once(
    "app/bug_candidates.py",
    "from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations",
    "from raw_family_collectors import collect_api_configuration_observations, collect_authentication_observations, collect_authorization_observations, collect_business_logic_observations, collect_client_side_observations, collect_exposure_headers_observations, collect_file_remote_resource_observations, collect_injection_observations, collect_owasp_top10_2025_observations",
)

new_schemas = r'''    "software_supply_chain_failure": {"required_any": (("component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "component_fingerprint"), ("known_vulnerable_component_observed", "unmaintained_component_confirmed", "untrusted_component_source", "privileged_pipeline_executes_untrusted_code", "component_update_path_compromised")), "label": "supply-chain surface plus observed vulnerable/untrusted component or pipeline condition"},
    "cryptographic_failure": {"required_any": (("cryptographic_surface", "transport_crypto_surface", "key_generation_surface", "sensitive_transport"), ("weak_crypto_algorithm_observed", "weak_tls_observed", "cryptographic_key_reuse", "predictable_randomness_observed", "crypto_downgrade_observed", "plaintext_sensitive_transport")), "label": "crypto/transport surface plus observed cryptographic control failure"},
    "software_data_integrity_failure": {"required_any": (("integrity_boundary", "update_artifact", "serialized_input", "external_code_dependency"), ("unsigned_update_accepted", "integrity_check_missing", "untrusted_code_executed", "unsafe_deserialization_observed", "unsigned_serialized_data_trusted")), "label": "code/data integrity boundary plus observed missing verification or unsafe trust"},
    "security_logging_alerting_failure": {"required_any": (("auditable_security_event", "logging_surface", "security_control_event"), ("security_event_not_logged", "alerting_absent_observed", "sensitive_data_logged", "log_injection_observed", "log_integrity_missing")), "label": "security-event/logging surface plus stored logging/alerting failure evidence"},
    "exceptional_condition_mishandling": {"required_any": (("exception_surface", "abnormal_input_context", "transactional_operation"), ("unhandled_exception_observed", "fail_open_observed", "state_corruption_after_error", "partial_commit_after_error", "crash_on_exception", "exception_control_bypass")), "label": "exception surface plus observed unsafe exceptional-condition outcome"},
'''
insert_before_once("app/bug_candidates.py", "}\n\nBUG_FAMILIES: dict[str, dict[str, Any]] = {", new_schemas)

new_bug_families = r'''    "software_supply_chain_failure": {"label": "Software Supply Chain Failure", "impact": 88, "category": "supply_chain"},
    "cryptographic_failure": {"label": "Cryptographic Failure", "impact": 84, "category": "cryptography"},
    "software_data_integrity_failure": {"label": "Software or Data Integrity Failure", "impact": 90, "category": "integrity"},
    "security_logging_alerting_failure": {"label": "Security Logging and Alerting Failure", "impact": 64, "category": "observability"},
    "exceptional_condition_mishandling": {"label": "Mishandling of Exceptional Conditions", "impact": 82, "category": "error_handling"},
'''
insert_before_once("app/bug_candidates.py", "}\n\nSAFE_ACTIONS = {", new_bug_families)

new_safe_actions = r'''    "software_supply_chain_failure": "Review SBOM/dependency/build provenance and deployment reachability. Do not execute untrusted pipeline code or modify third-party registries; confirm only from stored, authorized artifacts.",
    "cryptographic_failure": "Review stored TLS/algorithm/key-generation evidence and the sensitivity of protected data. Do not attempt downgrade or key-recovery attacks unless explicitly authorized.",
    "software_data_integrity_failure": "Trace update, plugin, serialization, and signature/integrity boundaries from stored artifacts. Do not load untrusted code or destructive serialized payloads.",
    "security_logging_alerting_failure": "Use existing authorized logs, telemetry, and configuration to compare expected security events with recorded/alerted events. Never infer missing logging merely because it is invisible to the client.",
    "exceptional_condition_mishandling": "Review stored abnormal/error outcomes for fail-open, crash, rollback, or state inconsistency. Do not intentionally crash services or corrupt state; active fault injection requires explicit authorization.",
'''
insert_before_once("app/bug_candidates.py", "}\n\nPRIVILEGED_FIELDS", new_safe_actions)

collector_loop = r'''    # Analysis 6.25 — physical OWASP Top 10:2025 completion collector ownership.
    # The collector is metadata-only. WSTG/OWASP/CWE/write-ups define criteria;
    # target evidence remains solely in passive execution/reconstruction and admission.
    for observation in collect_owasp_top10_2025_observations(execution_map):
        emit(
            observation.family,
            observation.variant,
            observation.base,
            [],
            [],
            list(observation.missing),
            list(observation.rules),
            observation.summary,
            direct=observation.direct,
            impact=observation.impact,
        )

'''
insert_before_once("app/bug_candidates.py", "    # BOLA / IDOR 2.0", collector_loop)

# ---------------------------------------------------------------------------
# 6) Passive/offline execution heuristics. Strong conditions are inferred only
#    where stored artifacts themselves demonstrate them. Explicit normalized
#    condition flags are already handled by _explicit_contract_flags().
# ---------------------------------------------------------------------------
execution_constants = r'''SUPPLY_CHAIN_SURFACE_MARKERS = ("package-lock", "yarn.lock", "pnpm-lock", "requirements.txt", "poetry.lock", "pom.xml", "build.gradle", "sbom", "dependency", "dependencies", "github actions", ".github/workflows", "ci/cd", "artifact registry", "container image")
CRYPTO_SURFACE_MARKERS = ("tls", "ssl", "cipher", "crypto", "encrypt", "decrypt", "signature", "nonce", "random", "md5", "sha1", "sha-1", "aes", "rsa", "ecdsa")
INTEGRITY_SURFACE_MARKERS = ("deserialize", "deserialization", "objectinputstream", "readobject", "pickle.loads", "yaml.load(", "fastjson", "autotype", "enabledefaulttyping", "firmware update", "software update", "plugin update", "signature verification", "checksum", "integrity")
LOGGING_SURFACE_MARKERS = ("audit log", "audit_log", "security log", "logger", "logging", "alerting", "telemetry", "monitoring", "security event")
EXCEPTION_SURFACE_MARKERS = ("uncaught exception", "unhandled exception", "nullpointerexception", "panic:", "segmentation fault", "fatal exception", "rollback", "fail open", "fail-open")
LOG_CONTENT_KEYS = {"log_entry", "log_message", "logger_output", "audit_log", "audit_entry", "debug_log", "telemetry_event", "security_event"}
'''
insert_before_once("app/family_detectors/execution.py", "\n\n@dataclass(frozen=True)\nclass ExecutionProfile:", "\n" + execution_constants)

execution_heuristics = r'''    # Analysis 6.25: OWASP Top 10:2025 completion families. These rules remain
    # passive/offline and only use stored target artifacts. In particular, missing
    # client-visible logging is never interpreted as a logging failure.
    supply_dependency_keys = {"package", "package_name", "package_version", "dependency", "dependencies", "component", "component_version", "sbom", "artifact", "repository", "image"}
    supply_keys = sorted(set(flat) & supply_dependency_keys)
    supply_surface = bool(supply_keys) or any(marker in surface_text for marker in SUPPLY_CHAIN_SURFACE_MARKERS)
    if supply_surface:
        packet = _packet_for(result, "software_supply_chain_failure")
        if any(marker in surface_text for marker in ("github actions", ".github/workflows", "ci/cd", "workflow", "pipeline")):
            _add_identity(packet, "software_supply_chain_failure", "build_pipeline", "stored_build_artifact", "Stored artifacts expose a build/CI pipeline trust surface.", "supply_chain_surface", 14)
        else:
            _add_identity(packet, "software_supply_chain_failure", "component_inventory", "stored_component_artifact", "Stored dependency/component metadata exposes a supply-chain inventory surface.", "supply_chain_surface", 14)

    crypto_surface = any(marker in surface_text for marker in CRYPTO_SURFACE_MARKERS) or endpoint.lower().startswith("http://")
    if crypto_surface:
        packet = _packet_for(result, "cryptographic_failure")
        _add_identity(packet, "cryptographic_failure", "cryptographic_surface", "stored_crypto_artifact", "Stored artifacts contain cryptographic/TLS/key-generation semantics.", "crypto_surface", 12)
        if endpoint.lower().startswith("http://"):
            _add_identity(packet, "cryptographic_failure", "transport_crypto_surface", "endpoint", "Stored target endpoint uses cleartext HTTP transport.", "crypto_surface", 14)
        security_sensitive_transport = bool(auth_hints) or bool(all_fields & SENSITIVE_FIELD_WORDS) or any(word in text_lower for word in SENSITIVE_FIELD_WORDS)
        if endpoint.lower().startswith("http://") and security_sensitive_transport:
            _add_identity(packet, "cryptographic_failure", "sensitive_transport", "endpoint_context", "Cleartext endpoint carries an authentication or sensitive-data context.", "crypto_context", 16)
            _add(packet, "support", _signal("cryptographic_failure", "plaintext_sensitive_transport", "endpoint_transport", "Stored target evidence shows security-sensitive traffic exposed over cleartext HTTP.", source_group="crypto_behavior", weight=30, basis="sensitive_cleartext_endpoint"))
        weak_algo = any(token in text_lower for token in ("md5(", "md5.new", "sha1(", "sha-1")) and any(token in text_lower for token in ("password", "secret", "token", "signature", "key", "credential", "auth"))
        if weak_algo:
            _add(packet, "support", _signal("cryptographic_failure", "weak_crypto_algorithm_observed", "stored_source", "Stored source uses MD5/SHA-1 in a security-sensitive credential/key/signature context.", source_group="crypto_behavior", weight=28, basis="security_context_weak_algorithm"))
        weak_random = any(token in text_lower for token in ("math.random", "random.random(", "rand()")) and any(token in text_lower for token in ("token", "secret", "key", "nonce", "session", "password reset"))
        if weak_random:
            _add_identity(packet, "cryptographic_failure", "key_generation_surface", "stored_source", "Stored source uses a random generator in a security-token/key/nonce context.", "crypto_context", 14)
            _add(packet, "support", _signal("cryptographic_failure", "predictable_randomness_observed", "stored_source", "Stored source ties a non-cryptographic random primitive to a security-token/key/nonce context.", source_group="crypto_behavior", weight=28, basis="security_context_weak_randomness"))

    unsafe_deser = any(marker in text_lower for marker in ("objectinputstream", "readobject(", "pickle.loads", "yaml.load(", "fastjson", "autotype", "enabledefaulttyping"))
    integrity_surface = unsafe_deser or any(marker in surface_text for marker in INTEGRITY_SURFACE_MARKERS)
    if integrity_surface:
        packet = _packet_for(result, "software_data_integrity_failure")
        if unsafe_deser:
            _add_identity(packet, "software_data_integrity_failure", "serialized_input", "stored_source", "Stored source exposes an object deserialization boundary.", "integrity_surface", 16)
            _add_identity(packet, "software_data_integrity_failure", "integrity_boundary", "stored_source", "Deserialized data crosses a code/data trust boundary.", "integrity_context", 12)
            if all_fields:
                _add(packet, "support", _signal("software_data_integrity_failure", "unsafe_deserialization_observed", "stored_source_relation", "Client-controlled request fields are present on an endpoint whose stored source uses an unsafe deserialization primitive.", source_group="integrity_behavior", weight=30, basis="client_input_to_unsafe_deserialization_surface"))
        else:
            signal = "update_artifact" if any(token in surface_text for token in ("update", "firmware", "plugin")) else "integrity_boundary"
            _add_identity(packet, "software_data_integrity_failure", signal, "stored_integrity_artifact", "Stored artifacts expose an update/code/data integrity trust boundary.", "integrity_surface", 14)

    log_values: list[str] = []
    for key in LOG_CONTENT_KEYS:
        for value in flat.get(key, []):
            if isinstance(value, str):
                log_values.append(value[:16384])
            elif isinstance(value, Mapping):
                try:
                    log_values.append(json.dumps(value, ensure_ascii=False, sort_keys=True)[:16384])
                except (TypeError, ValueError):
                    pass
    log_text = "\n".join(log_values).lower()
    logging_surface = bool(log_values) or any(marker in surface_text for marker in LOGGING_SURFACE_MARKERS)
    if logging_surface:
        packet = _packet_for(result, "security_logging_alerting_failure")
        _add_identity(packet, "security_logging_alerting_failure", "logging_surface", "stored_logging_artifact", "Stored target artifacts expose a logging/audit/alerting/telemetry surface.", "logging_surface", 14)
        if any(token in surface_text for token in AUTH_MARKERS) or admin or flow_hits:
            _add_identity(packet, "security_logging_alerting_failure", "auditable_security_event", "endpoint_semantic", "The stored endpoint represents an authentication, privileged, or sensitive business event that should be auditable.", "security_event_surface", 10)
        if log_text and any(token in log_text for token in ("authorization: bearer", "bearer eyj", "password=", "password:", "access_token=", "refresh_token=", "api_key=", "client_secret=")):
            _add(packet, "support", _signal("security_logging_alerting_failure", "sensitive_data_logged", "stored_log_content", "Stored log/telemetry content contains credential- or secret-bearing material.", source_group="logging_behavior", weight=30, basis="stored_sensitive_log_content"))

    exception_surface = any(marker in surface_text for marker in EXCEPTION_SURFACE_MARKERS) or _flag(flat, "exception_unhandled") or _flag(flat, "process_crashed")
    if exception_surface:
        packet = _packet_for(result, "exceptional_condition_mishandling")
        _add_identity(packet, "exceptional_condition_mishandling", "exception_surface", "stored_error_artifact", "Stored target artifacts expose an exceptional/error-handling surface.", "exception_surface", 14)
        if method in {"POST", "PUT", "PATCH", "DELETE"} and flow_hits:
            _add_identity(packet, "exceptional_condition_mishandling", "transactional_operation", "endpoint_contract", "Exceptional behavior occurs on a state-changing business operation.", "exception_context", 12)
        strong_unhandled = any(marker in text_lower for marker in ("uncaught exception", "unhandled exception", "nullpointerexception", "panic:", "segmentation fault", "fatal exception"))
        if status >= 500 and strong_unhandled:
            _add(packet, "support", _signal("exceptional_condition_mishandling", "unhandled_exception_observed", "stored_error_response", "Stored server-error response records an unhandled/fatal exceptional condition.", source_group="exception_behavior", weight=28, basis="server_error_with_unhandled_exception"))
        if status >= 500 and any(marker in text_lower for marker in ("panic:", "segmentation fault")):
            _add(packet, "support", _signal("exceptional_condition_mishandling", "crash_on_exception", "stored_error_response", "Stored error artifact contains a process-crash signature under an exceptional condition.", source_group="exception_behavior", weight=30, basis="crash_signature_in_server_error"))

'''
insert_before_once("app/family_detectors/execution.py", "    version_hits = re.findall", execution_heuristics)

# ---------------------------------------------------------------------------
# 7) Historical seals remain minimum lineage assertions when new families are
#    added; the current 6.25 test below owns the exact 36-family assertion.
# ---------------------------------------------------------------------------
for test_path in (ROOT / "tests").glob("test_*.py"):
    text = test_path.read_text(encoding="utf-8")
    updated = text.replace(
        "self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 31)",
        "self.assertGreaterEqual(len(FAMILY_ADMISSION_POLICIES), 31)",
    )
    if updated != text:
        test_path.write_text(updated, encoding="utf-8")

# ---------------------------------------------------------------------------
# 8) Dedicated contract tests.
# ---------------------------------------------------------------------------
write("tests/test_owasp_top10_2025_completion_v6250.py", r'''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, validate_family_standards
from family_detectors import get_detector_spec, validate_detector_registry, execute_detector_intelligence
from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission
from raw_family_collectors import (
    OWASP_TOP10_2025_COLLECTOR_RULE_VERSION,
    OWASP_TOP10_2025_FAMILIES,
    collect_owasp_top10_2025_observations,
    validate_owasp_top10_2025_collectors,
)


NEW_FAMILIES = {
    "software_supply_chain_failure",
    "cryptographic_failure",
    "software_data_integrity_failure",
    "security_logging_alerting_failure",
    "exceptional_condition_mishandling",
}


class OwaspTop102025Completion6250Tests(unittest.TestCase):
    def test_exact_family_count_and_new_family_ownership(self) -> None:
        self.assertEqual(len(FAMILY_ADMISSION_POLICIES), 36)
        self.assertEqual(set(OWASP_TOP10_2025_FAMILIES), NEW_FAMILIES)
        self.assertEqual(OWASP_TOP10_2025_COLLECTOR_RULE_VERSION, "2026.08.12.6.25")
        self.assertEqual(validate_owasp_top10_2025_collectors(), [])
        self.assertEqual(validate_family_standards(FAMILY_ADMISSION_POLICIES), [])
        self.assertEqual(validate_detector_registry(), [])

    def test_owasp_top10_2025_is_exactly_ten_of_ten(self) -> None:
        top10 = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("A") and str(ref.get("id") or "").endswith(":2025")
        }
        self.assertEqual(top10, {f"A{i:02d}:2025" for i in range(1, 11)})
        api = {
            str(ref.get("id"))
            for profile in FAMILY_STANDARDS.values()
            for ref in profile.get("owasp", [])
            if str(ref.get("id") or "").startswith("API") and str(ref.get("id") or "").endswith(":2023")
        }
        self.assertEqual(api, {f"API{i}:2023" for i in range(1, 11)})

    def test_new_families_keep_four_layer_grounding_and_non_evidence_writeups(self) -> None:
        expected = {
            "software_supply_chain_failure": ({"WSTG-CONF-01", "WSTG-CONF-02"}, {"A03:2025"}, {"CWE-1104", "CWE-1357", "CWE-1395"}),
            "cryptographic_failure": ({"WSTG-CRYP-01"}, {"A04:2025"}, {"CWE-319", "CWE-327", "CWE-338", "CWE-757"}),
            "software_data_integrity_failure": ({"WSTG-CONF-02"}, {"A08:2025"}, {"CWE-345", "CWE-494", "CWE-502", "CWE-829"}),
            "security_logging_alerting_failure": ({"WSTG-CONF-02", "WSTG-ERRH-01"}, {"A09:2025"}, {"CWE-117", "CWE-532", "CWE-778"}),
            "exceptional_condition_mishandling": ({"WSTG-ERRH-01", "WSTG-ERRH-02"}, {"A10:2025"}, {"CWE-248", "CWE-636", "CWE-703", "CWE-755"}),
        }
        for family, (wstg, owasp, cwe) in expected.items():
            spec = get_detector_spec(family)
            self.assertEqual(set(spec.wstg_ids), wstg, family)
            self.assertEqual(set(spec.owasp_ids), owasp, family)
            self.assertEqual(set(spec.cwe_ids), cwe, family)
            self.assertTrue(spec.writeups, family)
            self.assertTrue(all(ref.lesson.strip() for ref in spec.writeups), family)
            self.assertTrue(all(not ref.counts_as_target_evidence for ref in spec.writeups), family)

    def test_collector_is_metadata_only(self) -> None:
        execution = {family: {"support": [{"type": "surface"}], "contradict": []} for family in NEW_FAMILIES}
        observations = collect_owasp_top10_2025_observations(execution)
        self.assertEqual({row.family for row in observations}, NEW_FAMILIES)
        for row in observations:
            self.assertFalse(hasattr(row, "support"))
            self.assertFalse(hasattr(row, "evidence"))

    def test_supply_chain_surface_without_condition_stays_hidden(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/assets/app.js",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"source_code": "package-lock.json dependencies component version registry"},
        )
        packet = packets["software_supply_chain_failure"]
        assessment = assess_admission("software_supply_chain_failure", packet["support"], packet["contradict"])
        self.assertFalse(assessment["admitted"])
        self.assertTrue({"component_inventory", "dependency_manifest", "build_pipeline", "artifact_repository", "component_fingerprint"} & {x.get("type") for x in packet["support"]})

    def test_crypto_cleartext_sensitive_transport_can_admit_from_real_stored_context(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="http://example.test/login",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["password"], "path_parameters": [], "object_identifiers": [], "authentication_hints": ["session"]},
            details={"status_code": 200},
        )
        packet = packets["cryptographic_failure"]
        types = {x.get("type") for x in packet["support"]}
        self.assertIn("plaintext_sensitive_transport", types)
        self.assertTrue(assess_admission("cryptographic_failure", packet["support"], packet["contradict"])["admitted"])

    def test_unsafe_deserialization_requires_a_real_input_relation(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/import",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["payload"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"source_code": "ObjectInputStream in = new ObjectInputStream(req.getInputStream()); Object x = in.readObject();"},
        )
        packet = packets["software_data_integrity_failure"]
        self.assertIn("unsafe_deserialization_observed", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("software_data_integrity_failure", packet["support"], packet["contradict"])["admitted"])

    def test_logging_failure_is_not_inferred_from_login_without_log_artifacts(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/login",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["username", "password"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 401, "response_body": "invalid credentials"},
        )
        self.assertNotIn("security_logging_alerting_failure", packets)

    def test_sensitive_log_content_is_real_logging_condition(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/admin/audit",
            method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": ["session"]},
            details={"audit_log": "login success authorization: bearer eyJREDACTEDTOKEN"},
        )
        packet = packets["security_logging_alerting_failure"]
        self.assertIn("sensitive_data_logged", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("security_logging_alerting_failure", packet["support"], packet["contradict"])["admitted"])

    def test_unhandled_server_exception_can_admit_but_plain_error_text_cannot(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test",
            endpoint="/api/process",
            method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["input"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 500, "response_body": "Uncaught exception: NullPointerException"},
        )
        packet = packets["exceptional_condition_mishandling"]
        self.assertIn("unhandled_exception_observed", {x.get("type") for x in packet["support"]})
        self.assertTrue(assess_admission("exceptional_condition_mishandling", packet["support"], packet["contradict"])["admitted"])
        near = execute_detector_intelligence(
            target="example.test", endpoint="/api/process", method="POST",
            endpoint_schema={"query_parameters": [], "body_fields": ["input"], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={"status_code": 400, "response_body": "validation error"},
        )
        if "exceptional_condition_mishandling" in near:
            n = near["exceptional_condition_mishandling"]
            self.assertFalse(assess_admission("exceptional_condition_mishandling", n["support"], n["contradict"])["admitted"])

    def test_external_owasp_condition_never_counts_as_target_evidence(self) -> None:
        packets = execute_detector_intelligence(
            target="example.test", endpoint="/", method="GET",
            endpoint_schema={"query_parameters": [], "body_fields": [], "path_parameters": [], "object_identifiers": [], "authentication_hints": []},
            details={},
            evidence_for=[{"type": "known_vulnerable_component_observed", "source": "OWASP", "source_group": "wstg", "text": "external taxonomy only"}],
        )
        self.assertNotIn("software_supply_chain_failure", packets)


if __name__ == "__main__":
    unittest.main()
''')

write("docs/ANALYSIS_ENGINE_6_25_OWASP_TOP10_COMPLETION.md", '''# Analysis Engine 6.25 — OWASP Top 10:2025 Coverage Completion\n\nAnalysis 6.25 adds explicit physical families for the five OWASP Top 10:2025 categories that were not previously represented as first-class vulnerability families:\n\n- A03:2025 Software Supply Chain Failures\n- A04:2025 Cryptographic Failures\n- A08:2025 Software or Data Integrity Failures\n- A09:2025 Security Logging and Alerting Failures\n- A10:2025 Mishandling of Exceptional Conditions\n\nThe five new families use the same WSTG + OWASP + CWE + real-write-up detector contract as the existing families. External standards and write-ups never count as target evidence. Raw collectors are metadata-only; target evidence remains owned by passive/offline detector execution and raw-condition reconstruction.\n\nPrecision boundaries are intentional. Supply-chain and logging failures are not inferred from the absence of client-visible evidence. Exceptional-condition findings require an unsafe observed outcome, not just an error message. Cryptographic and integrity findings require security-sensitive context plus an observed control failure.\n\nWith these additions the engine has 36 total vulnerability families and explicit coverage for all ten OWASP Top 10:2025 categories while preserving all ten OWASP API Security Top 10:2023 category mappings.\n''')

update_manifest()
