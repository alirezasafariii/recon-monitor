from .base import make_spec, writeup
SPEC = make_spec(
    family="software_supply_chain_failure",
    strategy="supply_chain_provenance_and_component_lifecycle",
    surface_terms=("dependency", "package", "sbom", "lockfile", "workflow", "ci/cd", "artifact", "registry", "container", "component version"),
    surface_fields=("package", "version", "dependency", "artifact", "repository", "image", "workflow", "sbom"),
    confounders=("unsafe_api_consumption", "improper_inventory_management", "software_data_integrity_failure", "security_misconfiguration"),
    expected_wstg=("WSTG-CONF-01", "WSTG-CONF-02"),
    expected_cwe=("CWE-1104", "CWE-1357", "CWE-1395"),
    writeups=(writeup(
        "GHSL-2024-171 / QGIS Poisoned Pipeline Execution",
        "https://securitylab.github.com/advisories/GHSL-2024-171_QGIS/",
        "exact",
        "Build/dependency metadata is only a surface; promotion requires evidence that untrusted or compromised supply-chain input can affect a privileged build, component, or update path.",
    ),),
)
