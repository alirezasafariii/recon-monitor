from .base import make_spec, writeup
SPEC = make_spec(
    family="software_data_integrity_failure",
    strategy="software_data_integrity_boundary",
    surface_terms=("update", "firmware", "artifact", "signature", "integrity", "deserialize", "serialized", "plugin", "module", "cdn"),
    surface_fields=("artifact", "signature", "checksum", "payload", "serialized", "plugin", "module", "update_url"),
    confounders=("software_supply_chain_failure", "mass_assignment", "command_injection", "unsafe_api_consumption"),
    expected_wstg=("WSTG-CONF-02",),
    expected_cwe=("CWE-345", "CWE-494", "CWE-502", "CWE-829"),
    writeups=(writeup(
        "GHSL-2024-301 / springboot-openai-chatgpt unsafe deserialization",
        "https://securitylab.github.com/advisories/GHSL-2024-301_274056675_springboot-openai-chatgpt/",
        "exact",
        "Serialization or update functionality is only a trust surface; promotion requires evidence that untrusted code/data crosses the integrity boundary without effective authenticity/integrity verification.",
    ),),
)
