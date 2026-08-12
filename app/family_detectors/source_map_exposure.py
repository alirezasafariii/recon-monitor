from .base import make_spec, writeup
SPEC = make_spec(
    family="source_map_exposure", strategy="public_internal_source_map",
    surface_terms=("sourcemappingurl",".map","sourcescontent","webpack://","source map"),
    surface_fields=("sourceMappingURL","sources","sourcesContent"),
    confounders=("information_disclosure","secret_exposure"),
    expected_wstg=("WSTG-CONF-04",), expected_cwe=("CWE-200",),
    writeups=(
        writeup(
            "CVE-2024-27257 / IBM OpenPages JavaScript source-map information exposure",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27257",
            "exact",
            "Source-map presence is not sufficient; promotion requires source-map content that discloses meaningful client source information to an unauthorized or unintended audience.",
            source="NVD / IBM vulnerability record",
        ),
    ),
)
