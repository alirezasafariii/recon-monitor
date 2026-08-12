from .base import make_spec, writeup
SPEC = make_spec(
    family="sensitive_caching",
    strategy="shared_cache_isolation",
    surface_terms=("cache-control","public","s-maxage","cdn","vary","authorization","etag","no-store"),
    surface_fields=("cache-control","vary","age","x-cache"),
    confounders=("information_disclosure","security_misconfiguration"),
    expected_wstg=("WSTG-ATHN-06",),
    expected_cwe=("CWE-524","CWE-525"),
    writeups=(
        writeup(
            "CVE-2024-45314 / Flask-AppBuilder browser cache of sensitive login fields",
            "https://github.com/dpgaspar/Flask-AppBuilder/security/advisories/GHSA-fw5r-6m3x-rh7p",
            "exact",
            "Sensitive/authenticated content is vulnerable only when caching policy permits retention or cross-context reuse; a cache header or route name alone is not sufficient.",
            source="GitHub Repository Security Advisory",
        ),
    ),
)
