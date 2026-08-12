from .base import make_spec, writeup
SPEC = make_spec(
    family="account_enumeration",
    strategy="identity_differential",
    surface_terms=("username","email","forgot password","reset password","account exists","user not found"),
    surface_fields=("username","email","login","user"),
    confounders=("authentication_session","information_disclosure"),
    expected_wstg=("WSTG-IDNT-04",),
    expected_cwe=("CWE-204",),
    writeups=(
        writeup(
            "CVE-2022-40482 / Laravel user-enumeration timing differential",
            "https://github.com/advisories/GHSA-5qxg-5vwh-7j5j",
            "exact",
            "Identity input is only a lookup surface; promotion requires a controlled existing/non-existing account discrepancy, and timing is decisive only when repeatable and materially separated.",
            source="GitHub Advisory Database",
        ),
    ),
)
