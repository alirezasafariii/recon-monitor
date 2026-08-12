from .base import make_spec, writeup
SPEC = make_spec(
    family="exceptional_condition_mishandling",
    strategy="exception_fail_closed_behavior",
    surface_terms=("exception", "error", "panic", "crash", "rollback", "fail open", "timeout", "null pointer", "segmentation fault"),
    surface_fields=("error", "exception", "status", "rollback", "transaction", "panic", "crash"),
    confounders=("information_disclosure", "security_misconfiguration", "business_logic", "race_condition", "security_logging_alerting_failure"),
    expected_wstg=("WSTG-ERRH-01", "WSTG-ERRH-02"),
    expected_cwe=("CWE-248", "CWE-636", "CWE-703", "CWE-755"),
    writeups=(writeup(
        "GHSL-2023-116 / MySQL unsafe exceptional state transition",
        "https://securitylab.github.com/advisories/GHSL-2023-116_MySQL/",
        "adjacent_primary_case",
        "Exception text alone is disclosure context; promotion requires an unsafe exceptional-condition outcome such as a crash, fail-open control path, corrupted state, or partial transaction effect.",
    ),),
)
