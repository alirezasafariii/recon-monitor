from .base import make_spec, writeup
SPEC = make_spec(
    family="security_logging_alerting_failure",
    strategy="security_event_logging_and_alerting",
    surface_terms=("log", "logging", "audit", "alert", "monitor", "telemetry", "security event", "failed login"),
    surface_fields=("log", "audit_log", "logger", "alert", "event", "telemetry", "monitoring"),
    confounders=("information_disclosure", "security_misconfiguration", "exceptional_condition_mishandling"),
    expected_wstg=("WSTG-CONF-02", "WSTG-ERRH-01"),
    expected_cwe=("CWE-117", "CWE-532", "CWE-778"),
    writeups=(writeup(
        "GHSA-vqf5-2xx6-9wfm / GitHub token written to debug artifacts",
        "https://github.com/advisories/GHSA-vqf5-2xx6-9wfm",
        "exact",
        "Do not infer missing monitoring from a public response; promotion requires stored logging/telemetry/config evidence such as a missed security event, absent alert, unsafe log content, or log-integrity failure.",
        source="GitHub Advisory Database",
    ),),
)
