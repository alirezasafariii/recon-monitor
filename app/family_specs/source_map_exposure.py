from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


SOURCE_MAP_EXPOSURE_STANDARD_SPEC = FamilyStandardSpec(
    family="source_map_exposure",
    version="1.0.0",
    strategy="public_source_map_internal_structure_exposure",
    principle=(
        "A sourceMappingURL directive, .map filename or internal-looking source path is discovery context only; promotion "
        "requires stored evidence of meaningful source content together with public reachability, or a strong stored "
        "sensitive-source observation retained as an unconfirmed hypothesis until reachability is established."
    ),
    owasp=("A02:2025 Security Misconfiguration",),
    wstg=("WSTG-INFO-05",),
    cwe=("CWE-540", "CWE-497", "CWE-200"),
    capec=(),
    methodology=(
        MethodologyStep(
            id="SMAP-01-reference-surface",
            basis=("WSTG-INFO-05",),
            principle="Treat sourceMappingURL directives and .map references as discovery surface only; a reference does not prove public reachability.",
        ),
        MethodologyStep(
            id="SMAP-02-passive-reachability",
            basis=("WSTG-INFO-05", "CWE-200"),
            principle="Use only already-stored passive collector evidence to establish that the same source map was reachable without credentials.",
        ),
        MethodologyStep(
            id="SMAP-03-source-structure",
            basis=("WSTG-INFO-05", "CWE-497"),
            principle="Require internal source structure, paths, modules or equivalent implementation metadata before a generic public map is treated as meaningful exposure.",
        ),
        MethodologyStep(
            id="SMAP-04-sensitive-content",
            basis=("CWE-540", "CWE-200"),
            principle="Sensitive source content is strong evidence only when explicitly observed in stored redacted metadata; never infer secrets from filenames and never copy source contents into the finding.",
        ),
        MethodologyStep(
            id="SMAP-05-behavioral-decision",
            basis=("A02:2025", "WSTG-INFO-05"),
            principle="A confirmed Potential Finding requires public reachability of the relevant map plus meaningful internal source structure; sensitive content without reachability remains an elevated hidden hypothesis.",
        ),
        MethodologyStep(
            id="SMAP-06-falsification",
            basis=("WSTG-INFO-05",),
            principle="A stored observation that the referenced map is not public contradicts the exposure hypothesis; empty embedded sources may reduce impact but do not erase other exposed internal map metadata.",
        ),
    ),
    surface_terms=("sourcemappingurl", "source map", ".map", "sources", "sourcescontent", "webpack", "vite", "frontend source"),
    surface_fields=("source_map_url", "sourceMappingURL", "sources", "sourcesContent", "sourceRoot"),
    confounders=("information_disclosure", "secret_exposure", "security_misconfiguration"),
    false_positive_checks=(
        "A sourceMappingURL directive or .map filename alone is only a reference surface.",
        "Internal-looking filenames without public reachability do not establish exposure.",
        "A source map available only with authorized credentials is not treated as publicly exposed.",
        "A public map with no meaningful internal source structure is not promoted by this family.",
        "Empty sourcesContent can reduce source-content impact but does not prove that other internal map structure is absent.",
        "Secret/token material remains in the dedicated Secret Exposure family and must stay redacted.",
        "Source contents are never copied into analyzer output.",
        "OWASP, WSTG, CWE and write-ups add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-wstg-info-05-source-maps",
            source="OWASP WSTG",
            ref="WSTG-INFO-05 / Review Web Page Content for Information Leakage",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            relation="canonical_source_map_review_method",
            lesson="Production source maps can expose original frontend source structure and implementation details, but a reference alone is insufficient; the detector must establish actual target-side availability and meaningful content.",
            signal_hints=("source_map", "internal_sources", "source_map_publicly_reachable"),
        ),
        WriteupLesson(
            id="cwe-200-source-code-state",
            source="MITRE CWE",
            ref="CWE-200 / Exposure of Sensitive Information to an Unauthorized Actor",
            url="https://cwe.mitre.org/data/definitions/200.html",
            relation="unauthorized_information_exposure_model",
            lesson="Source and implementation metadata matter when delivered outside the intended audience; public reachability and the exposed information class are separate facts.",
            signal_hints=("source_map_publicly_reachable", "sensitive_source_content_observed"),
        ),
        WriteupLesson(
            id="cwe-540-sensitive-source-code",
            source="MITRE CWE",
            ref="CWE-540 / Inclusion of Sensitive Information in Source Code",
            url="https://cwe.mitre.org/data/definitions/540.html",
            relation="sensitive_source_content_model",
            lesson="Sensitive information embedded in source raises impact, but the engine records only redacted categories and still separates content sensitivity from public reachability.",
            signal_hints=("sensitive_source_content_observed",),
        ),
    ),
)
