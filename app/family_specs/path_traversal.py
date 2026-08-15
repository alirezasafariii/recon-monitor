from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


PATH_TRAVERSAL_STANDARD_SPEC = FamilyStandardSpec(
    family="path_traversal",
    version="1.0.0",
    strategy="filesystem_root_containment_boundary",
    principle=(
        "Path or filename inputs plus file operations are attack-surface context only; promotion requires stored "
        "target evidence that a controlled non-sensitive test path escaped the intended root and reached the file operation."
    ),
    owasp=("A01:2025 Broken Access Control",),
    wstg=("WSTG-ATHZ-01",),
    cwe=("CWE-22", "CWE-23", "CWE-36"),
    capec=("CAPEC-139", "CAPEC-597"),
    methodology=(
        MethodologyStep(
            id="PATH-01-path-surface",
            basis=("WSTG-ATHZ-01", "CWE-22"),
            principle="Identify a concrete user-influenced path, filename, archive member or storage-path input and a filesystem-relevant operation.",
        ),
        MethodologyStep(
            id="PATH-02-root-policy",
            basis=("WSTG-ATHZ-01", "CWE-22"),
            principle="Model the intended root/base directory, canonicalization, absolute-path, allow-list and archive extraction containment policy.",
        ),
        MethodologyStep(
            id="PATH-03-controlled-boundary-observation",
            basis=("WSTG-ATHZ-01", "CWE-23", "CWE-36"),
            principle="Promotion requires a controlled non-sensitive test resource that should remain inside or be rejected but resolves outside the root and reaches a file operation.",
        ),
        MethodologyStep(
            id="PATH-04-controls",
            basis=("CWE-22", "CWE-23", "CWE-36"),
            principle="Canonicalization, real-path/root containment, absolute-path rejection and archive-member normalization are contradiction evidence when enforced.",
        ),
        MethodologyStep(
            id="PATH-05-confirmation",
            basis=("WSTG-ATHZ-01", "CWE-22", "GHSL-2024-073"),
            principle="Confirmation requires out-of-root access/write behavior or an actual canonicalization/root-containment bypass tied to the same controlled operation.",
        ),
    ),
    surface_terms=("path", "filename", "directory", "download", "archive", "extract", "import", "upload", "storage path"),
    surface_fields=("path", "file_path", "filename", "directory", "folder", "storage_path", "archive_entry", "member_path"),
    confounders=("file_upload", "information_disclosure", "file_inclusion"),
    false_positive_checks=(
        "A parameter named path, file, filename or directory is only an input surface.",
        "A download, archive, import, extract or upload route does not prove the supplied path reaches a filesystem operation.",
        "Normalization changes or parent-directory syntax do not prove that the resolved path escaped the intended root.",
        "Direct evidence is limited to explicitly controlled non-sensitive test resources.",
        "Canonicalization, root containment, absolute-path rejection and archive-member normalization contradict traversal when enforced.",
        "File Upload acceptance and Information Disclosure consequences are neighboring concerns, not substitutes for proving the path boundary failure.",
        "OWASP, WSTG, CWE, CAPEC and write-up similarity add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="ghsl-2024-073-reposilite-path-traversal",
            source="GitHub Security Lab",
            ref="GHSL-2024-073 / Reposilite path traversal",
            url="https://securitylab.github.com/advisories/GHSL-2024-072_GHSL-2024-074_Reposilite/",
            relation="direct_archive_path_traversal",
            lesson=(
                "Reposilite constructed extraction paths from untrusted archive entry names without containment, "
                "allowing paths outside the intended extraction directory. The reusable lesson is root containment at the actual filesystem operation."
            ),
            signal_hints=("archive_operation", "path_escape_observed", "canonicalization_bypass_observed", "out_of_root_file_write_observed"),
        ),
    ),
)
