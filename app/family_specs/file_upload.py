from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


FILE_UPLOAD_STANDARD_SPEC = FamilyStandardSpec(
    family="file_upload",
    version="1.0.1",
    strategy="file_policy_processing_boundary",
    principle=(
        "A file field, multipart request, or upload route is only attack-surface context; promotion requires "
        "stored behavior showing an explicitly controlled inert file outside the intended policy was accepted. "
        "Confirmation requires a file-validation bypass or unsafe execution/serving boundary."
    ),
    owasp=("OWASP File Upload Cheat Sheet",),
    wstg=("WSTG-BUSL-08", "WSTG-BUSL-09"),
    cwe=("CWE-434",),
    capec=(),
    methodology=(
        MethodologyStep(
            id="FILE-01-upload-surface",
            basis=("WSTG-BUSL-08", "CWE-434"),
            principle="Identify a concrete file input and upload/import operation; multipart, filename, or route names alone remain structural evidence.",
        ),
        MethodologyStep(
            id="FILE-02-expected-file-policy",
            basis=("WSTG-BUSL-08", "WSTG-BUSL-09"),
            principle="Model expected extension, MIME/signature, size, filename, archive/content, authorization and serving/storage controls.",
        ),
        MethodologyStep(
            id="FILE-03-controlled-acceptance",
            basis=("WSTG-BUSL-08", "CWE-434"),
            principle="Promotion requires stored behavior from a controlled inert test file that policy says should be rejected but the application accepts.",
        ),
        MethodologyStep(
            id="FILE-04-processing-storage-boundary",
            basis=("WSTG-BUSL-09", "CWE-434"),
            principle="Separate simple acceptance from validation bypass and execution-capable or unsafe serving/storage behavior.",
        ),
        MethodologyStep(
            id="FILE-05-confirmation-boundary",
            basis=("WSTG-BUSL-08", "WSTG-BUSL-09", "CWE-434", "GHSL-2026-052"),
            principle="Confirmation requires stored evidence of a content/type validation bypass or execution-capable unsafe handling, never a filename or HTTP status alone.",
        ),
    ),
    surface_terms=("upload", "import", "multipart", "attachment", "avatar", "document", "media", "archive"),
    surface_fields=("file", "filename", "attachment", "avatar", "document", "upload_file", "import_file", "archive"),
    confounders=("path_traversal", "stored_xss", "information_disclosure"),
    false_positive_checks=(
        "multipart/form-data, a file field, or an upload route proves only an upload surface.",
        "HTTP success or a returned file identifier does not prove that a policy-disallowed file was accepted or persisted.",
        "A policy-allowed inert file being accepted is expected behavior.",
        "Direct promotion evidence is limited to explicitly controlled inert test files with a documented expected rejection.",
        "Observed extension, MIME/signature, archive/content, size or authorization enforcement contradicts unsafe acceptance where relevant.",
        "Isolated storage, generated filenames, disabled execution and forced attachment serving reduce downstream impact and must be retained as controls.",
        "Client-supplied Content-Type is not authoritative; a bypass requires stored target differential evidence.",
        "OWASP, WSTG, CWE and write-ups never count as target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-upload",
            source="OWASP Cheat Sheet Series",
            ref="OWASP File Upload Cheat Sheet",
            url="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            relation="canonical_defensive_method",
            lesson=(
                "File-upload assessment must connect extension/content validation, storage, naming, authorization and serving behavior. "
                "The checklist defines expected controls but never proves a target is vulnerable."
            ),
            signal_hints=("file_input", "unsafe_file_accepted", "content_type_bypass_observed", "file_type_enforcement_observed", "safe_storage_observed"),
        ),
        WriteupLesson(
            id="ghsl-2026-052-docmost-mime-spoofing",
            source="GitHub Security Lab",
            ref="GHSL-2026-052 / Docmost MIME type spoofing",
            url="https://securitylab.github.com/advisories/GHSL-2026-052_docmost/",
            relation="direct_file_validation_serving_boundary",
            lesson=(
                "Docmost trusted client-controlled MIME metadata and later used it for inline serving. "
                "The reusable detector lesson is to connect upload validation to persisted metadata and downstream serving behavior."
            ),
            signal_hints=("unsafe_file_accepted", "content_type_bypass_observed", "executable_upload_observed", "safe_storage_observed"),
        ),
    ),
)
