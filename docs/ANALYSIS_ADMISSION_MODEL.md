# Analysis Admission Model

## Goal

Recon Monitor separates **remembering a security clue** from **showing an analyst a Potential Finding**.

The design objective is simultaneous precision and recall:

```text
Observation
  -> Hidden Hypothesis
  -> Evidence Correlation
  -> Family Admission Gate
  -> Candidate / Potential Finding
  -> Analyst Decision
```

A weak clue is never silently deleted merely because it is currently insufficient. It is retained in the hidden hypothesis ledger so later independent evidence can strengthen, contradict, or retire it.

## Epistemic separation

- **Observation**: a stored fact from Recon or another authorized evidence source.
- **Hypothesis**: an internal security explanation suggested by one or more observations. It can be incomplete.
- **Admission**: a deterministic family-specific check that asks whether enough relevant evidence exists to deserve analyst attention.
- **Candidate / Potential Finding**: an admitted, still-unverified hypothesis with traceable evidence.
- **Confirmed**: reserved for an explicit analyst decision; the reasoning engine does not confirm vulnerabilities by itself.

## External knowledge

Security references and real-world writeups are **knowledge context**, not target evidence. They can influence what evidence patterns the engine looks for, but they must never increase a target's evidence count merely because a document describes a vulnerability class.

The current admission knowledge set includes:

- OWASP Web Security Testing Guide / authorization testing
- OWASP Unrestricted File Upload guidance
- OWASP Path Traversal guidance
- MITRE CWE-22 (Path Traversal)
- MITRE CWE-434 (Dangerous File Upload)
- MITRE CWE-639 (Authorization Bypass Through User-Controlled Key)
- PortSwigger Web Security Academy material for IDOR, file upload, and path traversal
- GitHub Security Lab real-world vulnerability research, including archive-path traversal examples

Knowledge references are persisted in the hypothesis record for auditability, but they are kept separate from `supporting_evidence_json` and `evidence_records`.

## File upload admission

A generic `Content-Type`, a word such as `file`, or an endpoint contract alone is a useful clue but does not establish an upload surface.

An analyst-facing File Upload candidate requires both:

1. an actual structured file input, and
2. an upload or import operation.

Examples of stronger evidence include a structured `file`/`attachment`/`filename` field, multipart semantics tied to an explicit upload route, or an upload/import operation tied to a state-changing method.

Generic file metadata stays in the hidden hypothesis ledger until complementary evidence appears.

## Path traversal admission

Words such as `path`, `folder`, or `download` are not sufficient by themselves.

An analyst-facing Path Traversal candidate requires both:

1. user-influenced structured path/filename/storage-path evidence, and
2. a file-relevant operation such as download, import, archive/extract, upload, or another explicit file operation.

This preserves real upload-filename and archive-entry traversal cases while preventing generic metadata from becoming analyst-facing noise.

## Correlation and promotion

Hypotheses use semantic fingerprints derived from target, family, variant, and normalized endpoint. Repeated clues for the same hypothesis are merged before admission is evaluated. This allows complementary evidence arriving through separate observations to promote a previously hidden hypothesis without losing its history.

## Dashboard philosophy

The dashboard remains intentionally small. Hidden hypotheses are not added as a normal navigation surface. They are available for audit through the CLI (`analysis hypotheses`) and can be inspected when debugging engine behavior.

## Safety

Admission only determines whether stored evidence deserves analyst attention. It does not authorize active testing. Live validation remains subject to target scope, explicit authorization, family restrictions, and manual safety controls.
