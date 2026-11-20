# Final review: browser-backed XSS

The Agent corrections in PR_202_FINAL_REVIEW.md are incorporated in this branch.
The browser review reproduced these additional response-handling defects:

| Response | Before | After |
| --- | --- | --- |
| gzip/deflate response despite an identity request | Content-Encoding was discarded while compressed bytes were forwarded; page broke | Decode the entity, preserve browser-visible decoded bytes and retain wire/decoded hashes |
| Corrupt/unsupported coding | Removing the coding could render bytes a normal client would reject | Capture is incomplete; invalid bytes do not establish execution |
| UTF-16 HTML | Browser could execute while UTF-8 evidence decoding lost the marker | BOM/header/meta-aware text reconstruction preserves evidence |

Real Chromium regressions cover gzip, zlib/raw deflate, stacked encodings,
UTF-16, Windows-1256 and a meta charset declaration, each with executable and
encoded safe controls. Separate corrupt/unknown coding checks remain incomplete.
Decompression checks stop controls between blocks and imposes no total-byte quota.
Brotli is supported only when its optional Python decoder is available; unknown
codings fail explicitly. HTTP entity decoding is distinct from input encodings.

.github/workflows/xss-browser.yml requires a working Chromium before running the
browser acceptance suite, preventing a green run consisting only of skipped
optional tests. Strict browser mode turns fixture startup failures into failures
instead of skips. It targets Linux/macOS, including this stacked PR base. Workflow
configuration is not evidence of a successful hosted run: actual GitHub statuses
must be checked independently.

Review scope: source and synthetic Linux Chromium acceptance. No external target
was scanned. Native macOS/hosted CI and production-application acceptance are not
claimed unless the actual corresponding runs succeed. Both PRs remain unmerged.

Browser failures retain a sanitized network error code when available; full URLs,
payloads and session credentials are not included in diagnostic errors.
