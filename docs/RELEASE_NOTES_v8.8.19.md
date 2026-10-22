# Recon Monitor 8.8.19 — Reliable Collection and Baseline Integrity

Application version: **8.8.19**. Core database schema: **18**, unchanged.

This patch release records the collection, Resume and comparison-baseline fixes merged in PRs #194 and #195. It also documents the integrated reliability work retained since 8.8.18.

## Collection and Resume

- Ordinary collector failures retain available observations and allow later collectors, Analysis and reporting to run. A failed collector still makes collection incomplete. Target budget exhaustion and operator interruption continue to stop further collection.
- Resume keeps completed work from the same Run and refreshes downstream stages when an earlier collector adds input. JavaScript queues can progress beyond the per-attempt file limit. Valid JavaScript and source-map 404/410 receipts are reusable, and JavaScript disappearance evidence survives subsequent attempts.
- Execution success and content visibility have separate diagnostics. HTTP 401/403, failed origin probes and other proven gaps remain visible even when Analysis or reporting succeeds. Finalization refreshes diagnostics without target requests or rewriting historical outcomes.
- Shared HTTP cooldowns, including remote-worker leases, remain enforced. The pinned project Katana installer and runtime checks are retained. macOS cancellation now verifies child exit when a concurrent waiter is already reaping the process.

## Comparison baseline integrity

- Only collection-complete observations can establish or refresh the canonical Recon baseline. A failed or partial replacement preserves a healthy committed snapshot.
- Positive evidence that an older baseline was incomplete quarantines that reference. The stored snapshot, Run history, source observations and analyst evidence remain available; comparison and confirmation paths exclude the quarantined reference.
- A complete replacement establishes a fresh comparison reference. Same-Run recovery preserves new observations without rehabilitating unobserved JavaScript or derived receipts from an excluded attempt.
- `platform baseline-repair --target TARGET` reviews retained evidence offline. It uses the scan lock, refuses active targets and is idempotent. See [scan visibility](SCAN_VISIBILITY.md) and [migration](../MIGRATION-v8.8.19.md).

## Compatibility and limits

Core schema 18 is retained. Baseline-integrity tables, frozen coverage receipts and JavaScript comparison flags are installed through additive, independently versioned compatibility metadata. Existing configuration, Run evidence and analyst decisions are preserved.

Browser JavaScript import remains an offline analysis path with source provenance; it does not change the original scan's collection status. Public GraphQL field names alone do not establish excessive data exposure. The separately reviewed Analysis issues are not repaired by this release.

Remote access restrictions, challenge pages, DNS failures and finite crawl budgets can still leave a scan partial. A successful Analysis does not certify complete collection or confirm a vulnerability. Durable Katana continuation still requires a separately installed compatible producer.

## Validation

PR #195's exact source head `4abd27fe05e57fe320e15b43180f43ca8e5081ad` passed all nine CI checks. The local source suite passed 1,941 tests with 3,888 SQLite connections explicitly closed; a subsequent focused recheck passed 84 tests with 157 connections explicitly closed. These results describe the reviewed source fixes. Release packaging and publication require successful CI for the exact resulting main commit and the verified-release workflow's archive and updater checks.
