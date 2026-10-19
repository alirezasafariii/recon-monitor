# Reliability branch review — 2026-10-19

Reviewed against `main` at `6e78bc57545ac369d4ad4026a73cecd250370ef4`:

| Initial branch head | Useful changes beyond shared `c338f89` | Missing changes |
| --- | --- | --- |
| `fix/p3-katana-reliability-integrated-20261019` at `ae6ff135584150cb5206dc7d3fc2376b3c940d03` | Katana signal cancellation; bounded checkpoint shutdown grace; propagate real crawl failures while retaining planned deadline continuation | Project runtime installation, selection and policy-aware CLI preflight |
| `fix/recon-reliability-main-20261018` at `7ad79e96300f1eba74e0a0c703719124f6938c1e` | Pinned project runtime installer; local binary selection; shared contract predicates; policy-aware preflight | The other branch's producer and shutdown changes |

Neither initial branch contained all changes from the other. The existing PR #193 branch is the recommended merge candidate **after incorporating the P3 changes and the repairs below**. Review compared all branch differences and followed collection, queue/checkpoint resume, transport, analysis inputs, reporting and successful baseline promotion. The common collection repairs were retained.

## Confirmed and repaired defects

1. **P1 — Project Katana installation always fails before acceptance.** A literal `\n` joined the contract-check command and `printf`. Bash syntax validation passed, but execution supplied extra arguments to the Python verifier. Separate the commands. A full helper-flow regression checks successful promotion, rejected contracts, failed acceptance, preservation of the existing binary, and paths containing spaces. The real installer was also run from the explicit install entry point against the pinned upstream and loopback fixtures.
2. **P2 — Preflight ignores the selected Python interpreter.** `RECON_PYTHON` selected the CLI interpreter, while preflight independently selected `python3`. A supported custom interpreter could therefore be blocked by an older or differently configured system Python. Both commands now use the selected interpreter. An executable interpreter fixture records both invocations.
3. **P2 — Snapshot database constructor leaks on initialization failure.** Closing on base schema failure did not cover failures after the base connection was opened. Snapshot, lifecycle, stable-confirmation and notification initialization now close the connection before propagating an exception or interrupt. Eight fault-injection subcases failed before the repair and pass with explicit-close tracking afterward. This common fix is also applied to the P3 branch.

4. **P2 — Remote work bypasses shared host cooldown.** The claim API previously consulted only an individual item retry delay, and a remote 429 did not publish the shared host deadline. Claim admission now checks the host table after validating scope. A verified leased 429 atomically stores its queue failure and the requested/final host deadlines. The controller retains longer Retry-After deadlines; invalid/expired leases and unsafe responses cannot publish a cooldown. New regressions cover both task kinds, fresh runs, independent hosts, pagination beyond 50 blocked items, expiry and redirect hosts. This common fix is applied to both branches.

## Integration and validation

- P3 shutdown grace and producer cancellation/error propagation are incorporated into PR #193 without dropping its runtime installation/selection changes.
- Three real process tests cover slow checkpoint publication after Next, external cancellation, and a group leader exiting before its descendant finishes cleanup.
- Producer runner tests preserve genuine errors and unfinished input identity, and accept only the intended bounded-deadline continuation. CI runs these with the race detector alongside existing checkpoint/parser/queue tests, 20 repetitions. Workflow path filters now also cover installer, launcher, runner and contract changes.
- The initial heads passed 1,791 and 1,811 Python tests respectively; each observed 3,443 explicitly closed SQLite connections. These existing passing suites did not cover the three defects above.
- Final combined candidate: **1,820 Python tests passed**, 3,488 SQLite connections explicitly closed, zero ResourceWarnings; fixture integration, release metadata and all 703 manifest entries passed. The repaired P3 branch separately passed 1,798 tests with 3,488 explicit connection closes and zero ResourceWarnings.
- Real local tests cover stock Katana, patched Stage behavior, durable frontier progress, 200 origins/400 retained URLs, DNS fallback with real dnsx/dig, and cooldown across independent runs. The scale backlog progressed `200 → 157 → 118 → 79 → 40 → 1 → 0`; the previous baseline remained unchanged until collection completed.
- The macOS inherited-stdout fixture now allows scheduling margin for its 0.7-second deadline plus the full 1-second grace. Its 2.8-second bound remains below the descendant’s natural 5-second exit; product timeouts are unchanged.
- Exact local results and source/binary identity are recorded in [the acceptance evidence](prototypes/branch-reliability-acceptance-20261019.json). GitHub check results must be read on the final commit, not inferred from either initial head.

## Runtime operation and limits

Install or rebuild the producer matching the checked-out patch with:

```bash
./install.sh --install-project-katana
```

The installer requires Git, Python 3.10+ and a Go compiler compatible with the pinned source (`go 1.26.0`; local validation used 1.26.5). It validates the candidate before replacing `state/bin/katana`. Normal URL-enabled CLI runs require this project-owned completion/checkpoint contract. DNS-only policies and dry-run/help remain available without it. The low-level stock Katana fallback remains independently tested.

Capability help proves protocol support, not the exact source revision of an older installed binary. Rebuild an existing project runtime to receive the latest producer fixes. Cooldown sharing is limited to one installation/database. The 200-origin harness uses controlled loopback targets and fixtures for other stages/analysis/notifications; it does not establish public production-scale coverage. Old empty checkpoint locks still require verification that their legacy owner has stopped before removing only the lock; retain the checkpoint itself.

No branch was merged as part of this review.
