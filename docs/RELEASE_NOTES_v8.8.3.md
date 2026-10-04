# Recon Monitor 8.8.3 — macOS Process Cleanup

Recon Monitor 8.8.3 fixes the process cleanup error that caused the 8.8.2 update to roll back during local tests on macOS with Python 3.14. It includes all collection and operational fixes in 8.8.2.

## Correct cleanup and interruption results

- All CommandRunner group signals share one checked shutdown path. A macOS permission denial after the direct child has exited is recorded without aborting bounded pipe cleanup. This handles the detached pipe-holder regression while preserving captured output and the actual Timeout or Operator Next outcome.
- Permission failures while the direct child is alive, permission failures on other platforms, and unexpected signal errors remain failures. Watchdog signal errors reach the calling thread instead of disappearing into an unhandled thread exception.
- The runner remains reusable after interrupted cleanup. Seven additional offline regressions cover Timeout, Next, cancellation, original callback errors, genuine permission errors, and unexpected signal errors. The existing detached-child and force-kill tests remain enabled on macOS.

## Cross-platform checks

- CI runs the full unit suite and fixture integration on Linux with Python 3.11, 3.13, and 3.14.
- CI also runs the full unit suite and fixture integration on Intel and Apple Silicon macOS with Python 3.14, alongside the existing strict macOS API lifecycle checks. Command cleanup is tested separately with ResourceWarning promoted to an error.
- Existing unrelated Python 3.14 database ResourceWarnings are not suppressed by this fix. The reported update failure was the CommandRunner PermissionError.

## Upgrade and compatibility

Application version: **8.8.3**. Core database schema: **18**, unchanged from 8.8.1 and 8.8.2. No manual database migration or target scan is required.

If installation of 8.8.2 reported a validation rollback, first check the installed version, then use the normal authenticated GitHub update path:

```bash
./recon-monitor.sh --version
./recon-monitor.sh update check --repo alirezasafariii/recon-monitor
./recon-monitor.sh update install --repo alirezasafariii/recon-monitor
./recon-monitor.sh --version
./recon-monitor.sh doctor
```

The final version must be `8.8.3`. The release assets are `recon-monitor-v8.8.3.zip` and `recon-monitor-v8.8.3.zip.sha256`. Publication verifies packaged source files, manifest entries, the matching SHA-256 sidecar, and downloaded assets against the tested release source. Local validation remains enabled; neither sudo nor skipping tests is needed for this correction.
