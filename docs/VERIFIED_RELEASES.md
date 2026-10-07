# Verified releases

The canonical workflow is .github/workflows/verified-release.yml. It accepts a version, full main commit SHA and expected Git tree through workflow_call or workflow_dispatch. The caller must use main or a publish/vVERSION-* branch. Publication is serialized.

Before packaging and again before draft creation and final publication, tools/verify_release_ci.py checks the latest push CI run for exactly that main SHA. Branch/PR CI cannot substitute. All seven required jobs must succeed; macOS unit tests, integration and cleanup must explicitly succeed. Missing, skipped, cancelled or failed jobs block publication. A moved main ref or changed CI attempt also blocks it. Re-run a failed CI job after investigating its logs, then retry publication; do not bypass the gate.

Packaging verifies source bytes/modes, manifest, version consistency, integration and actual 8.8.3/8.8.5 updater installs. The draft assets are downloaded and compared byte for byte before Latest is published. Verification reports and the CI proof are retained as workflow artifacts. This workflow does not claim cryptographic package signatures.
