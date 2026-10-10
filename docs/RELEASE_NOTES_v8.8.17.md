# Recon Monitor 8.8.17 — Katana Resume Budget Allocation

Application version: **8.8.17**. Database schema: **18**, unchanged.

Completed origins are removed before allocating the finite Katana crawl envelope. A small unfinished backlog no longer inherits the short per-origin duration of the original large discovery, and completed origins cannot occupy limited request-envelope admission slots. Existing URL evidence, exact-origin scope, rate, request reservations, runtime ceilings and fail-closed completion remain intact. The 30-second per-origin ceiling remains in place; this change does not guarantee completion of large queues.

Resume starts a new crawl session. Internal Katana frontiers are not persisted. Request errors, internal deadlines and missing evidence remain partial. Official Katana does not emit the optional completion contract; the experimental producer is not bundled or installed.

Validation of the runtime fix: 50 Katana tests and the full 1740-test suite passed (one skip); all seven PR #163 CI jobs passed. Regressions cover 600 live origins with one unfinished origin and a late backlog origin with six requests available. The source change is merged as 54f79f928d72eb81fa004c346f3f0d92f3aad8dd. Installed macOS acceptance of 8.8.17 remains pending. Publication is gated on exact-main CI, manifest/archive checks, updater tests and downloaded asset verification.

No historical DNS or crawl state is rewritten. Existing pending origins remain pending until new valid completion evidence is collected.
