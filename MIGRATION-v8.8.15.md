# Recon Monitor 8.8.15 — Katana Batch Exit Margin

Application version: **8.8.15**. Database schema: **18**, unchanged.

The macOS 8.8.14 target run exposed a deadline collision: five sequential
15-second crawls shared a 75-second outer process timeout. Eleven batches
hit that timeout; a final shorter batch returned zero and was correctly
marked completion_unverified.

Finite batches now reserve 0.5–5 seconds for startup and shutdown inside the
existing outer envelope. Internal crawl time is shortened, not the wall
budget extended: the 75-second example uses five 14-second crawls. Batches
without enough time for a one-second crawl per input and the exit margin
are not launched, reserve no requests and retain pending origins.

The rate, request allowance, global deadline, scope and configured timeout
are unchanged. Deadline-limited zero exits remain completion_unverified;
URLs are preserved and the stage stays partial. The margin is bounded and
cannot guarantee that every crawler shutdown finishes in time. Live target
acceptance of this change is pending. No historical results are rewritten.

Regression coverage includes 60 origins in 12 batches and insufficient
runtime. Publication requires green exact-main CI, verified archive and
manifest, actual updater installs and downloaded asset verification.
