# Analysis Engine 6.14 — Raw Precision Calibration

Analysis 6.14 calibrates raw-artifact evidence boundaries using the already-consumed Analysis 6.13 raw v2 result as a development diagnostic only. It does not alter the v2 corpus, lower admission thresholds, or make a new fresh/blind claim.

## Changes

- Account enumeration requires semantically opposite present/absent identity contexts and a material observable differential; timing-only evidence must clear absolute and relative jitter floors.
- NoSQL error evidence no longer treats generic database/query prose as an error signature.
- CORS sensitive/authenticated context is condition evidence only when an unsafe origin policy is directly observed.
- Command injection gains passive direct input-to-process-sink reconstruction without executing a command.
- Race-condition reconstruction requires explicit stored evidence that multiple concurrent attempts both succeeded.
- Resource-consumption reconstruction requires a successful high-amplification request plus a material stored latency or output-size cost signal.
- Generic login fields no longer make account enumeration outrank authentication unless an explicit enumeration surface or controlled present/absent contexts exist.

## Scientific boundary

The consumed v2 corpus is regression-only. Improvements on it repair known failure modes; they are not evidence of fresh generalization. A future independent raw holdout is required for a new blind claim.
