# Analysis Engine 6.15 — Fresh Raw Holdout v3 Result

Analysis 6.15 evaluated the frozen Analysis 6.14 engine exactly once on a newly collected, source-isolated raw-artifact holdout. The benchmark was sealed before scoring and was immediately marked consumed after the first evaluation.

## Corpus

- 96 cases: 24 source roots × 4 variants
- 24 distinct source projects
- 18 positive vulnerability families
- prior source-root overlap: 0
- prior advisory-URL overlap: 0
- positive/control exact raw collisions: 0
- positive observable-delta rate: 1.0
- corpus SHA-256: `ee17e481dd543a8cd0a9c35c07e2eab32f6cbac8e15d62016c9b953799e6d10f`

All roots from the complete Analysis 6.13/v2 discovery inventory were also excluded from v3 discovery. Where the fully unseen GitHub Reviewed Advisory pool could not preserve the pre-registered family floor, zero-overlap primary GitHub Security Lab or vendor advisories were used and independently checked against prior benchmark provenance before materialization.

## First and only fresh evaluation

- Run: `31559204156`
- Trigger SHA: `4fb15070d2c084bcf14f5cbf91d8f798bf483713`
- Frozen production engine head: `50b9875c3d358f6a3e38a4946e5d72eb1e3dc50e`

Metrics:

- condition extraction precision: `1.000000`
- condition extraction recall: `1.000000`
- routing Top-1 accuracy: `0.930556`
- routing Top-3 accuracy: `0.958333`
- admission precision: `1.000000`
- admission recall: `1.000000`
- abstention accuracy: `1.000000`
- false-promotion rate: `0.000000`
- wrong-family promotion rate: `0.000000`
- end-to-end accuracy: `1.000000`
- prior source-root overlap rate: `0.000000`
- raw-label leakage rate: `0.000000`

All pre-registered raw quality gates passed.

## Scientific boundary

This result supports generalization of the 6.14 raw-condition calibration within the curated raw-artifact benchmark boundary represented by v3. It is not a universal claim about real-world vulnerability detection accuracy, and it does not prove coverage for arbitrary recon formats or every vulnerability family.

Raw v3 is now permanently `evaluated_once_consumed`. Any future execution against v3 is regression-only and must never be described as fresh or blind.
