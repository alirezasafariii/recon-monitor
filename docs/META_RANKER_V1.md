# Meta Ranker V1

Meta Ranker V1 turns Recon Monitor's existing evidence, vulnerability-profile
compatibility, writeup retrieval, analyst history, and related-surface context
into an explainable multi-label **bug proximity** ranking.

It does **not** confirm vulnerabilities and it does not replace family admission.

## Two scores, two meanings

Every ranked family exposes two intentionally separate scores:

- `bug_proximity_score`: how closely the observed surface resembles a bug family
  and how useful it is to investigate that direction;
- `target_evidence_confidence`: how much family-specific evidence was actually
  observed on the target.

`target_evidence_confidence` is calculated only from target observations that
match the family's strong/medium/weak signal vocabulary plus independent target
source groups and contradictions.

The following inputs are advisory and **cannot** increase target evidence
confidence or satisfy admission:

- taxonomy/profile knowledge;
- writeup similarity;
- historical analyst feedback;
- candidate/surface correlation;
- LLM advisory scores.

## V1 component weights

The default proximity weights are:

| Component | Weight | Evidentiary? |
| --- | ---: | --- |
| target evidence | 40% | yes, target observations only |
| profile compatibility | 30% | no |
| writeup similarity | 15% | no |
| historical feedback | 7% | no |
| related-surface correlation | 5% | no |
| LLM advisory | 3% | no |

Missing optional components are excluded rather than replaced with an invented
neutral score.

## Guardrails

Knowledge-only resemblance is useful for discovery but must remain visibly weak.
Meta Ranker therefore applies hard caps:

- zero family-specific target evidence => proximity cannot exceed `35`;
- target evidence below `25` => proximity cannot exceed `55`;
- no strong family signal and weak evidence => proximity cannot exceed `69`;
- family contradictions reduce both target-evidence confidence and proximity;
- LLM advisory has no path into target-evidence confidence and has only a small
  proximity weight.

The output status is always `proximity_only_not_confirmed`.

## Runtime integration

`hypothesis_admission.py` calculates admission first. Only after that decision is
fixed does it build the knowledge/meta-ranking context.

For persisted hypotheses the runtime also supplies two existing Recon Monitor
signals as non-evidentiary priors:

1. **historical analyst prior** — reviewed outcomes for the same target/family,
   shrunk toward neutral until enough reviews exist;
2. **related-surface correlation** — already-promoted candidates sharing the
   current endpoint, alert, or source reference.

The resulting object is persisted under:

```text
analysis_hypotheses.admission_json
  -> knowledge_context
     -> meta_ranker
```

The primary result can also produce safe classification tags such as:

```text
proximity-family:broken-object-authorization
proximity:high
hunt-priority:high
```

These tags mean "review this direction" and never "vulnerability confirmed".

## Example

```json
{
  "family": "broken_object_authorization",
  "bug_proximity_score": 82,
  "target_evidence_confidence": 70,
  "proximity_band": "high",
  "hunt_priority": "HIGH",
  "components": {
    "target_evidence": 70,
    "profile_compatibility": 92,
    "writeup_similarity": 96,
    "historical_feedback": null,
    "correlation": null,
    "llm_advisory": null
  },
  "status": "proximity_only_not_confirmed"
}
```

## Next step

V1 deliberately stops at hypothesis-level ranking and safe tags. The next phase
is to persist/serve the same ranking in the candidate investigation queue and
then upgrade correlation from exact shared surfaces to object-model and
cross-endpoint clusters.
