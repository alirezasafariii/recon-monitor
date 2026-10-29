# Analysis evidence facts and independent sources

Analysis retains distinct supporting and contradicting facts even when they
share a source group. Source correlation limits independent score contributions;
it does not remove types needed by family prerequisites, admission checks or
contradiction assessment.

Previously, semantic enrichment selected only the strongest fact in a group.
For example, an SSRF observation could retain `server_fetch_observed` while
discarding `url_parameter` and `server_fetch_semantic`. Final reasoning then
reported incomplete prerequisites despite those facts being present in the
original hypothesis.

## Current contract

- `independent_evidence` preserves every input fact and reports source-group
  counts separately. The compatibility import from `candidate_intelligence`
  remains available.
- Final evidence identity includes the exact typed fact, its provenance and
  polarity. Different types, response codes, identity contexts and raw
  references cannot replace each other because their summary text is similar.
  Derived IDs, correlation counts and weight updates do not change fact identity.
- Exact duplicate facts select the stronger weight and retain the excluded
  duplicate in the audit trail. Distinct correlated facts remain linked and
  snapshotted. A shared evidence record is updated without deleting other
  candidates' links or snapshots through SQLite replacement cascades.
- Trust averaging, direct-source counts, independent-source promotion thresholds
  and repeated contradiction penalties use source groups, not the number of
  typed facts. Different types can legitimately satisfy different prerequisites;
  they do not become separate independent confirmations.
- Reasoning lineage distinguishes retained fact counts from independent source
  counts. `double_counted_signals_suppressed` in enrichment and
  `suppressed_correlated_signals` in reasoning describe extra scoring
  contributions that were suppressed; retained facts have not been discarded.
- Semantic rules are `2026.10.29.1` (engine `5.1.1`) and final reasoning rules
  are `2026.10.29.1` (engine `5.2.2`). Older cached reasoning is retained but
  cannot substitute for results under the new rule version.

No database migration, network request, baseline update or automatic replay of
historical analyses is required. The correction applies to new analyses and
explicit replays. Historical runs, hypotheses, analyst decisions and evidence
from earlier analyses remain stored with their original provenance. It cannot
reconstruct observations that were never collected, and complete prerequisite
coverage is not a confirmed vulnerability.

## Regression coverage

`tests/test_evidence_grouping.py` exercises enrichment, materialization, shared
evidence links, immutable historical snapshots, polarity separation, repeated
weight updates, independent-source promotion and cache-version isolation. Its
full Analysis regression starts from a stored endpoint observation and verifies
that required SSRF coverage remains 100% after enrichment and final reasoning.
All fixtures are offline; DNS, socket connections and subprocess launch are
blocked. Correlated supporting and contradicting repetitions are also checked
for score inflation or excessive repeated penalties.
