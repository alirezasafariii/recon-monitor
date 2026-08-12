# Analysis Engine 6.18 — File and Remote-Resource Raw Collector Decomposition

Analysis 6.18 continues physical raw-collector decomposition after the sealed 6.17 authorization batch.

## Migration batch

The batch owns exactly three alert-path families:

- Server-Side Request Forgery (`ssrf`)
- File Upload / Import (`file_upload`)
- Path Traversal (`path_traversal`)

`app/raw_family_collectors/file_remote_resource.py` owns emission metadata only: family variant, base score, missing-evidence prompts, rule identifiers, and summary. It never manufactures target evidence. Evidence remains produced by detector execution and raw-condition reconstruction and is still evaluated by the physical family detector, hypothesis ledger, family admission policy, independent-source guard, and candidate insertion path.

## Shared remote-destination metadata

The orchestrator retains the small `ssrf_tokens` / `generic_url_fields` surface calculation because API10 Unsafe Consumption of Third-Party APIs uses that shared context to identify an upstream API surface. Analysis 6.18 removes SSRF emission from that block but does not break the independent API10 family path.

## Validation contract

The migration must retain:

- exact three-family collector coverage;
- positive admission only when each family-specific condition is present;
- abstention on surface-only near misses;
- end-to-end rule lineage through `raw-collector-file-remote-v1`;
- candidate promotion for decisive stored target evidence;
- existing unit, Golden, and integration regressions;
- no change to detector conditions, admission thresholds, ranking, or active-request behavior.

Analysis 6.18 is an architecture/refactor phase and does not create a fresh accuracy claim. The Analysis Engine remains sealed at 6.17.0 until a separate 6.18 seal explicitly advances version lineage after the physical cutover is validated.
