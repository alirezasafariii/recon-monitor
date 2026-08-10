# Analysis 6.10 — Detector Execution Intelligence

Analysis 6.10 turns the 6.9 physical family contracts into passive/offline executors over stored target artifacts.

## Core boundary

`stored raw/minimally-normalized artifact -> detector execution -> physical family detector 6.9 -> family evidence firewall 6.8 -> admission -> family reasoner 6.7 -> candidate`

The execution layer never sends a request, follows a redirect, guesses an identifier, mutates application state, generates an exploit payload, or validates a secret online. It only reads artifacts already stored by Recon Monitor.

## Non-negotiable epistemic rules

1. External OWASP/WSTG/CWE/write-up material is detector knowledge only and never target evidence.
2. A surface clue is not a vulnerability condition.
3. Condition evidence is family-specific and cannot satisfy another family's condition group.
4. Blocking controls remain first-class contradictory evidence and can prevent admission.
5. Execution-only signals that do not pass admission remain hidden hypotheses.
6. Secret-like material is redacted and represented by a fingerprint; the raw value is not persisted by the executor.
7. Passive error signatures are evidence of an observed interpreter/database error, not automatic proof of exploitability.

## Versions

- Analysis Engine: `6.10.0`
- Candidate Engine: `6.10.0`
- Security Reasoning Engine: `6.10.0`
- Physical Detector Engine: `1.0.0`
- Detector Execution Engine: `1.0.0`
- Execution Rule: `2026.08.11.6.10`

## Execution input contract

Each alert is executed once against:

- endpoint and HTTP method;
- endpoint schema: query/body/path fields, object identifiers, authentication hints;
- stored details and bounded raw response/source snippets;
- stored `evidence_for` / `evidence_against` entries;
- category and business context;
- stored contextual/behavioral observations when available.

The result is a sparse map:

`family -> support + contradict + execution rule IDs`

Only the packet for the family currently being emitted is merged into that family's hypothesis. This prevents cross-family execution evidence leakage.

## Family execution matrix

| Family | Passive/offline execution logic | Decisive evidence remains |
|---|---|---|
| `broken_object_authorization` | object identifiers + object operation + stored identity/authorization contexts | cross-owner/tenant/scope or unauthorized object behavior |
| `broken_function_authorization` | privileged route/function semantics + state change + stored role contexts | lower-privilege/unauthorized function success or role differential |
| `mass_assignment` | writable contract + privilege-sensitive body fields | server acceptance/application of unauthorized privileged property |
| `authentication_session` | login/session/OAuth/SAML/recovery/token lifecycle surfaces | stored lifecycle/boundary regression or validation failure |
| `account_enumeration` | identity fields in lookup/login/recovery flows | controlled response/error/timing account-existence differential |
| `dom_xss` | stored JavaScript browser sources + dangerous DOM/JS sinks | runtime-reachable unsanitized source-to-sink flow |
| `postmessage_trust` | message handlers + adjacent sensitive browser actions | missing origin/source/schema enforcement |
| `open_redirect` | redirect fields + stored Location/client navigation sink | unintended external destination acceptance |
| `ssrf` | remote URL fields + stored server-fetch/source primitives | observed server-side outbound request behavior |
| `file_upload` | file/multipart contract + upload/import operation | unsafe file type/storage/serving/filename behavior |
| `path_traversal` | path/filename fields + file operations | path escape/confinement/canonicalization failure |
| `information_disclosure` | stored debug/stack-trace/sensitive response material | public/unintended response exposure |
| `source_map_exposure` | `.map`/sourceMappingURL + sources/sourcesContent + stored status | meaningful source content plus direct public reachability |
| `secret_exposure` | redacted secret patterns + client/source context + entropy fingerprinting | non-placeholder credential/token evidence in client context |
| `graphql_authorization` | GraphQL operation + object IDs | resolver/object authorization failure |
| `graphql_data_exposure` | GraphQL operation + sensitive field contract | actual field exposure outside intended policy |
| `business_logic` | state-changing business-flow semantics | observed invariant/value/state transition violation |
| `race_condition` | state-changing single-use/balance semantics | duplicate effect/atomicity/concurrency invariant failure |
| `websocket_authorization` | WebSocket/subscription surface + channel/room/user selectors | unauthorized subscription/message scope failure |
| `cors_misconfiguration` | ACAO policy + request Origin + ACAC + auth/sensitive context | unsafe origin policy combined with credentials/sensitive exposure |
| `sensitive_caching` | cache directives + sensitive/auth context + Vary/CDN evidence | shared-cache isolation weakness |
| `sql_injection` | input/query surface + passive SQL/database error signatures | SQL semantic/error/boolean/timing/query-construction influence |
| `nosql_injection` | structured/document-query surface + passive NoSQL errors | operator/query influence or auth/result differential |
| `command_injection` | input fields + stored shell/process API semantics | observed process/command effect or unsafe command construction |
| `server_side_template_injection` | input + stored server-render/template semantics + template errors | observed server-side expression evaluation |
| `ldap_injection` | directory/LDAP surface + passive LDAP error signatures | filter/result/auth influence |
| `unrestricted_resource_consumption` | limit/batch/expensive-operation surfaces + stored HTTP controls | missing/ineffective size/rate/timeout/cost control |
| `sensitive_business_flow_abuse` | purchase/reservation/signup/redeem/etc. flow semantics | missing/bypassable automation/business-frequency restriction |
| `security_misconfiguration` | transport, stack trace, directory listing and explicit config flags | directly observed insecure configuration |
| `improper_inventory_management` | version/legacy/non-production route semantics + stored reachability | active legacy/undocumented/non-production security-relevant exposure |
| `unsafe_api_consumption` | third-party/upstream semantics + stored upstream configuration | unsafe upstream transport/trust/redirect/resource/auth/validation behavior |

## Explicit passive control extraction

Some stored observations reduce confidence rather than increase it:

- HTTP `429` -> `rate_limit_enforced` for unrestricted resource consumption;
- HTTP `413` -> `payload_size_rejected`;
- stored lower-privilege denial -> BFLA control evidence;
- stored unauthorized object denial -> BOLA control evidence;
- family-specific explicit blocking-control flags -> contradiction packet.

These controls are passed through the existing 6.9/6.8 firewall and admission system. The executor cannot override them.

## Cross-family isolation

Focused regression tests enforce, among other boundaries:

- SQL error signatures do not become NoSQL conditions;
- server-fetch evidence does not become Open Redirect evidence;
- an external `Location` response does not become SSRF evidence;
- resource-control observations remain contradictory controls;
- external knowledge never enters target evidence;
- secret values never appear in executor output.

## Pipeline integration

`bug_candidates._alert_candidates()` executes `execute_detector_intelligence()` once for each alert. The nested `emit(family, ...)` function merges only the matching family's packet before `evaluate_family_detector()` and admission.

If the execution layer discovers a family that legacy surface heuristics did not emit, a `raw_execution_intelligence` fallback hypothesis is recorded. It is still subject to the same physical detector, evidence firewall, and admission gate. There is no execution-layer bypass to candidate promotion.

## Interpretation boundary

Analysis 6.10 improves the conversion of stored recon artifacts into family-specific evidence. It does **not** claim that every real vulnerability can be detected from passive artifacts, and it does not replace controlled analyst validation. A passive error signature or source-code pattern may strengthen a hypothesis, but the existing family-specific admission contract remains authoritative.
