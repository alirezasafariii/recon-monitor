# Feature matrix — Recon Monitor 6.0.1

| Area | Capability | Status / boundary |
|---|---|---|
| Database | Additive migrations | Schema 15 |
| Recon | Scope-aware passive and gated active modules | Implemented |
| Budgets | Runtime, HTTP, DNS, download and asset budgets | Implemented |
| Evidence | Content-addressed objects and ZIP integrity manifest | Implemented |
| Analysis | Semantic, behavioral and security reasoning | Implemented |
| Candidates | Family mapping, independent evidence, calibration and analyst-only confirmation | Implemented |
| Cases | Lifecycle, ownership, stories, validation context and reports | Implemented |
| Safe validation | Offline | Implemented; zero network requests |
| Safe validation | Passive live | Approved in-scope GET/HEAD/OPTIONS only |
| Safe validation | Controlled/high-risk families | Plan-only or manual-only |
| Validation intelligence | Reliability, contexts, comparability, identity, scope and freshness | Implemented |
| Revalidation | Interval/deployment/shape/auth/evidence triggers | Implemented; automatic execution is offline-only |
| Data quality | Coverage scoring and blind-spot detection | Implemented |
| Review priority | Information gain / analyst effort ranking | Implemented |
| Burp round-trip | Redacted package export and structured result import | Implemented; no raw bodies/credentials |
| Stories | Correlation v2 and member lineage | Implemented |
| Scheduler | macOS LaunchAgent generation/application | Implemented; explicit apply, macOS only |
| Scheduled workflow | Quiet hours, recon, sync, offline revalidation, immediate notifications | Implemented |
| Notifications | Immediate/digest/system/silent, policy thresholds, dedup | Implemented |
| Dashboard | Grouped navigation, unified filters, bounded queries and snapshots | Implemented |
| Dashboard | Validation, quality, priority, automation, report, performance, retention and security pages | Implemented |
| API | Local token API with roles, scopes and expiry | Implemented |
| Authentication | Session RBAC, CSRF, lockout and localhost controls | Implemented |
| Audit | Administrative log and tamper-evident hash chain | Implemented |
| Retention | Preview, protected evidence, exact deletion confirmation | Implemented |
| Performance | Route/platform samples, slow operations, DB/WAL and table metrics | Implemented |
| Templates | Passive, web, SPA, API, GraphQL, enterprise and low-noise | Implemented; never changes scope |
| Reports | Automatic quality and missing-section checks | Implemented |
| Plugins | Manifest governance and health history | Implemented; not an OS sandbox |
| Backups | Create, verify, restore and isolated restore drill | Implemented |
| Exploitation | Payload, credential replay, destructive or cross-user automation | Not included |
| Confirmation | Automatic vulnerability confirmation | Not included |
| Tests | Unit suite | 124 tests |
| Tests | Local integration fixture | Implemented |
