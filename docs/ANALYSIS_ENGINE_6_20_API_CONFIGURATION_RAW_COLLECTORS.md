# Analysis Engine 6.20 — API / Configuration raw collectors

Analysis 6.20 physically decomposes five remaining API/configuration families from the alert-orchestrator monolith:

- `unrestricted_resource_consumption`
- `sensitive_business_flow_abuse`
- `security_misconfiguration`
- `improper_inventory_management`
- `unsafe_api_consumption`

## Four-layer detector grounding

Every family remains subject to the Analysis 6.19 mandatory detector contract:

1. OWASP WSTG testing method.
2. OWASP Top 10:2025 and/or OWASP API Security Top 10:2023 taxonomy.
3. MITRE CWE weakness taxonomy.
4. A real security write-up that sharpens the family condition, confounders, and decisive-evidence boundary.

For this batch the primary taxonomy anchors are API4:2023, API6:2023, API8:2023, API9:2023, and API10:2023, with family-specific WSTG/CWE mappings already enforced by the physical detector registry.

## Write-up lineage

The batch preserves family-specific write-up lessons and tightens direct advisory URLs for the Mealie resource-consumption case and the Branch Deploy Action control-bypass case. The write-up layer remains detector knowledge only.

## Evidence firewall

WSTG, OWASP, CWE, write-ups, advisories, or other knowledge sources never count as target evidence. They cannot satisfy admission groups, independent-source requirements, or override contradictory target controls. Target evidence is produced only by stored passive execution/reconstruction artifacts.

## Recall-preserving cutover

Before removing the five inline blocks, 6.20 expands passive raw-surface reconstruction for patterns previously owned by the monolith:

- API inventory forms such as `v1`, `v2`, `old`, `legacy`, `dev`, `test`, `staging`, `beta`, and `alpha`.
- Upstream `webhook` trust-boundary surfaces.
- Configuration surfaces such as Swagger, Actuator, phpinfo, server-status, OPTIONS, debug/trace semantics, and cleartext HTTP clues.
- Resource surfaces including PDF/biometric/paid-provider-like and expensive operations.
- Sensitive business-flow semantics including posting, messaging, invitation, and account-creation paths.

These remain surface clues only. Promotion still requires each family's decisive condition evidence and independent-source admission requirements.

## Scientific boundary

This phase is an architecture and regression claim. It does not claim universal vulnerability-detection accuracy and does not consume a new fresh holdout. Existing Golden/raw corpora remain regression assets.
