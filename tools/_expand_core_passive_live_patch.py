from __future__ import annotations

from pathlib import Path
import hashlib


def require_replace(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise RuntimeError(f"patch anchor missing: {label}")
    return text.replace(old, new, 1)


adapter = Path("app/typed_evidence_adapter.py")
text = adapter.read_text(encoding="utf-8")
text = require_replace(
    text,
    "import json\nfrom pathlib import Path",
    "import json\nimport urllib.parse\nfrom pathlib import Path",
    "urllib import",
)
text = require_replace(
    text,
    'TYPED_EVIDENCE_ADAPTER_VERSION = "1.0.0"',
    'TYPED_EVIDENCE_ADAPTER_VERSION = "1.1.0"',
    "adapter version",
)
text = require_replace(
    text,
    'TYPED_EVIDENCE_ADAPTER_RULE_VERSION = "2026.09.14.1"',
    'TYPED_EVIDENCE_ADAPTER_RULE_VERSION = "2026.09.14.2"',
    "adapter rule version",
)
old_supported = '''SUPPORTED_FAMILIES = frozenset(
    {
        "cors_misconfiguration",
        "sensitive_caching",
        "information_disclosure",
        "source_map_exposure",
    }
)'''
new_supported = '''SUPPORTED_FAMILIES = frozenset(
    {
        "authentication_session",
        "account_enumeration",
        "open_redirect",
        "information_disclosure",
        "source_map_exposure",
        "secret_exposure",
        "graphql_data_exposure",
        "cors_misconfiguration",
        "sensitive_caching",
    }
)'''
text = require_replace(text, old_supported, new_supported, "supported families")

anchor = '''def _derive_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
    existing_support_types: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
'''
expansion = r'''
_AUTH_SURFACE_MARKERS = (
    "login", "signin", "sign-in", "logout", "signout", "session", "token",
    "oauth", "saml", "sso", "password", "reset", "recover", "recovery",
    "otp", "mfa", "2fa", "webauthn", "passkey", "account",
)
_SECRET_HINTS = (
    "secret", "token", "credential", "password", "api_key", "apikey",
    "private_key", "access_key", "client_secret", "refresh_token",
)


def _url_parts(
    observation: Mapping[str, Any],
) -> tuple[str, urllib.parse.SplitResult | None]:
    value = str(observation.get("url") or "").strip()
    if not value:
        return "", None
    try:
        return value, urllib.parse.urlsplit(value)
    except ValueError:
        return value, None


def _authentication_session_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        url, parsed = _url_parts(observation)
        surface = (parsed.path if parsed else url).lower()
        if any(marker in surface for marker in _AUTH_SURFACE_MARKERS):
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "authentication_surface",
                    polarity="support",
                    weight=18,
                    text=(
                        "The approved passive-live observation targets a client-visible "
                        "authentication/session surface."
                    ),
                ),
            )
        if str(observation.get("method") or "").strip():
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "client_operation",
                    polarity="support",
                    weight=10,
                    text=(
                        "The approved passive-live artifact records a concrete client-visible "
                        "HTTP operation for the authentication/session surface."
                    ),
                ),
            )
        if int(observation.get("status_code") or 0) in {401, 403}:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "auth_boundary",
                    polarity="support",
                    weight=14,
                    text=(
                        "The anonymous passive-live request was denied with an authentication/"
                        "authorization status, establishing a boundary surface but not a lifecycle weakness."
                    ),
                ),
            )
    return support, []


def _account_enumeration_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        url, parsed = _url_parts(observation)
        surface = (parsed.path if parsed else url).lower()
        if any(marker in surface for marker in _AUTH_SURFACE_MARKERS):
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "authentication_surface",
                    polarity="support",
                    weight=14,
                    text=(
                        "The approved passive-live observation reaches an authentication/account "
                        "surface relevant to enumeration analysis."
                    ),
                ),
            )
        if str(observation.get("method") or "").strip():
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "client_operation",
                    polarity="support",
                    weight=8,
                    text=(
                        "The artifact records one bounded client operation; no real-user identity "
                        "comparison is inferred."
                    ),
                ),
            )
    # One anonymous request cannot establish identity lookup or a response/timing
    # differential. Those signals require explicitly controlled identities.
    return support, []


def _open_redirect_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        headers = _headers(observation)
        location = str(headers.get("location") or "").strip()
        status = int(observation.get("status_code") or 0)
        if location and 300 <= status < 400:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "navigation_context",
                    polarity="support",
                    weight=16,
                    text=(
                        "The approved passive-live response exposes an HTTP redirect/navigation "
                        "context through a Location header."
                    ),
                ),
            )
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "dataflow_sink",
                    polarity="support",
                    weight=10,
                    text=(
                        "A redirect Location sink is present, but the adapter does not infer that "
                        "a user-controlled external destination was accepted."
                    ),
                ),
            )
    return support, []


def _secret_exposure_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        keys, categories = _sensitive_metadata(observation)
        normalized = [
            value.lower().replace("-", "_")
            for value in [*keys, *categories]
        ]
        if not any(
            any(hint in value for hint in _SECRET_HINTS)
            for value in normalized
        ):
            continue
        _append_unique(
            support,
            _signal(
                execution,
                observation,
                "secret_pattern",
                polarity="support",
                weight=20,
                text=(
                    "Redacted response metadata contains a credential/secret-like field or "
                    "pattern category; no secret value is retained or validated."
                ),
            ),
        )
        _append_unique(
            support,
            _signal(
                execution,
                observation,
                "context",
                polarity="support",
                weight=12,
                text=(
                    "The secret-like marker occurs in a bounded stored response-shape context "
                    "from the approved passive-live observation."
                ),
            ),
        )
    # Never synthesize credential_material_confirmed/live_secret_context from
    # field names or redacted categories alone.
    return support, []


def _graphql_data_exposure_signals(
    execution: Mapping[str, Any],
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    support: list[dict[str, Any]] = []
    for observation in observations:
        url, parsed = _url_parts(observation)
        surface = (parsed.path if parsed else url).lower()
        if "graphql" not in surface:
            continue
        keys, categories = _sensitive_metadata(observation)
        if keys or categories:
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "sensitive_fields",
                    polarity="support",
                    weight=18,
                    text=(
                        "Redacted GraphQL response-shape metadata contains sensitive-looking "
                        "fields/categories; field authorization is not inferred."
                    ),
                ),
            )
        if str(observation.get("method") or "").strip():
            _append_unique(
                support,
                _signal(
                    execution,
                    observation,
                    "client_operation",
                    polarity="support",
                    weight=10,
                    text=(
                        "The approved passive-live artifact records a concrete GraphQL endpoint "
                        "operation without inferring resolver/field authorization policy."
                    ),
                ),
            )
    # Never synthesize sensitive_graphql_response_observed or an authorization
    # differential without an explicit expected-field policy and controlled role.
    return support, []


'''
text = require_replace(text, anchor, expansion + anchor, "derive signals anchor")
old_dispatch = '''    family = str(execution.get("family") or "")
    if family == "cors_misconfiguration":
        return _cors_signals(execution, observations)
    if family == "sensitive_caching":
        return _cache_signals(execution, observations)
    if family == "information_disclosure":
        return _information_disclosure_signals(execution, observations)
    if family == "source_map_exposure":
        return _source_map_signals(execution, observations, existing_support_types)
    raise ReconError(f"No typed evidence adapter is registered for family: {family}")'''
new_dispatch = '''    family = str(execution.get("family") or "")
    if family == "authentication_session":
        return _authentication_session_signals(execution, observations)
    if family == "account_enumeration":
        return _account_enumeration_signals(execution, observations)
    if family == "open_redirect":
        return _open_redirect_signals(execution, observations)
    if family == "secret_exposure":
        return _secret_exposure_signals(execution, observations)
    if family == "graphql_data_exposure":
        return _graphql_data_exposure_signals(execution, observations)
    if family == "cors_misconfiguration":
        return _cors_signals(execution, observations)
    if family == "sensitive_caching":
        return _cache_signals(execution, observations)
    if family == "information_disclosure":
        return _information_disclosure_signals(execution, observations)
    if family == "source_map_exposure":
        return _source_map_signals(execution, observations, existing_support_types)
    raise ReconError(f"No typed evidence adapter is registered for family: {family}")'''
text = require_replace(text, old_dispatch, new_dispatch, "family dispatch")
adapter.write_text(text, encoding="utf-8")


tests = Path("tests/test_typed_evidence_adapter.py")
test_text = tests.read_text(encoding="utf-8")
test_anchor = '''    def test_adapter_source_has_no_transport_surface(self):
'''
new_tests = r'''    def test_remaining_core_passive_live_families_are_enrichment_only(self):
        cases = [
            (
                "authentication_session",
                "VEX-AUTH-1",
                "https://api.example.test/session",
                self.fx.observation("https://api.example.test/session", status=401),
                {"authentication_surface", "client_operation", "auth_boundary"},
                {
                    "session_reuse_after_logout",
                    "token_not_rotated",
                    "recovery_bypass",
                    "authentication_state_violation",
                },
            ),
            (
                "account_enumeration",
                "VEX-ENUM-1",
                "https://api.example.test/login",
                self.fx.observation("https://api.example.test/login", status=200),
                {"authentication_surface", "client_operation"},
                {
                    "identity_lookup",
                    "identity_response_differential",
                    "identity_timing_differential",
                },
            ),
            (
                "open_redirect",
                "VEX-REDIRECT-1",
                "https://api.example.test/redirect",
                self.fx.observation(
                    "https://api.example.test/redirect",
                    status=302,
                    headers={"location": "/home"},
                ),
                {"navigation_context", "dataflow_sink"},
                {"external_destination_accepted", "navigation_validation_absent"},
            ),
            (
                "secret_exposure",
                "VEX-SECRET-1",
                "https://api.example.test/config",
                self.fx.observation(
                    "https://api.example.test/config",
                    sensitive_keys=["client_secret"],
                    sensitive_categories=["credential"],
                ),
                {"secret_pattern", "context"},
                {"credential_material_confirmed", "live_secret_context"},
            ),
            (
                "graphql_data_exposure",
                "VEX-GQL-DATA-1",
                "https://api.example.test/graphql",
                self.fx.observation(
                    "https://api.example.test/graphql",
                    sensitive_keys=["viewer.email"],
                ),
                {"sensitive_fields", "client_operation"},
                {
                    "sensitive_graphql_response_observed",
                    "field_authorization_differential",
                },
            ),
        ]
        for family, execution_id, endpoint, observation, expected, forbidden in cases:
            with self.subTest(family=family):
                hypothesis = self.fx.hypothesis(family, endpoint)
                self.fx.write_execution(
                    execution_id=execution_id,
                    hypothesis_id=hypothesis["hypothesis_id"],
                    family=family,
                    endpoint=endpoint,
                    observations=[observation],
                )
                result = self.adapt(execution_id)
                observed = set(result["support_types"])
                self.assertTrue(expected.issubset(observed), (family, observed))
                self.assertTrue(forbidden.isdisjoint(observed), (family, observed))
                self.assertFalse(result["admitted"])
                self.assertEqual(result["candidate_id"], "")
                self.assertFalse(result["vulnerability_confirmed"])

    def test_core_passive_live_family_coverage_is_explicit(self):
        from typed_evidence_adapter import PROMOTION_BRIDGE_FAMILIES, SUPPORTED_FAMILIES

        expected = {
            "authentication_session",
            "account_enumeration",
            "open_redirect",
            "information_disclosure",
            "source_map_exposure",
            "secret_exposure",
            "graphql_data_exposure",
            "cors_misconfiguration",
            "sensitive_caching",
        }
        self.assertTrue(expected.issubset(SUPPORTED_FAMILIES))
        self.assertEqual(
            PROMOTION_BRIDGE_FAMILIES,
            {"cors_misconfiguration", "source_map_exposure"},
        )

'''
test_text = require_replace(test_text, test_anchor, new_tests + test_anchor, "test anchor")
tests.write_text(test_text, encoding="utf-8")


docs = Path("docs/TYPED_EVIDENCE_ADAPTER.md")
doc = docs.read_text(encoding="utf-8")
old_block = '''## Initial family coverage

Version 1.0 supports four `passive_live` families:

- `cors_misconfiguration`: a controlled Origin accepted by the stored CORS policy can become `untrusted_origin_allowed`; credentialed cross-origin readability is never inferred.
- `source_map_exposure`: `source_map_publicly_reachable` is emitted only when the approved anonymous `.map` observation has source-map structure and independent stored evidence already establishes internal source structure.
- `sensitive_caching`: cache headers, sensitive response-shape markers, private/no-store controls, and user-specific `Vary` controls are typed, but this adapter does not synthesize shared-cache or cross-user exposure.
- `information_disclosure`: redacted sensitive-key/category markers can enrich the hypothesis, but visibility-boundary exposure is not inferred from field names alone.

Only CORS and source-map adapters are promotion-capable in this version, and only when Canonical Admission is satisfied. Caching and information-disclosure adaptation may strengthen, weaken, or preserve a hypothesis but cannot create a new Potential Finding through this adapter.
'''
new_block = '''## Core passive-live family coverage

Version 1.1 covers all nine `passive_live` families in the core Family Reasoning catalog:

- `cors_misconfiguration`: a controlled Origin accepted by the stored CORS policy can become `untrusted_origin_allowed`; credentialed cross-origin readability is never inferred.
- `source_map_exposure`: `source_map_publicly_reachable` is emitted only when the approved anonymous `.map` observation has source-map structure and independent stored evidence already establishes internal source structure.
- `sensitive_caching`: cache headers, sensitive response-shape markers, private/no-store controls, and user-specific `Vary` controls are typed, but shared-cache or cross-user exposure is never synthesized.
- `information_disclosure`: redacted sensitive-key/category markers enrich the hypothesis, but visibility-boundary exposure is not inferred from field names alone.
- `authentication_session`: authentication surfaces, concrete operations, and anonymous 401/403 boundaries are typed; lifecycle violations, token-rotation failures, recovery bypasses, and post-logout reuse are never inferred.
- `account_enumeration`: authentication/account surface and operation context are typed; identity lookup and response/timing differential require controlled identities and are never synthesized from one request.
- `open_redirect`: stored 3xx `Location` behavior can establish navigation/sink context; acceptance of a user-controlled external destination is never inferred.
- `secret_exposure`: redacted credential-like field/category metadata can establish `secret_pattern` and contextual evidence; credential completeness or liveness is never inferred or validated online.
- `graphql_data_exposure`: redacted sensitive-looking fields on a GraphQL endpoint can establish structural field/operation evidence; excessive exposure or field-authorization differential is never inferred without an explicit policy boundary.

Only CORS and source-map adapters remain promotion-capable in version 1.1, and only when Canonical Admission is satisfied. The other seven adapters are enrichment/contradiction-only and cannot create a new Potential Finding through this adapter.
'''
doc = require_replace(doc, old_block, new_block, "documentation coverage block")
docs.write_text(doc, encoding="utf-8")


manifest = Path("MANIFEST.sha256")
lines = manifest.read_text(encoding="utf-8").splitlines()
changed = {
    "app/typed_evidence_adapter.py",
    "tests/test_typed_evidence_adapter.py",
    "docs/TYPED_EVIDENCE_ADAPTER.md",
}
seen: set[str] = set()
out: list[str] = []
for line in lines:
    parts = line.split("  ", 1)
    if len(parts) == 2 and parts[1] in changed:
        path = parts[1]
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        out.append(f"{digest}  {path}")
        seen.add(path)
    else:
        out.append(line)
missing = changed - seen
if missing:
    raise RuntimeError(f"manifest entries missing: {sorted(missing)}")
manifest.write_text("\n".join(out) + "\n", encoding="utf-8")
