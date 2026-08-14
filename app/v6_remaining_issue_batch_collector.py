from __future__ import annotations

import argparse
import base64
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from raw_recon_corpus import ROOT

MANIFEST = ROOT / "benchmarks/raw/sources/v6_remaining_capture_manifest.json"


def get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "analysis-631-source-capture"})
    with urllib.request.urlopen(req, timeout=45) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected object from {url}")
    return value


def get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "analysis-631-source-capture"})
    with urllib.request.urlopen(req, timeout=45) as response:
        return response.read().decode("utf-8")


def condition_for(family: str) -> str:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for row in data.get("families", []):
        if row.get("family") == family:
            signals = [str(v) for v in row.get("condition_signals", []) if str(v)]
            if not signals:
                raise RuntimeError(f"{family}: missing sealed condition vocabulary")
            return signals[0]
    raise RuntimeError(f"{family}: not present in remaining manifest")


def emit(out: Path, family: str, kind: str, *, reference: str, payload: dict[str, Any], raw: dict[str, Any], notes: str, signals: list[str], basis: str = "source_observation", source_file: str = "upstream source") -> None:
    captured = datetime.now(timezone.utc).isoformat()
    doc = {
        "family": family,
        "case_kind": kind,
        "captured_at": captured,
        "capture_reference": reference,
        "capture_method": "repository_test_fixture" if source_file != "GitHub issue" else "cli_output",
        "collector": {"tool": "github-actions/source-grounded-issue-batch", "command": "fetch upstream issue and/or current upstream source", "source_file": source_file},
        "source_snapshot": {"reference": reference, "retrieved_at": captured, "payload": payload},
        "adjudication": {"basis": basis, "notes": notes, "expected_condition_signals": signals, "detector_output_used": False, "admission_output_used": False, "ranking_output_used": False},
        "raw": raw,
    }
    d = out / family
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{kind}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def capture_bfla(out: Path) -> None:
    family = "broken_function_authorization"; signal = condition_for(family)
    api = "https://api.github.com/repos/rivoli-ai/andy-rbac/issues/97"; ref = "https://github.com/rivoli-ai/andy-rbac/issues/97"
    issue = get_json(api); body = str(issue.get("body") or "")
    current_ref = "https://github.com/rivoli-ai/andy-rbac/blob/main/src/Andy.Rbac.Api/Controllers/PoliciesController.cs"
    current = get_text("https://raw.githubusercontent.com/rivoli-ai/andy-rbac/main/src/Andy.Rbac.Api/Controllers/PoliciesController.cs")
    markers = ["Any valid bearer token can create, update, or delete applications, roles, teams, subjects, policies, and grants.", "Program.cs:280` adds only a generic authorization requirement.", "An authenticated non-admin can rewrite the authorization system and escalate privileges."]
    for marker in markers: assert marker in body, marker
    assert "[Authorize(Policy = RbacAuthorizationPolicies.Administrator)]" in current
    emit(out,family,"positive",reference=ref,payload={"issue":97,"excerpt":markers[0]},raw={"target":"Andy RBAC management API","endpoint":"management mutations","method":"WRITE","endpoint_schema":{},"details":{"valid_bearer_token_only":True,"lower_privileged_authenticated_caller_can_mutate_management_resources":True,"function_permission_check_absent":True}},notes="The upstream audit records authenticated non-admin access to privileged management mutations because only generic authentication was enforced.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"near_miss",reference=ref,payload={"issue":97,"excerpt":markers[1]},raw={"target":"Andy RBAC generic authentication layer","endpoint":"Program.cs authorization requirement","method":"UNKNOWN","endpoint_schema":{},"details":{"generic_authentication_required":True,"privileged_function_policy_observed":False}},notes="Generic authentication is a real adjacent control, but it does not establish function-level privilege enforcement.",signals=[],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=current_ref,payload={"path":"PoliciesController.cs","administrator_policy_occurrences":current.count("RbacAuthorizationPolicies.Administrator")},raw={"target":"Andy RBAC current policy mutations","endpoint":"PoliciesController mutations","method":"WRITE","endpoint_schema":{},"details":{"administrator_policy_on_create":True,"administrator_policy_on_update":True,"administrator_policy_on_delete":True}},notes="Current upstream source applies the Administrator authorization policy to create, update, and delete policy operations, providing an implemented privileged-function control.",signals=[],basis="patched_control",source_file="current PoliciesController.cs")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":97,"related":[51,48]},raw={"target":"Andy RBAC related security inventory","endpoint":"related issue references","method":"UNKNOWN","endpoint_schema":{},"details":{"related_web_ui_auth_issue":51,"related_enumeration_issue":48,"management_request_outcome_present":False}},notes="Related issue references are source-grounded context but contain no privileged-operation outcome and are intentionally sparse.",signals=[],source_file="GitHub issue")


def capture_cors(out: Path) -> None:
    family="cors_misconfiguration"; signal=condition_for(family); api="https://api.github.com/repos/forkwright/harmonia/issues/710"; ref="https://github.com/forkwright/harmonia/issues/710"
    issue=get_json(api); body=str(issue.get("body") or "")
    markers=["CorsLayer::permissive()` allows any origin, any method, and any header.", "authentication surface is included rather than exempted.", "`permissive()` is the correct default while a frontend is being developed against a moving API", "`CorsLayer::permissive()` and `allow_credentials(true)` are\nmutually exclusive in `tower_http` by design — the wildcard origin is rejected with credentials"]
    for m in markers: assert m in body, m
    emit(out,family,"positive",reference=ref,payload={"issue":710,"excerpt":markers[0]+" "+markers[1]},raw={"target":"harmonia router","endpoint":"/api/auth/*","method":"CROSS_ORIGIN","endpoint_schema":{},"details":{"wildcard_origin_policy":True,"authentication_routes_under_same_policy":True,"cross_origin_auth_response_surface":True}},notes="The upstream source records a wildcard cross-origin policy applied at router scope that includes live authentication endpoints.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"near_miss",reference=ref,payload={"issue":710,"excerpt":markers[2]},raw={"target":"harmonia development CORS context","endpoint":"moving frontend API","method":"CROSS_ORIGIN","endpoint_schema":{},"details":{"permissive_policy_can_be_intended_for_development":True,"sensitive_authenticated_response_not_established_by_this_observation":True}},notes="The issue explicitly distinguishes permissive development CORS as a legitimate adjacent context; wildcard policy alone is therefore not sufficient.",signals=[],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=ref,payload={"issue":710,"excerpt":markers[3]},raw={"target":"tower_http credentialed wildcard guard noted by harmonia audit","endpoint":"credentialed CORS invariant","method":"CROSS_ORIGIN","endpoint_schema":{},"details":{"wildcard_origin_with_credentials_rejected_by_framework":True,"credentialed_cross_origin_read_not_permitted_under_that_combination":True}},notes="The same upstream audit records an implemented framework invariant: credentialed CORS cannot be combined with the permissive wildcard origin, so that combination is rejected rather than exposed.",signals=[],basis="upstream_secure_control",source_file="GitHub issue")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":710,"excerpt":"integration tests post to /api/auth/login and /api/auth/refresh"},raw={"target":"harmonia auth route inventory","endpoint":"/api/auth/login /api/auth/refresh","method":"POST","endpoint_schema":{},"details":{"live_auth_routes_recorded":True,"cross_origin_response_headers_not_present_in_this_observation":True}},notes="Live authentication-route evidence establishes a sensitive surface but does not itself show the cross-origin response policy.",signals=[],source_file="GitHub issue")


def capture_graphql_data(out: Path) -> None:
    family="graphql_data_exposure"; signal=condition_for(family); api="https://api.github.com/repos/ryjen/eyespie/issues/122"; ref="https://github.com/ryjen/eyespie/issues/122"
    issue=get_json(api); body=str(issue.get("body") or "")
    required=["current RLS permits **all authenticated users to SELECT all Thing rows**", "`thingsnearby` returns `SETOF Thing`", "`match_things` returns `to_jsonb(t.*)`", "does **not** request exact Thing location or embedding", "creates a **365-day signed URL**"]
    for m in required: assert m in body, m
    emit(out,family,"positive",reference=ref,payload={"issue":122,"excerpts":required[:3]},raw={"target":"EyeSpie Thing authority data","endpoint":"GraphQL/RPC Thing projections","method":"QUERY","endpoint_schema":{},"details":{"authenticated_users_can_select_full_rows":True,"nearby_returns_full_thing":True,"match_serializes_full_row":True,"sensitive_authority_fields_cross_client_boundary":True}},notes="The upstream issue records multiple query paths returning full Thing authority state to broadly authenticated callers rather than a field-minimized projection.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=ref,payload={"issue":122,"excerpt":required[3]},raw={"target":"EyeSpie current GameNode client projection","endpoint":"GameNode GraphQL query","method":"QUERY","endpoint_schema":{},"details":{"exact_location_requested":False,"embedding_requested":False,"narrow_gameplay_projection_observed":True}},notes="The issue independently records a current GraphQL query that already omits exact location and embedding, demonstrating a real narrower field projection.",signals=[],basis="source_secure_control",source_file="GitHub issue")
    emit(out,family,"near_miss",reference=ref,payload={"issue":122,"excerpt":required[4]},raw={"target":"EyeSpie signed image capability","endpoint":"Thing.image_url","method":"UNKNOWN","endpoint_schema":{},"details":{"long_lived_signed_url_persisted":True,"graphql_field_policy_outcome_not_established_by_this_observation":True}},notes="Long-lived signed image capability is sensitive adjacent exposure, but by itself does not establish excessive GraphQL field projection and is retained as a near-miss.",signals=[],source_file="GitHub issue")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":122,"blocks":[18,90],"refs":[92,94,126]},raw={"target":"EyeSpie privacy issue linkage","endpoint":"tracker relationships","method":"UNKNOWN","endpoint_schema":{},"details":{"privacy_tracker_links_present":True,"response_payload_not_present":True}},notes="Tracker linkage is source-grounded privacy context without a response payload and is intentionally sparse.",signals=[],source_file="GitHub issue")


def capture_mass_assignment(out: Path) -> None:
    family="mass_assignment"; signal=condition_for(family); api="https://api.github.com/repos/frankbria/narrative-modeling-app/issues/451"; ref="https://github.com/frankbria/narrative-modeling-app/issues/451"
    issue=get_json(api); body=str(issue.get("body") or "")
    current_ref="https://github.com/frankbria/narrative-modeling-app/blob/main/apps/backend/app/api/routes/user_data.py"; current=get_text("https://raw.githubusercontent.com/frankbria/narrative-modeling-app/main/apps/backend/app/api/routes/user_data.py")
    required=["accepts a client-supplied `s3_url` and persists it onto the `UserData` document", "PUT /api/v1/user_data/{id}` mass-assigns the same field", "request model exposes a field that is server-authoritative"]
    for m in required: assert m in body, m
    assert "updated.user_id = user_id  # ensure this isn't overwritten" in current
    emit(out,family,"positive",reference=ref,payload={"issue":451,"excerpts":required},raw={"target":"Narrative Modeling user_data API","endpoint":"POST/PUT /api/v1/user_data","method":"WRITE","endpoint_schema":{},"details":{"client_supplied_server_authoritative_s3_url_accepted":True,"property_persisted":True,"downstream_storage_fetch_uses_property":True}},notes="The upstream finding records a server-authoritative storage property exposed on the writable request model and persisted from client input.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=current_ref,payload={"path":"user_data.py","excerpt":"updated.user_id = user_id  # ensure this isn't overwritten"},raw={"target":"Narrative Modeling user_data ownership property","endpoint":"PUT /api/v1/user_data/{id}","method":"PUT","endpoint_schema":{},"details":{"client_user_id_overwritten_server_side":True,"authenticated_user_id_authoritative":True}},notes="Current upstream code independently protects another privileged property by overwriting user_id from the authenticated context, demonstrating a server-authoritative field control.",signals=[],basis="source_secure_control",source_file="current user_data.py")
    emit(out,family,"near_miss",reference=current_ref,payload={"path":"user_data.py","excerpt":"if doc.user_id != user_id: ... 403"},raw={"target":"Narrative Modeling object ownership check","endpoint":"GET/PUT /api/v1/user_data/{id}","method":"GET","endpoint_schema":{},"details":{"object_owner_check_present":True,"property_write_allowlist_not_established_by_this_observation":True}},notes="Object-level ownership is a real adjacent authorization control, but does not by itself prevent writable server-authoritative properties.",signals=[],source_file="current user_data.py")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":451,"excerpt":"get_file_from_s3 has no bucket allowlist"},raw={"target":"Narrative Modeling storage fetch boundary","endpoint":"get_file_from_s3","method":"SERVER_GET","endpoint_schema":{},"details":{"bucket_allowlist_absent_reported":True,"request_property_acceptance_outcome_not_present":True}},notes="The unallowlisted downstream storage fetch expands impact but is not itself a mass-assignment observation, so it is intentionally sparse/noisy for this family.",signals=[],source_file="GitHub issue")


def capture_nosql(out: Path) -> None:
    family="nosql_injection"; signal=condition_for(family); api="https://api.github.com/repos/pathosDev/actor-ts/issues/738"; ref="https://github.com/pathosDev/actor-ts/issues/738"
    issue=get_json(api); body=str(issue.get("body") or "")
    required=["MongoQuery` embeds the tag value as a filter value", "MongoDB interprets an object in that position as an operator expression", "SqliteQuery.ts:81 `stmts.fetchByTag.all(allTags[0]!, fromOffset.timestamp)`", "CassandraQuery.ts:98-103 `client.execute('... WHERE tag = ? AND timestamp >= ?', [tag, fromTimestamp], ...)`", "eventMatchesTagFilter(tags, spec)", "assertValidTags` genuinely covers the write path"]
    for m in required: assert m in body, m
    emit(out,family,"positive",reference=ref,payload={"issue":738,"excerpts":required[:2]},raw={"target":"actor-ts MongoQuery","endpoint":"currentEventsByTag Mongo filter","method":"QUERY","endpoint_schema":{},"details":{"caller_value_embedded_in_query_document":True,"non_string_value_becomes_operator_expression":True,"server_query_semantics_influenced":True}},notes="The upstream audit and verifier record caller-controlled structured values entering the Mongo query document as operator expressions.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=ref,payload={"issue":738,"excerpts":required[2:4]},raw={"target":"actor-ts indexed sibling query backends","endpoint":"SqliteQuery/CassandraQuery tag query","method":"QUERY","endpoint_schema":{},"details":{"sqlite_parameter_binding":True,"cassandra_prepared_binding":True,"non_string_operator_document_not_interpreted_as_mongo_operator":True}},notes="The same verified source records SQLite and Cassandra sibling implementations using parameter/prepared binding, providing independent secure query-construction controls.",signals=[],basis="source_secure_control",source_file="GitHub issue")
    emit(out,family,"near_miss",reference=ref,payload={"issue":738,"excerpt":"JS refinement drops all-branch object matches"},raw={"target":"actor-ts post-query JS refinement","endpoint":"eventMatchesTagFilter","method":"QUERY","endpoint_schema":{},"details":{"post_query_refinement_present":True,"cross_tenant_disclosure_neutralized":True,"server_side_scan_still_possible":True}},notes="The source explicitly verifies a post-query refinement that prevents the stronger data-disclosure outcome while leaving server-side scan impact; this is a genuine near-miss/confounder.",signals=[],source_file="GitHub issue")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":738,"excerpt":required[5]},raw={"target":"actor-ts write-side tag validation","endpoint":"journal append","method":"WRITE","endpoint_schema":{},"details":{"write_side_tag_validation_present":True,"read_side_query_outcome_not_present":True}},notes="Write-side validation is a real adjacent control but does not cover read-side Mongo query construction, so it is intentionally sparse for the target condition.",signals=[],source_file="GitHub issue")


def capture_postmessage(out: Path) -> None:
    family="postmessage_trust"; signal=condition_for(family); api="https://api.github.com/repos/auth0/auth0.js/issues/508"; ref="https://github.com/auth0/auth0.js/issues/508"
    issue=get_json(api); body=str(issue.get("body") or "")
    current_ref="https://github.com/auth0/auth0.js/blob/master/src/web-auth/silent-authentication-handler.js"; current=get_text("https://raw.githubusercontent.com/auth0/auth0.js/master/src/web-auth/silent-authentication-handler.js")
    required=["not confirming", "origin is correct for the message", "no check that the message is from the correct iFrame", "There is no validation of the message content"]
    for m in required: assert m in body, m
    assert "eventData.event.origin !== _this.postMessageOrigin" in current
    assert "eventData.event.source !== _this.handler.iframe.contentWindow" in current
    assert "eventData.event.data.type === _this.postMessageDataType" in current
    emit(out,family,"positive",reference=ref,payload={"issue":508,"version":"auth0-js@8.10.0","observed_gaps":required[1:]},raw={"target":"auth0-js silent authentication message handler","endpoint":"renewAuth usePostMessage","method":"MESSAGE","endpoint_schema":{},"details":{"origin_validation_missing":True,"source_iframe_validation_missing":True,"message_content_validation_missing":True,"unrelated_iframe_message_reached_handler":True}},notes="The upstream issue records silent-authentication messages accepted without origin, source-window, or content validation, including interference from an unrelated iframe.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=current_ref,payload={"path":"silent-authentication-handler.js","origin_check":True,"source_window_check":True,"message_type_check":True},raw={"target":"auth0-js current silent authentication handler","endpoint":"getEventValidator.isValid","method":"MESSAGE","endpoint_schema":{},"details":{"expected_origin_checked":True,"expected_iframe_window_checked":True,"configured_message_type_checked":True}},notes="Current upstream source rejects messages from the wrong origin or iframe and optionally enforces the configured message type, providing implemented sender/message validation.",signals=[],basis="patched_control",source_file="current silent-authentication-handler.js")
    emit(out,family,"near_miss",reference=ref,payload={"issue":508,"excerpt":"same origin two iframes can respond in reversed order"},raw={"target":"auth0-js same-origin iframe interference test","endpoint":"message event ordering","method":"MESSAGE","endpoint_schema":{},"details":{"same_origin_messages_possible":True,"source_window_identity_is_decisive":True,"malicious_origin_not_required":True}},notes="The issue describes same-origin competing iframes as a confounder: origin alone can be correct while source-window identity is wrong.",signals=[],source_file="GitHub issue")
    emit(out,family,"sparse_noisy",reference=ref,payload={"issue":508,"excerpt":"message content validation described as possibly paranoid"},raw={"target":"auth0-js historical message schema concern","endpoint":"authResult callback","method":"MESSAGE","endpoint_schema":{},"details":{"content_validation_concern_recorded":True,"sensitive_action_outcome_not_recorded":True}},notes="The historical content-validation concern is source-grounded but was explicitly uncertain and contains no sensitive action outcome, so it is sparse/noisy.",signals=[],source_file="GitHub issue")


def capture_websocket(out: Path) -> None:
    family="websocket_authorization"; signal=condition_for(family); api="https://api.github.com/repos/bazauto/layout-orchestration/issues/20"; ref="https://github.com/bazauto/layout-orchestration/issues/20"
    issue=get_json(api); body=str(issue.get("body") or "")
    docs_ref="https://github.com/bazauto/layout-orchestration/blob/main/docs/auth.md"; docs=get_text("https://raw.githubusercontent.com/bazauto/layout-orchestration/main/docs/auth.md")
    required=["The throttle and point WebSocket control channel is already unauthenticated, and already commands hardware.", "WebSocket upgrade rejects unauthenticated connections"]
    for m in required: assert m in body, m
    assert "reject an unauthenticated upgrade before the socket ever completes" in docs
    assert "one Fastify `onRequest` hook" in docs and "REST" in docs and "`/ws` upgrade" in docs
    emit(out,family,"positive",reference=ref,payload={"issue":20,"excerpt":required[0]},raw={"target":"layout-orchestration realtime control channel","endpoint":"/ws","method":"WEBSOCKET","endpoint_schema":{},"details":{"websocket_control_channel_unauthenticated":True,"hardware_commands_available":True,"identity_scope_enforcement_absent":True}},notes="The upstream security review records an unauthenticated WebSocket channel already capable of issuing hardware control commands.",signals=[signal],source_file="GitHub issue")
    emit(out,family,"secure_negative",reference=docs_ref,payload={"path":"docs/auth.md","excerpt":"shared onRequest hook rejects unauthenticated /ws upgrade"},raw={"target":"layout-orchestration current authentication edge","endpoint":"/ws upgrade","method":"WEBSOCKET","endpoint_schema":{},"details":{"session_cookie_required_on_upgrade":True,"shared_on_request_auth_hook_covers_websocket":True,"unauthenticated_upgrade_rejected_before_protocol_switch":True}},notes="Current upstream authentication design records and implements the shared request hook covering `/ws`, rejecting unauthenticated upgrade requests before protocol switch.",signals=[],basis="patched_control",source_file="current docs/auth.md implementation record")
    emit(out,family,"near_miss",reference=docs_ref,payload={"path":"docs/auth.md","excerpt":"POST /api/emergency-stop stays unauthenticated deliberately"},raw={"target":"layout-orchestration emergency fail-safe path","endpoint":"POST /api/emergency-stop","method":"POST","endpoint_schema":{},"details":{"unauthenticated_http_endpoint":True,"failsafe_direction_only":True,"websocket_subscription_or_command_scope":False}},notes="An intentionally unauthenticated fail-safe HTTP endpoint is adjacent to control authorization but is not a WebSocket authorization failure and is retained as a near-miss.",signals=[],source_file="current docs/auth.md")
    emit(out,family,"sparse_noisy",reference=docs_ref,payload={"path":"docs/auth.md","excerpt":"Playwright mocks WebSocket and auth; integration tests perform real login"},raw={"target":"layout-orchestration test transport","endpoint":"mock websocket/auth test paths","method":"WEBSOCKET","endpoint_schema":{},"details":{"test_mock_transport_present":True,"production_websocket_authorization_outcome_not_present":True}},notes="Test-mode mock transport is independently documented but does not establish a production authorization outcome, so it is intentionally sparse.",signals=[],source_file="current docs/auth.md")


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("output",type=Path); args=parser.parse_args(); out=args.output
    for fn in (capture_bfla,capture_cors,capture_graphql_data,capture_mass_assignment,capture_nosql,capture_postmessage,capture_websocket): fn(out)
    print(json.dumps({"captured_families":7,"captured_evidence":28,"scoring_executed":False,"first_blind_consumed":False},sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
