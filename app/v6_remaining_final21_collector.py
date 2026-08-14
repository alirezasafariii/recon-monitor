from __future__ import annotations

import argparse
import base64
import html
import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_RESEARCH = ROOT / "benchmarks/raw/sources/v6_literal_source_research.json"
SIGNALS = ROOT / "benchmarks/raw/sources/v6_remaining_signal_index.json"
REMAINING = {
    "authentication_session","broken_function_authorization","cors_misconfiguration",
    "dom_xss","file_upload","graphql_data_exposure","improper_inventory_management",
    "ldap_injection","mass_assignment","nosql_injection","open_redirect","postmessage_trust",
    "race_condition","secret_exposure","security_logging_alerting_failure",
    "security_misconfiguration","server_side_template_injection","sql_injection",
    "unrestricted_resource_consumption","unsafe_api_consumption","websocket_authorization",
}
VARIANTS = {"positive","near_miss","secure_negative","sparse_noisy"}
UA = "analysis-631-final21-source-capture/1.0"

@dataclass(frozen=True)
class Source:
    reference: str
    text: str
    source_file: str
    method: str = "cli_output"

def _request(url: str) -> bytes:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json,text/html;q=0.9,*/*;q=0.8",
        "User-Agent": UA,
    })
    with urllib.request.urlopen(req, timeout=45) as response:
        return response.read()

def _strip_html(value: str) -> str:
    value = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", value)
    value = re.sub(r"(?s)<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()

def external(url: str) -> Source:
    raw = _request(url).decode("utf-8", errors="replace")
    text = _strip_html(raw) if "<html" in raw[:2000].lower() or "<!doctype" in raw[:2000].lower() else raw
    if len(text) < 80:
        raise RuntimeError(f"external source too small: {url}")
    return Source(url, text, url, "cli_output")

def github_file(repo: str, path: str, ref: str | None = None) -> Source:
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    if ref:
        url += f"?ref={ref}"
    data = json.loads(_request(url))
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        raise RuntimeError(f"unexpected GitHub contents response for {repo}/{path}")
    text = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return Source(str(data.get("html_url") or f"https://github.com/{repo}/blob/HEAD/{path}"),
                  text, path, "repository_test_fixture")

def github_issue(repo: str, number: int) -> Source:
    url = f"https://api.github.com/repos/{repo}/issues/{number}"
    data = json.loads(_request(url))
    body = str(data.get("body") or "")
    if not body:
        raise RuntimeError(f"empty issue body: {repo}#{number}")
    return Source(str(data.get("html_url") or f"https://github.com/{repo}/issues/{number}"),
                  body, f"GitHub issue #{number}", "cli_output")

def _flatten(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float, bool)):
        return [str(value)]
    if isinstance(value, dict):
        out: list[str] = []
        for key, child in value.items():
            out.append(str(key))
            out.extend(_flatten(child))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for child in value:
            out.extend(_flatten(child))
        return out
    return []

def canonical_sources() -> dict[str, Source]:
    doc = json.loads(SOURCE_RESEARCH.read_text(encoding="utf-8"))
    out: dict[str, Source] = {}
    for entry in doc.get("entries") or []:
        family = str(entry.get("family") or "")
        if family not in REMAINING:
            continue
        payload = entry.get("snapshot_payload") if isinstance(entry.get("snapshot_payload"), dict) else {}
        text = "\n".join(_flatten(payload))
        out[family] = Source(
            str(entry.get("canonical_reference") or ""),
            text,
            "benchmarks/raw/sources/v6_literal_source_research.json",
            "cli_output",
        )
    missing = REMAINING - set(out)
    if missing:
        raise RuntimeError(f"missing canonical snapshots: {sorted(missing)}")
    return out

def condition_signals() -> dict[str, str]:
    doc = json.loads(SIGNALS.read_text(encoding="utf-8"))
    families = doc.get("families") if isinstance(doc.get("families"), dict) else {}
    out: dict[str, str] = {}
    for family in REMAINING:
        row = families.get(family) if isinstance(families.get(family), dict) else {}
        vals = [str(v) for v in row.get("condition_signals") or [] if str(v)]
        if not vals:
            raise RuntimeError(f"missing condition signal: {family}")
        out[family] = vals[0]
    return out

def excerpt(source: Source, needle: str, width: int = 800) -> str:
    pos = source.text.casefold().find(needle.casefold())
    if pos < 0:
        raise RuntimeError(f"marker not found in {source.reference}: {needle!r}")
    start = max(0, pos - 120)
    end = min(len(source.text), pos + len(needle) + width)
    return re.sub(r"\s+", " ", source.text[start:end]).strip()

def require(source: Source, *needles: str) -> None:
    missing = [n for n in needles if n.casefold() not in source.text.casefold()]
    if missing:
        raise RuntimeError(f"missing markers in {source.reference}: {missing}")

def observation(target: str, endpoint: str, points: list[Any], method: str = "UNKNOWN") -> dict[str, Any]:
    # Generic keys prevent pre-score family/condition identifiers leaking into raw benchmark data.
    return {
        "target": target,
        "endpoint": endpoint,
        "method": method,
        "endpoint_schema": {},
        "details": {"evidence-points": points},
    }

def emit(out: Path, signals: dict[str, str], family: str, kind: str, source: Source,
         needle: str, target: str, endpoint: str, points: list[Any], notes: str,
         basis: str = "source_observation") -> None:
    captured = datetime.now(timezone.utc).isoformat()
    payload = {
        "family": family,
        "case_kind": kind,
        "captured_at": captured,
        "capture_reference": source.reference,
        "capture_method": source.method,
        "collector": {
            "tool": "analysis-631-final21-source-grounded-collector",
            "command": "read sealed passive snapshot and/or fetch upstream source control",
            "source_file": source.source_file,
        },
        "source_snapshot": {
            "reference": source.reference,
            "retrieved_at": captured,
            "payload": {"excerpt": excerpt(source, needle)},
        },
        "adjudication": {
            "basis": basis,
            "notes": notes,
            "expected_condition_signals": [signals[family]] if kind == "positive" else [],
            "detector_output_used": False,
            "admission_output_used": False,
            "ranking_output_used": False,
        },
        "raw": observation(target, endpoint, points),
    }
    d = out / family
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{kind}.json").write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                    encoding="utf-8")

def collect(out: Path) -> dict[str, Any]:
    c = canonical_sources()
    sig = condition_signals()

    # authentication/session boundary
    s = c["authentication_session"]; require(s, "NTLM session negotiation", "CWE-287", "AV:N/AC:H")
    emit(out,sig,"authentication_session","positive",s,"NTLM session negotiation","IBM i network authentication","session negotiation",
         ["remote client", "authenticated-user privilege context can be reached", "authentication check is improper"],
         "The sealed advisory records a remote client obtaining server-resource access with an authenticated user's privileges because NTLM negotiation is improperly authenticated.")
    emit(out,sig,"authentication_session","near_miss",s,"AV:N/AC:H","IBM i network authentication","negotiation prerequisite",
         ["network reachable", "high attack complexity", "no privilege-bearing session result in this observation"],
         "The advisory independently records high attack complexity; reachability plus a hard timing/negotiation path is not the privilege-bearing session outcome.")
    emit(out,sig,"authentication_session","sparse_noisy",s,"IBM i 7.6","IBM i release inventory","affected release metadata",
         ["release lines 7.6, 7.5, 7.4 and 7.3", "no network exchange in this observation"],
         "Affected-release metadata is source-grounded but contains no authentication exchange.")
    ibm_i = external("https://www.ibm.com/support/pages/node/7283573"); require(ibm_i, "Remediation/Fixes")
    emit(out,sig,"authentication_session","secure_negative",ibm_i,"Remediation/Fixes","IBM i fixed release state","vendor remediation",
         ["vendor remediation section exists", "fixed product levels are published", "vulnerable negotiation state is not the fixed expectation"],
         "The vendor bulletin publishes remediation/fixed levels, providing a concrete fixed-state control.", "patched_control")

    # broken function authorization
    s = c["broken_function_authorization"]; require(s, "Any valid bearer token can create", "authenticated non-admin")
    cur = github_file("rivoli-ai/andy-rbac","src/Andy.Rbac.Api/Controllers/PoliciesController.cs")
    require(cur,"RbacAuthorizationPolicies.Administrator","HttpPost","HttpGet")
    emit(out,sig,"broken_function_authorization","positive",s,"Any valid bearer token can create","RBAC management API","management mutation",
         ["valid bearer token", "caller is not an administrator", "privileged mutation was reachable"],
         "The upstream audit records authenticated non-admin callers reaching privileged management mutations under generic authorization.")
    emit(out,sig,"broken_function_authorization","near_miss",cur,"Read paths are open to any","RBAC policy catalog","read-only catalog operation",
         ["authenticated caller", "read operation only", "no policy mutation"],
         "Current source intentionally permits authenticated reads; that is adjacent to, but distinct from, privileged management mutation.", "repository_test_fixture")
    emit(out,sig,"broken_function_authorization","secure_negative",cur,"RbacAuthorizationPolicies.Administrator","RBAC management API","protected mutation",
         ["administrator policy is attached", "generic bearer authentication alone is insufficient"],
         "Current source applies the Administrator policy to mutation endpoints, providing a concrete patched role-boundary control.", "patched_control")
    emit(out,sig,"broken_function_authorization","sparse_noisy",s,"Program.cs:280","RBAC audit inventory","controller evidence locations",
         ["controller locations recorded", "generic authorization location recorded", "no request result"],
         "The audit's source-location inventory is real evidence context but contains no request outcome.")

    # CORS
    s = c["cors_misconfiguration"]; require(s,"CorsLayer::permissive()","/api/auth","allows any origin")
    cur = github_file("forkwright/harmonia","crates/paroche/src/lib.rs"); require(cur,'"/api/system/health"', "CorsLayer::permissive()")
    emit(out,sig,"cors_misconfiguration","positive",s,"allows any origin","Harmonia browser API","authentication routes",
         ["router-wide permissive cross-origin policy", "login and refresh routes share that router", "sensitive authentication surface is browser reachable"],
         "The source ties a router-wide permissive cross-origin policy directly to login and token-refresh routes.")
    emit(out,sig,"cors_misconfiguration","near_miss",s,"severity depends on how the resulting session is carried","Harmonia browser API","credential transport precondition",
         ["permissive policy exists", "session transport mode changes exploitability", "no sensitive response proven by this observation alone"],
         "The finding explicitly distinguishes cookie and bearer-token transport; policy presence alone does not prove sensitive response exposure.")
    emit(out,sig,"cors_misconfiguration","secure_negative",cur,"/api/system/health","Harmonia public route","health response",
         ["same broad cross-origin layer", "health endpoint response", "no authentication secret response"],
         "The same router contains a public health response; cross-origin accessibility of a deliberately non-sensitive response is a negative control for the target condition.", "repository_test_fixture")
    emit(out,sig,"cors_misconfiguration","sparse_noisy",cur,"CorsLayer::permissive()","Harmonia router composition","middleware inventory",
         ["middleware call present", "no browser request or response transcript"],
         "The middleware call is source-grounded but contains no browser exchange.", "repository_test_fixture")

    # DOM XSS
    s = c["dom_xss"]; require(s,"j&#x61;vascript","v-html","v1.0.4-beta.1")
    cur = github_file("ThinkInAIXYZ/deepchat","src/main/lib/svgSanitizer.ts","dev")
    require(cur,"decodeHtmlEntities","normalizeUrlProtocol","startsWith('javascript:')")
    emit(out,sig,"dom_xss","positive",s,"j&#x61;vascript","DeepChat SVG renderer","rendered SVG link",
         ["entity-obfuscated script scheme survived old text filter", "browser decoded the attribute", "script execution was observed after interaction"],
         "The published PoC records entity-obfuscated script text passing the old sanitizer and executing after browser decoding.")
    emit(out,sig,"dom_xss","near_miss",s,"regex matches literal characters precisely","DeepChat SVG sanitizer","literal protocol filter",
         ["literal dangerous scheme is matched", "entity obfuscation not used", "bypass not demonstrated"],
         "The old regex catches the literal spelling; that partial control does not reproduce the entity-decoding bypass.")
    emit(out,sig,"dom_xss","secure_negative",cur,"decodeHtmlEntities","DeepChat current SVG sanitizer","URL normalization",
         ["HTML entities decoded before protocol decision", "control characters removed", "dangerous scheme rejected"],
         "Current source decodes browser-style entities and normalizes URL text before rejecting dangerous schemes.", "patched_control")
    emit(out,sig,"dom_xss","sparse_noisy",s,"v1.0.4-beta.1","DeepChat advisory inventory","patched release metadata",
         ["patched release recorded", "no browser event trace"],
         "Patch metadata is source-grounded but contains no runtime DOM event.")

    # file upload
    s = c["file_upload"]; require(s,"unrestricted file upload","empty upload extension filter","auth_pass")
    cur = github_file("dulldusk/phpfm","index.php"); require(cur,"$upload_ext_filter = array();","foreach($upload_ext_filter","$is_denied = true")
    emit(out,sig,"file_upload","positive",s,"unrestricted file upload","phpFileManager","upload path",
         ["authentication defaults empty", "extension deny list defaults empty", "server-executable upload can be placed and requested"],
         "The advisory records an unauthenticated dangerous upload path created by empty authentication and extension-filter defaults.")
    emit(out,sig,"file_upload","near_miss",cur,"$upload_ext_filter = array();","phpFileManager","upload configuration",
         ["deny-filter mechanism exists", "configured rule count is zero", "no blocked upload result"],
         "A filter mechanism exists but ships with no rules; mechanism presence alone is not a blocked dangerous upload.", "repository_test_fixture")
    emit(out,sig,"file_upload","secure_negative",cur,"$is_denied = true","phpFileManager","configured extension deny branch",
         ["filename matches a configured deny rule", "deny branch selected", "write is not permitted on that branch"],
         "Repository code contains a concrete deny branch for configured extensions, providing a source-level blocked-upload control.", "repository_test_fixture")
    emit(out,sig,"file_upload","sparse_noisy",cur,"$version = '1.8.0'","phpFileManager","release and default metadata",
         ["release 1.8.0", "default extension list empty", "no upload exchange"],
         "Version/default configuration is real source metadata without an upload exchange.", "repository_test_fixture")

    # GraphQL/data exposure
    s = c["graphql_data_exposure"]; require(s,"all authenticated users to SELECT all Thing rows","thingsnearby","to_jsonb(t.*)","GameNode")
    emit(out,sig,"graphql_data_exposure","positive",s,"all authenticated users to SELECT all Thing rows","Eyespie data API","broad authority read",
         ["all authenticated accounts can read authority rows", "full-row RPCs exist", "precise location and embedding share the authority row"],
         "The source records broad authenticated visibility and full-row RPCs carrying sensitive authority state.")
    emit(out,sig,"graphql_data_exposure","near_miss",s,"GraphQL field selection is not authorization","Eyespie GraphQL client","field selection",
         ["client asks for fewer fields", "backend authority remains broad", "authorization boundary is unchanged"],
         "The source explicitly warns that a narrow field selection is not an authorization control.")
    emit(out,sig,"graphql_data_exposure","secure_negative",s,"does not request exact Thing location or embedding","Eyespie gameplay query","narrow projection",
         ["exact location omitted", "embedding omitted", "only gameplay projection fields requested"],
         "The existing gameplay query is a source-grounded response-shape control where exact location and embedding are absent.")
    emit(out,sig,"graphql_data_exposure","sparse_noisy",s,"365-day signed URL","Eyespie authority model","storage metadata",
         ["long-lived image capability persisted", "location and embedding co-resident", "no query response in this observation"],
         "Persisted authority-state inventory is relevant context but contains no observed query result.")

    # inventory management
    inv = external("https://www.binarysecurity.no/posts/2024/11/apim-privesc")
    require(inv,"old versions of the ARM API","returning an empty response to readers","legacy APIs are also enabled by default")
    emit(out,sig,"improper_inventory_management","positive",inv,"old versions of the ARM API","Azure API Management","legacy management API version",
         ["Reader-level caller", "older management API selected", "older path exposes secrets or privileged operation"],
         "The write-up records Reader-level callers using older ARM versions to reach data/capabilities that newer paths restricted.")
    emit(out,sig,"improper_inventory_management","near_miss",inv,"If the toggle is off","Azure API Management","legacy credential prerequisite",
         ["legacy credential recovered", "direct management toggle disabled", "credential cannot be used on that branch"],
         "The source states one recovered credential path is unusable when the management REST toggle is off.")
    emit(out,sig,"improper_inventory_management","secure_negative",inv,"returning an empty response to readers","Azure API Management","patched legacy call",
         ["Reader caller", "old call returns no sensitive result", "empty response after vendor fix"],
         "The researcher records a vendor change where the legacy SSO-token call returns an empty response to Reader users.", "patched_control")
    emit(out,sig,"improper_inventory_management","sparse_noisy",inv,"legacy APIs are also enabled by default","Azure API Management","legacy-version policy inventory",
         ["legacy APIs enabled by default", "no management-operation response in this observation"],
         "Default legacy-version configuration is source-grounded inventory data, not an exploit result by itself.")

    # LDAP
    ldap = github_file("Tanguy-Boisset/CVE","CVE-2024-54852/README.md","master")
    require(ldap,"not** enabled by default","Unrestricted account creation","Versions between 1.9 and 1.12")
    emit(out,sig,"ldap_injection","positive",ldap,"Unrestricted account creation","Teedy LDAP login","username filter substitution",
         ["crafted username changes filter shape", "known directory password used", "new internal account created"],
         "The upstream PoC records a crafted username altering the LDAP filter and causing a new internal account to be created.")
    emit(out,sig,"ldap_injection","near_miss",ldap,"attacker knows one LDAP account","Teedy LDAP login","credential prerequisite",
         ["directory feature enabled", "one valid directory account known", "no crafted-filter result in this observation"],
         "The PoC's known-account prerequisite is necessary for its example but is not itself filter manipulation.")
    emit(out,sig,"ldap_injection","secure_negative",ldap,"not** enabled by default","Teedy default configuration","LDAP feature gate",
         ["directory integration disabled", "directory filter not executed", "username cannot reach that query path"],
         "The write-up explicitly states LDAP is disabled by default; in that deployment state the vulnerable query path is not executed.")
    emit(out,sig,"ldap_injection","sparse_noisy",ldap,"Versions between 1.9 and 1.12","Teedy release inventory","affected versions",
         ["affected range 1.9 through 1.12", "no directory exchange"],
         "Affected-version metadata contains no LDAP request/result.")

    # mass assignment
    s = c["mass_assignment"]; require(s,"client-supplied `s3_url`","server-authoritative")
    cur = github_file("frankbria/narrative-modeling-app","apps/backend/app/api/routes/user_data.py")
    require(cur,"user_data.user_id = user_id","updated.user_id = user_id","Access denied")
    emit(out,sig,"mass_assignment","positive",s,"client-supplied `s3_url`","Narrative Modeling dataset API","create/update body",
         ["storage location is client supplied", "value is persisted on authority object", "downstream fetch uses persisted location"],
         "The issue records a server-authoritative storage location exposed on input and later consumed by preview/visualization fetches.")
    emit(out,sig,"mass_assignment","near_miss",cur,"if doc.user_id != user_id","Narrative Modeling dataset API","object ownership check",
         ["object owner compared with caller", "mismatched owner denied", "request-body property processing not tested here"],
         "The ownership check blocks a different access path; it does not prove request-body field allowlisting.", "repository_test_fixture")
    emit(out,sig,"mass_assignment","secure_negative",cur,"updated.user_id = user_id","Narrative Modeling dataset API","server-owned owner property",
         ["client owner value not retained", "owner forced to authenticated subject"],
         "Current source overwrites the owner with the authenticated subject on create/update, providing a protected-property control.", "repository_test_fixture")
    emit(out,sig,"mass_assignment","sparse_noisy",s,"server-authoritative","Narrative Modeling schema audit","authority metadata",
         ["server-owned property exposed in request model", "no mutation result in this observation"],
         "The schema/audit statement is relevant source metadata without a mutation result.")

    # NoSQL
    s = c["nosql_injection"]; require(s,"becomes a MongoDB operator","refinement drops everything","SqliteQuery","CassandraQuery")
    emit(out,sig,"nosql_injection","positive",s,"becomes a MongoDB operator","Actor TS Mongo journal","tag prefilter",
         ["non-string value enters query document", "database interprets object as query syntax", "broad unindexed traversal can be triggered"],
         "The verified audit shows a runtime object becoming Mongo query syntax and causing a broad scan/memory workload.")
    emit(out,sig,"nosql_injection","near_miss",s,"refinement drops everything","Actor TS Mongo journal","post-query refinement",
         ["database prefilter broadened", "JavaScript refinement rejects object member", "cross-tenant rows are not returned"],
         "The source explicitly refutes the stronger disclosure claim: post-query refinement drops the broadened rows.")
    emit(out,sig,"nosql_injection","secure_negative",s,"SqliteQuery.ts:81","Actor TS sibling backends","bound tag lookup",
         ["driver parameter binding used", "caller object cannot become query syntax"],
         "The same audit verifies SQLite and Cassandra sibling implementations bind tag values as driver parameters.")
    emit(out,sig,"nosql_injection","sparse_noisy",s,"six write sites, zero read sites","Actor TS validation inventory","read/write guard map",
         ["six write guard sites", "zero read guard sites", "no database result"],
         "The guard-site inventory explains the asymmetry but has no database execution result.")

    # open redirect
    red = github_file("DevVaibhav07/VULN-POC","Saurus_OpenRedirect.md","main")
    require(red,"Location: https://evil.example.com","if (!$url)","4.7.FINAL")
    emit(out,sig,"open_redirect","positive",red,"Location: https://evil.example.com","Saurus CMS logout","destination parameter",
         ["caller supplies absolute external destination", "HTTP 302 observed", "Location host changed"],
         "The reproduced logout exchange returns HTTP 302 with an attacker-controlled external Location.")
    emit(out,sig,"open_redirect","near_miss",red,"The original request is","Saurus CMS logout","ordinary logout request",
         ["no destination parameter", "logout operation present", "no external destination observed"],
         "The unmodified logout request is adjacent to the vulnerable handler but does not supply an external redirect target.")
    emit(out,sig,"open_redirect","secure_negative",red,"if (!$url)","Saurus CMS logout","missing-destination fallback",
         ["destination absent", "fallback path is local index", "absolute external destination not used"],
         "The vulnerable code itself has a safe fallback when no URL is supplied: a local index path is used.", "repository_test_fixture")
    emit(out,sig,"open_redirect","sparse_noisy",red,"4.7.FINAL","Saurus CMS inventory","affected release metadata",
         ["latest affected release recorded", "no response exchange"],
         "Affected-release metadata is real but contains no redirect behavior.")

    # postMessage trust
    s = c["postmessage_trust"]; require(s,"origin is correct","correct iFrame","validation of the message content")
    cur = github_file("auth0/auth0.js","src/web-auth/silent-authentication-handler.js","master")
    require(cur,"eventData.event.origin !== _this.postMessageOrigin","eventData.event.source !== _this.handler.iframe.contentWindow")
    emit(out,sig,"postmessage_trust","positive",s,"origin is correct","Auth0 silent authentication","window message listener",
         ["expected origin not checked", "expected iframe window not checked", "unrelated message can reach handler"],
         "The historical issue records acceptance without expected-origin or expected-iframe validation.")
    emit(out,sig,"postmessage_trust","near_miss",s,"another iframe which posts a message","Auth0 silent authentication","same-page iframe interference",
         ["message can share origin", "source is a different iframe", "origin check alone would be insufficient"],
         "The report's second-iframe case demonstrates why origin-only validation is insufficient for same-origin windows.")
    emit(out,sig,"postmessage_trust","secure_negative",cur,"eventData.event.source !== _this.handler.iframe.contentWindow","Auth0 current silent authentication","message validator",
         ["expected origin required", "exact iframe window required", "mismatch rejected"],
         "Current upstream code requires both expected origin and exact iframe contentWindow.", "patched_control")
    emit(out,sig,"postmessage_trust","sparse_noisy",cur,"postMessageDataType","Auth0 message validator","optional type configuration",
         ["optional message-type filter exists", "no message event result"],
         "Optional message-type configuration is source-grounded metadata without an observed event outcome.", "repository_test_fixture")

    # race condition
    race = external("https://security.paloaltonetworks.com/CVE-2025-0120")
    require(race,"race condition","Product Status","Unaffected")
    emit(out,sig,"race_condition","positive",race,"race condition","GlobalProtect Windows client","privileged timing window",
         ["local non-administrative user", "race timing succeeds", "SYSTEM-level privilege is reached"],
         "The vendor advisory states a local non-admin can reach SYSTEM privileges when the race is successfully exploited.")
    near_marker = "successfully exploit the race condition" if "successfully exploit the race condition".casefold() in race.text.casefold() else "local non-administrative"
    emit(out,sig,"race_condition","near_miss",race,near_marker,"GlobalProtect Windows client","race prerequisite",
         ["local low-privilege user", "special timing must succeed", "no privilege change in this observation"],
         "Local access is necessary but is not the privilege-escalation result unless the timing race also succeeds.")
    emit(out,sig,"race_condition","secure_negative",race,"Unaffected","GlobalProtect product status","unaffected platform or release",
         ["vendor marks a listed product state unaffected", "race privilege path is not expected in that state"],
         "The official product-status table provides a vendor-marked unaffected control.", "patched_control")
    emit(out,sig,"race_condition","sparse_noisy",race,"Product Status","GlobalProtect inventory","affected/fixed version table",
         ["product status table present", "no timing trace"],
         "Version applicability is source-grounded but contains no race execution trace.")

    # secret exposure
    s = c["secret_exposure"]; require(s,"hardcoded token","inter-node cluster communication","REST API authentication")
    emit(out,sig,"secret_exposure","positive",s,"hardcoded token","IBM Storage Scale GUI","embedded credential",
         ["authentication token embedded in source", "token used for service authentication", "live authentication material"],
         "The advisory records a hard-coded authentication token used for inter-node and REST authentication.")
    emit(out,sig,"secret_exposure","near_miss",s,"inter-node cluster communication","IBM Storage Scale GUI","credential scope",
         ["credential role limited to GUI inter-node/API authentication", "actual token bytes not present in this observation"],
         "Contextual credential-use metadata alone is not a literal secret-value observation.")
    emit(out,sig,"secret_exposure","sparse_noisy",s,"5.2.3.0","IBM Storage Scale inventory","affected versions",
         ["affected release ranges recorded", "credential bytes absent"],
         "Affected-version metadata contains no credential bytes.")
    storage = external("https://www.ibm.com/support/pages/node/7283308"); require(storage,"Remediation/Fixes")
    emit(out,sig,"secret_exposure","secure_negative",storage,"Remediation/Fixes","IBM Storage Scale fixed state","vendor remediation",
         ["vendor remediation section exists", "fixed product levels published", "hard-coded authentication material is not the fixed expectation"],
         "The official vendor bulletin publishes fixed product levels, providing a remediated-state control.", "patched_control")

    # security logging/alerting
    s = c["security_logging_alerting_failure"]; require(s,"logging of plain text passwords in trace files","local attacker")
    emit(out,sig,"security_logging_alerting_failure","positive",s,"logging of plain text passwords","IBM Db2 diagnostic tracing","trace file output",
         ["password material written in plaintext", "local attacker can obtain trace data"],
         "The advisory records plaintext password material written into trace files where a local attacker can obtain it.")
    emit(out,sig,"security_logging_alerting_failure","near_miss",s,"local attacker","IBM Db2 diagnostic tracing","local-access prerequisite",
         ["attacker is local", "trace access context required", "no password record in this observation"],
         "The local-access prerequisite is relevant context but not proof that a password was written to a trace.")
    emit(out,sig,"security_logging_alerting_failure","sparse_noisy",s,"11.5.0","IBM Db2 inventory","affected versions",
         ["affected release ranges recorded", "no literal trace line"],
         "Affected-version metadata has no literal trace line.")
    db2 = external("https://www.ibm.com/support/pages/node/7282952"); require(db2,"Remediation/Fixes")
    emit(out,sig,"security_logging_alerting_failure","secure_negative",db2,"Remediation/Fixes","IBM Db2 fixed state","vendor remediation",
         ["vendor remediation section exists", "fixed levels published", "plaintext trace behavior is not the fixed expectation"],
         "The vendor bulletin publishes remediation for affected Db2 levels, providing a fixed-state control.", "patched_control")

    # security misconfiguration/error leakage
    s = c["security_misconfiguration"]; require(s,"X-Vault-Token","raw `AxiosError`","0.5.2")
    emit(out,sig,"security_misconfiguration","positive",s,"X-Vault-Token","hashi-vault-js","exception propagation",
         ["raw client error rethrown", "request headers retained", "request body retained", "live Vault material can reach logs"],
         "The advisory records raw Axios configuration, including token header and request data, propagating through thrown errors.")
    emit(out,sig,"security_misconfiguration","near_miss",s,"Consuming applications that log caught errors","hashi-vault-js consumer","logging prerequisite",
         ["sensitive error object exists", "consumer does not log it in this observation", "no log disclosure result"],
         "The source makes consumer logging a disclosure precondition; safe handling without logging is adjacent but not the logged-secret outcome.")
    emit(out,sig,"security_misconfiguration","secure_negative",s,"redacting `err.config.headers","hashi-vault-js","redacted error control",
         ["token header removed before rethrow", "request data removed before rethrow", "only safe error properties retained"],
         "Published patch guidance removes token/body material before rethrowing and the advisory identifies a patched release.", "patched_control")
    emit(out,sig,"security_misconfiguration","sparse_noisy",s,"0.5.2","hashi-vault-js inventory","package applicability",
         ["patched release metadata present", "no exception instance"],
         "Package applicability metadata contains no literal exception object.")

    # SSTI
    s = c["server_side_template_injection"]; require(s,"does NOT enable","env('APP_KEY')","trusted developers")
    cur = github_file("own-pay/OwnPay","src/View/TwigFactory.php"); require(cur,"autoescape","TwigExtensions","new Environment")
    emit(out,sig,"server_side_template_injection","positive",s,"env('APP_KEY')","OwnPay Twig rendering","editable template",
         ["non-superadmin controls template source", "server-side function expression present", "secret value rendered"],
         "The audit provides a concrete editable-template expression that evaluates a server-side secret function.")
    emit(out,sig,"server_side_template_injection","near_miss",cur,"autoescape","OwnPay Twig environment","HTML escaping control",
         ["HTML autoescape enabled", "template language execution remains enabled", "untrusted source not proven by this observation"],
         "HTML autoescape is a real output control but does not sandbox server-side Twig functions.", "repository_test_fixture")
    emit(out,sig,"server_side_template_injection","secure_negative",s,"trusted developers","OwnPay trusted template path","developer-shipped template",
         ["template source is trusted developer code", "non-privileged editor does not control source", "reported trust-boundary condition absent"],
         "The finding explicitly distinguishes trusted developer-shipped templates that may remain unsandboxed; without an untrusted author boundary, the reported privilege crossing is absent.")
    emit(out,sig,"server_side_template_injection","sparse_noisy",cur,"TwigExtensions","OwnPay Twig environment","extension inventory",
         ["custom extension registered", "no sandbox extension observed", "no rendered expression result"],
         "Environment/extension inventory is source-grounded but has no rendered template result.", "repository_test_fixture")

    # SQL injection
    s = c["sql_injection"]; require(s,"commentList.asp","id parameter","keyword blocklist")
    nuc = github_issue("projectdiscovery/nuclei-templates",7968); require(nuc,"UserID,GroupID,LoginName,Password","status_code_1 == 200")
    emit(out,sig,"sql_injection","positive",s,"inject arbitrary SQL","ASP-CMS comment listing","id input",
         ["unauthenticated GET", "parameter changes query structure", "sensitive database contents extracted"],
         "The advisory records unauthenticated id-parameter manipulation changing SQL structure and extracting database contents.")
    emit(out,sig,"sql_injection","near_miss",s,"keyword blocklist","ASP-CMS query filter","keyword blocking layer",
         ["keyword filter exists", "obfuscated terms cross the filter", "no database result in this observation"],
         "A keyword blocklist exists but is bypassable; its presence alone does not establish safe binding or extraction.")
    emit(out,sig,"sql_injection","secure_negative",nuc,"status_code_1 == 200","Nuclei ASP-CMS validation","multi-condition response matcher",
         ["HTTP success alone insufficient", "application marker required", "sensitive database field markers required", "missing markers means no positive match"],
         "The upstream validation template requires application and sensitive database markers in addition to HTTP 200; a response lacking them is not evidence of extraction.", "repository_test_fixture")
    emit(out,sig,"sql_injection","sparse_noisy",s,"Shadowserver Foundation","ASP-CMS inventory","observation metadata",
         ["external exploitation date recorded", "classification present", "no literal response body"],
         "Classification/observation metadata contains no database response body.")

    # resource consumption
    s = c["unrestricted_resource_consumption"]; require(s,"S2OPC 1.7.3","denial of service","queue resize")
    old = github_file("systerel/S2OPC","src/ClientServer/services/b2c/monitored_item_notification_queue_bs.c","S2OPC_Toolkit_1.7.3")
    cur = github_file("systerel/S2OPC","src/ClientServer/services/b2c/monitored_item_notification_queue_bs.c")
    require(old,"SOPC_InternalSetOverflowBitAfterDiscard","notifElt->value->Value.Status")
    require(cur,"SOPC_ASSERT(NULL != notifElt->value)","if (NULL == notifElt->value)")
    emit(out,sig,"unrestricted_resource_consumption","positive",s,"queue resize handling","S2OPC monitored event queue","remote resize",
         ["remote request", "event queue resize path reached", "service availability lost"],
         "The advisory records a remote denial of service through monitored-event queue resize handling.")
    emit(out,sig,"unrestricted_resource_consumption","near_miss",old,"GetCapacity","S2OPC notification queue","ordinary capacity control",
         ["queue capacity checked", "old notification discarded when full", "no crash result in this observation"],
         "Affected source already bounds ordinary queue capacity; this backpressure path is adjacent but does not cover the reported event-value edge.", "repository_test_fixture")
    emit(out,sig,"unrestricted_resource_consumption","secure_negative",cur,"if (NULL == notifElt->value)","S2OPC current queue handling","null-value guard",
         ["notification value checked", "invalid event/data value returns before dereference", "unsafe dereference not taken"],
         "Current source adds an explicit null guard and returns before the unsafe dereference in the affected queue logic.", "patched_control")
    emit(out,sig,"unrestricted_resource_consumption","sparse_noisy",s,"CWE-400","S2OPC inventory","release/classification metadata",
         ["affected release recorded", "resource-consumption classification recorded", "no runtime queue trace"],
         "Release/classification data contains no queue execution trace.")

    # unsafe API consumption
    s = c["unsafe_api_consumption"]; require(s,"aiohttp==3.10.10","server-side","Removing the pin")
    reqs = github_file("zachlagden/rickbot","requirements.txt"); require(reqs,"aiohttp==3.10.10","discord.py")
    emit(out,sig,"unsafe_api_consumption","positive",s,"These advisories are in exactly that code","Rickbot outbound network stack","pinned client dependency",
         ["old client release pinned", "reachable HTTP/WebSocket client paths documented", "high-severity client defects affect that release"],
         "The project issue validates that the pinned dependency is reached through Discord HTTP/WebSocket client paths and lists concrete client-side defects.")
    emit(out,sig,"unsafe_api_consumption","near_miss",s,"remaining ~60 are `aiohttp.web` server-side","Rickbot dependency advisories","server-only subset",
         ["application does not run the affected server component", "server-only defects exist in package", "those paths are not reachable"],
         "The source explicitly excludes server-only advisories because the bot does not run the server component; package presence alone is not reachability.")
    emit(out,sig,"unsafe_api_consumption","secure_negative",s,"Removing the pin","Rickbot dependency resolution","fixed client release state",
         ["manual old pin removed", "supported resolver range can select fixed release", "listed client defects have fixing releases"],
         "The issue states that removing the manual transitive pin allows selection of releases at or above the listed fixing levels.", "patched_control")
    emit(out,sig,"unsafe_api_consumption","sparse_noisy",reqs,"aiohttp==3.10.10","Rickbot dependency file","runtime inventory",
         ["client library pin present", "no runtime network response"],
         "The requirements file proves the pin but contains no network behavior.", "repository_test_fixture")

    # websocket authorization
    s = c["websocket_authorization"]; require(s,"WebSocket surface has no authentication","commands hardware")
    auth = github_file("bazauto/layout-orchestration","docs/auth.md"); require(auth,"WebSocket upgrade","reject an unauthenticated upgrade","Emergency Stop stays unauthenticated")
    emit(out,sig,"websocket_authorization","positive",s,"WebSocket surface has no authentication","Layout orchestration","control channel",
         ["session not required", "hardware command surface reachable", "anonymous control possible"],
         "The original security review records an unauthenticated WebSocket control channel that already sends hardware commands.")
    emit(out,sig,"websocket_authorization","near_miss",auth,"Emergency Stop stays unauthenticated","Layout orchestration","HTTP emergency stop",
         ["session not required", "transport is HTTP", "action only moves system to fail-safe state", "not the general control channel"],
         "The current design deliberately leaves only the fail-safe emergency-stop HTTP endpoint unauthenticated; this is an intentional adjacent exception.", "repository_test_fixture")
    emit(out,sig,"websocket_authorization","secure_negative",auth,"reject an unauthenticated upgrade","Layout orchestration","WebSocket upgrade",
         ["shared request hook runs before upgrade", "valid session required", "anonymous upgrade rejected"],
         "Current upstream design routes WebSocket upgrade through the root authentication hook before protocol switch.", "patched_control")
    emit(out,sig,"websocket_authorization","sparse_noisy",auth,"Sliding expiry","Layout orchestration","session lifetime metadata",
         ["opaque session token", "sliding expiry documented", "no WebSocket command result"],
         "Session-lifetime metadata is source-grounded but contains no WebSocket request result.", "repository_test_fixture")

    files = sorted(out.rglob("*.json"))
    families = {p.parent.name for p in files}
    errors: list[str] = []
    if families != REMAINING:
        errors.append(f"family coverage mismatch missing={sorted(REMAINING-families)} extra={sorted(families-REMAINING)}")
    for family in sorted(REMAINING):
        kinds = {p.stem for p in (out / family).glob("*.json")}
        if kinds != VARIANTS:
            errors.append(f"{family}: variants={sorted(kinds)}")
    if len(files) != 84:
        errors.append(f"expected 84 captures, found {len(files)}")
    result = {
        "passed": not errors,
        "errors": errors,
        "capture_count": len(files),
        "family_count": len(families),
        "families": sorted(families),
        "scoring_executed": False,
        "first_blind_consumed": False,
        "detector_output_used": False,
        "admission_output_used": False,
        "ranking_output_used": False,
    }
    if errors:
        raise RuntimeError(json.dumps(result, sort_keys=True))
    return result

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path, default=Path("captured-final21"))
    args = parser.parse_args()
    print(json.dumps(collect(args.output), indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
