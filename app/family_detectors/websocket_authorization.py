from .base import make_spec, writeup
SPEC = make_spec(
    family="websocket_authorization", strategy="channel_identity_boundary",
    surface_terms=("websocket","ws://","wss://","subscribe","channel","room","ddp","socket"),
    surface_fields=("channel","room","topic","user_id","tenant_id","boardId"),
    confounders=("graphql_authorization","broken_object_authorization","authentication_session"),
    expected_wstg=("WSTG-CLNT-10","WSTG-ATHZ-02"), expected_cwe=("CWE-862","CWE-863"),
    writeups=(
        writeup(
            "GHSL-2025-118 / Outline suspended-user WebSocket authentication bypass",
            "https://securitylab.github.com/advisories/GHSL-2025-117_GHSL-2025-118_Outline/",
            "exact",
            "Realtime authorization must hold when the connection/subscription is used; WebSocket construction or an authenticated handshake alone does not prove authorization to every channel, message, or identity scope.",
        ),
    ),
)
