from __future__ import annotations

from .base import FamilyStandardSpec, MethodologyStep, WriteupLesson


POSTMESSAGE_TRUST_STANDARD_SPEC = FamilyStandardSpec(
    family="postmessage_trust",
    version="1.0.0",
    strategy="cross_document_message_sender_trust_boundary",
    principle=(
        "A message handler, event.data flow or sensitive-looking client sink is only a trust surface; promotion requires "
        "stored runtime evidence that an explicitly untrusted sender was accepted and its message reached the identified "
        "security-sensitive consumer despite the intended origin/source boundary."
    ),
    owasp=("OWASP HTML5 Security Cheat Sheet / Web Messaging",),
    wstg=("WSTG-CLNT-11",),
    cwe=("CWE-346",),
    capec=(),
    methodology=(
        MethodologyStep(
            id="POSTMSG-01-handler-surface",
            basis=("WSTG-CLNT-11",),
            principle="Identify message handlers and the exact message data consumed; the existence of a message listener alone is only a client-side trust surface.",
        ),
        MethodologyStep(
            id="POSTMSG-02-origin-source-policy",
            basis=("WSTG-CLNT-11", "CWE-346"),
            principle="Model expected sender origins and source-window relationships and distinguish exact allow-list checks from absent, wildcard, substring or otherwise weak trust checks.",
        ),
        MethodologyStep(
            id="POSTMSG-03-message-schema",
            basis=("WSTG-CLNT-11",),
            principle="Treat message data as untrusted even when the sender is trusted; keep schema/type validation separate from origin/source authorization.",
        ),
        MethodologyStep(
            id="POSTMSG-04-sensitive-consumer",
            basis=("WSTG-CLNT-11",),
            principle="Classify whether accepted message data reaches a sensitive DOM, navigation, network, storage, authentication or state-changing consumer without treating static proximity as runtime effect.",
        ),
        MethodologyStep(
            id="POSTMSG-05-runtime-trust-decision",
            basis=("WSTG-CLNT-11", "CWE-346"),
            principle="Potential-Finding admission requires a stored observation that an explicitly untrusted sender was accepted and reached the identified sensitive consumer despite the intended trust boundary.",
        ),
    ),
    surface_terms=("postmessage", "message event", "event.data", "message handler", "cross document messaging"),
    surface_fields=("origin", "source", "data", "message", "event_data", "message_data"),
    confounders=("dom_xss", "open_redirect", "authentication_session"),
    false_positive_checks=(
        "A message handler and sensitive-looking sink in one static flow are one correlated evidence root, not two proofs.",
        "The presence of postMessage, a message listener or event.data does not establish that arbitrary or unintended senders are accepted.",
        "An exact scheme-host-port origin allow-list or verified source-window relationship contradicts an unsafe sender-trust hypothesis when enforced.",
        "A wildcard targetOrigin on the sending side is a separate disclosure concern and does not prove the receiver accepts untrusted senders.",
        "A trusted-origin message reaching a sensitive consumer does not establish a sender-trust failure.",
        "Schema/type validation and sender validation are separate controls; rejecting one invalid message shape does not prove every sender is trusted or untrusted.",
        "A downstream DOM execution issue may belong to DOM XSS and is not inferred automatically from a Web Messaging trust failure.",
        "OWASP, WSTG, CWE and research write-ups add zero target evidence.",
    ),
    writeups=(
        WriteupLesson(
            id="owasp-wstg-clnt-11-web-messaging",
            source="OWASP WSTG",
            ref="WSTG-CLNT-11 / Testing Web Messaging",
            url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging",
            relation="canonical_web_messaging_test_method",
            lesson=(
                "The reusable test method is to validate sender origin/source and treat message data as untrusted before sensitive use; the standard defines the method and never supplies target evidence."
            ),
            signal_hints=("postmessage_source", "message_handler", "origin_validation_absent", "untrusted_message_accepted"),
        ),
        WriteupLesson(
            id="github-securitylab-browser-extension-message-sender-trust",
            source="GitHub Security Lab",
            ref="Attacking browser extensions / external message sender validation",
            url="https://github.blog/security/vulnerability-research/attacking-browser-extensions/",
            relation="related_message_sender_trust_research",
            lesson=(
                "GitHub Security Lab's browser-extension research shows the broader sender-trust pattern: externally reachable message functionality becomes dangerous when the receiver fails to validate who sent the message. This is supporting methodology, not window.postMessage target evidence."
            ),
            signal_hints=("origin_check_observed", "trusted_origin_only", "untrusted_message_accepted"),
        ),
    ),
)
