from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

CLIENT_SIDE_COLLECTOR_VERSION = "1.0.0"
CLIENT_SIDE_COLLECTOR_RULE_VERSION = "2026.08.12.6.19"
CLIENT_SIDE_FAMILIES = (
    "dom_xss",
    "postmessage_trust",
    "open_redirect",
)

CLIENT_SIDE_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "dom_xss": RawFamilyObservation(
        family="dom_xss",
        variant="source_to_dom_sink",
        base=18,
        missing=(
            "Runtime reachability of the source-to-sink flow",
            "Effective sanitization or encoding before the sink",
            "Target-specific evidence that user-controlled data reaches executable/HTML interpretation",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-dom-source-sink",
            "admission-dom-runtime-condition",
        ),
        summary=(
            "Stored client artifacts expose a browser-controlled source and dangerous DOM/JavaScript sink; "
            "promotion requires runtime/reachability or missing-sanitizer evidence under the DOM XSS detector."
        ),
    ),
    "postmessage_trust": RawFamilyObservation(
        family="postmessage_trust",
        variant="message_to_sensitive_sink",
        base=17,
        missing=(
            "Strict sender-origin validation",
            "Source-window/channel binding",
            "Message schema validation before the sensitive action",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-message-handler",
            "admission-message-origin-source-schema",
        ),
        summary=(
            "Stored client artifacts expose a cross-window/external message handler near sensitive behavior; "
            "promotion requires target evidence that origin, source, or message-schema enforcement is missing."
        ),
    ),
    "open_redirect": RawFamilyObservation(
        family="open_redirect",
        variant="unvalidated_destination",
        base=20,
        missing=(
            "Final navigation destination after application handling",
            "Same-origin or destination allow-list enforcement",
            "Whether an unintended external destination is accepted",
        ),
        rules=(
            "raw-collector-client-side-v1",
            "candidate-redirect-parameter",
            "candidate-navigation-context",
            "admission-external-destination",
        ),
        summary=(
            "Stored navigation evidence exposes a user-controlled destination and navigation sink; "
            "promotion requires evidence that an unintended external destination is actually accepted."
        ),
    ),
}


def validate_client_side_collectors() -> list[str]:
    errors: list[str] = []
    if set(CLIENT_SIDE_OBSERVATIONS) != set(CLIENT_SIDE_FAMILIES):
        errors.append("client-side collector profile coverage drift")
    for family in CLIENT_SIDE_FAMILIES:
        observation = CLIENT_SIDE_OBSERVATIONS.get(family)
        spec = DETECTOR_SPECS.get(family)
        if spec is None:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not spec.wstg_ids:
            errors.append(f"client detector lacks WSTG grounding: {family}")
        if not spec.owasp_ids:
            errors.append(f"client detector lacks OWASP grounding: {family}")
        if not spec.cwe_ids:
            errors.append(f"client detector lacks CWE grounding: {family}")
        if not spec.writeups:
            errors.append(f"client detector lacks write-up grounding: {family}")
        if any(ref.counts_as_target_evidence for ref in spec.writeups):
            errors.append(f"client detector write-up counted as target evidence: {family}")
        if not spec.condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_client_side_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_client_side_collectors()
    if errors:
        raise RuntimeError("Invalid Analysis 6.19 client-side collector registry: " + "; ".join(errors))
    return [
        CLIENT_SIDE_OBSERVATIONS[family]
        for family in CLIENT_SIDE_FAMILIES
        if CLIENT_SIDE_OBSERVATIONS[family].packet_present(execution_map)
    ]
