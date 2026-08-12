from __future__ import annotations

from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_family_collectors.base import RawFamilyObservation

FILE_REMOTE_COLLECTOR_VERSION = "1.0.0"
FILE_REMOTE_COLLECTOR_RULE_VERSION = "2026.08.12.6.18"
FILE_REMOTE_FAMILIES = (
    "ssrf",
    "file_upload",
    "path_traversal",
)

FILE_REMOTE_OBSERVATIONS: dict[str, RawFamilyObservation] = {
    "ssrf": RawFamilyObservation(
        family="ssrf",
        variant="remote_fetch",
        base=20,
        missing=(
            "Whether the server performs the outbound request",
            "Destination validation and scheme restrictions",
            "Network egress policy",
        ),
        rules=(
            "raw-collector-file-remote-v1",
            "candidate-remote-destination",
            "candidate-server-fetch",
        ),
        summary=(
            "A remote-destination input may trigger server-side fetching; promotion requires "
            "stored target evidence that the server performs or attempts the outbound request."
        ),
    ),
    "file_upload": RawFamilyObservation(
        family="file_upload",
        variant="file_validation",
        base=18,
        missing=(
            "Allowed file types and size",
            "Storage and serving behavior",
            "Server-generated filenames and content disposition",
        ),
        rules=(
            "raw-collector-file-remote-v1",
            "candidate-file-surface",
            "candidate-file-validation",
            "admission-file-input-operation",
        ),
        summary=(
            "File-handling evidence is retained for correlation; promotion requires an actual "
            "file input, upload/import operation, and observed unsafe file-handling behavior."
        ),
    ),
    "path_traversal": RawFamilyObservation(
        family="path_traversal",
        variant="path_construction",
        base=16,
        missing=(
            "Path canonicalization",
            "Base-directory enforcement",
            "Whether user-controlled path data reaches filesystem APIs",
        ),
        rules=(
            "raw-collector-file-remote-v1",
            "candidate-path-input",
            "candidate-file-path",
            "admission-path-input-operation",
        ),
        summary=(
            "Path/file clues are retained for correlation; promotion requires structured "
            "path/filename control, a file operation, and observed filesystem/confinement failure."
        ),
    ),
}


def validate_file_remote_collectors() -> list[str]:
    errors: list[str] = []
    if set(FILE_REMOTE_OBSERVATIONS) != set(FILE_REMOTE_FAMILIES):
        errors.append("file/remote collector profile coverage drift")
    for family in FILE_REMOTE_FAMILIES:
        observation = FILE_REMOTE_OBSERVATIONS.get(family)
        if family not in DETECTOR_SPECS:
            errors.append(f"missing physical detector spec: {family}")
            continue
        if observation is None:
            errors.append(f"missing raw collector observation: {family}")
            continue
        if observation.family != family:
            errors.append(f"collector family mismatch: {family}")
        if not observation.variant or observation.base <= 0 or not observation.rules:
            errors.append(f"incomplete collector metadata: {family}")
        if not DETECTOR_SPECS[family].condition_signals:
            errors.append(f"physical detector lacks condition contract: {family}")
    return errors


def collect_file_remote_resource_observations(
    execution_map: Mapping[str, Mapping[str, Any]],
) -> list[RawFamilyObservation]:
    errors = validate_file_remote_collectors()
    if errors:
        raise RuntimeError(
            "Invalid Analysis 6.18 file/remote collector registry: " + "; ".join(errors)
        )
    return [
        FILE_REMOTE_OBSERVATIONS[family]
        for family in FILE_REMOTE_FAMILIES
        if FILE_REMOTE_OBSERVATIONS[family].packet_present(execution_map)
    ]
