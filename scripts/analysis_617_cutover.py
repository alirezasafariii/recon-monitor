from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUG = ROOT / "app" / "bug_candidates.py"
TEST = ROOT / "tests" / "test_physical_raw_collector_authorization_v6170.py"
DOC = ROOT / "docs" / "ANALYSIS_ENGINE_6_17_AUTHORIZATION_RAW_COLLECTORS.md"
MANIFEST = ROOT / "MANIFEST.sha256"


def patch_bug_candidates() -> None:
    source = BUG.read_text(encoding="utf-8")

    old_import = "from raw_family_collectors import collect_injection_observations\n"
    new_import = (
        "from raw_family_collectors import "
        "collect_authorization_observations, collect_injection_observations\n"
    )
    if old_import in source:
        source = source.replace(old_import, new_import, 1)
    elif new_import not in source:
        raise RuntimeError("Analysis 6.17 import anchor not found")

    bola_marker = "    # BOLA / IDOR 2.0 — object reference is a hypothesis surface, not a finding.\n"
    authorization_loop = '''    # Analysis 6.17 — physical raw collector ownership for function/property authorization.\n    # The collector contributes emission metadata only; target evidence remains owned\n    # by execute_detector_intelligence() and raw-condition reconstruction.\n    for observation in collect_authorization_observations(execution_map):\n        emit(\n            observation.family,\n            observation.variant,\n            observation.base,\n            [],\n            [],\n            list(observation.missing),\n            list(observation.rules),\n            observation.summary,\n            direct=observation.direct,\n            impact=observation.impact,\n        )\n\n'''
    if "collect_authorization_observations(execution_map)" not in source:
        if bola_marker not in source:
            raise RuntimeError("Analysis 6.17 BOLA insertion anchor not found")
        source = source.replace(bola_marker, authorization_loop + bola_marker, 1)

    legacy_start = "    # Function / role authorization\n"
    legacy_end = "    # Authentication / recovery / enumeration\n"
    replacement = (
        "    # Analysis 6.17: Function Authorization and Mass Assignment legacy collection was physically\n"
        "    # removed after equivalent execution/admission coverage moved to raw_family_collectors.authorization.\n\n"
    )
    if legacy_start in source:
        start = source.index(legacy_start)
        try:
            end = source.index(legacy_end, start)
        except ValueError as exc:
            raise RuntimeError("Analysis 6.17 legacy authorization end anchor not found") from exc
        source = source[:start] + replacement + source[end:]
    elif "Function Authorization and Mass Assignment legacy collection was physically" not in source:
        raise RuntimeError("Analysis 6.17 legacy authorization start anchor not found")

    if 'emit("broken_function_authorization"' in source:
        raise RuntimeError("legacy broken_function_authorization emit survived cutover")
    if 'emit("mass_assignment"' in source:
        raise RuntimeError("legacy mass_assignment emit survived cutover")

    BUG.write_text(source, encoding="utf-8")


def patch_test_contract() -> None:
    source = TEST.read_text(encoding="utf-8")
    marker = '\n\nif __name__ == "__main__":\n'
    method = '''\n    def test_orchestrator_cutover_removes_legacy_authorization_blocks(self):\n        source = (ROOT / "app" / "bug_candidates.py").read_text(encoding="utf-8")\n        self.assertIn("collect_authorization_observations(execution_map)", source)\n        self.assertIn("Function Authorization and Mass Assignment legacy collection was physically", source)\n        self.assertNotIn("# Function / role authorization", source)\n        self.assertNotIn("# Mass assignment / property-level authorization", source)\n        self.assertNotIn('emit("broken_function_authorization"', source)\n        self.assertNotIn('emit("mass_assignment"', source)\n'''
    if "test_orchestrator_cutover_removes_legacy_authorization_blocks" not in source:
        if marker not in source:
            raise RuntimeError("Analysis 6.17 test insertion anchor not found")
        source = source.replace(marker, method + marker, 1)
    TEST.write_text(source, encoding="utf-8")


def patch_doc() -> None:
    source = DOC.read_text(encoding="utf-8")
    start_marker = "## Stage-one contract\n"
    end_marker = "\n## Non-goals\n"
    replacement = '''## Cutover contract\n\nThe 6.17 cutover now routes both legacy raw authorization families through `collect_authorization_observations(execution_map)` and the existing `emit()` firewall. The old Function/Role Authorization and Mass Assignment collection blocks are physically removed from `_alert_candidates()`.\n\nThe cutover preserves:\n\n1. admission thresholds and family-specific decisive-condition requirements;\n2. detector execution and raw-condition reconstruction ownership of target evidence;\n3. independent-source guards and hidden-hypothesis behavior;\n4. BOLA, GraphQL and static authorization behavior;\n5. the existing ranking and impact model.\n\nSurface-only privileged routes and writable privileged fields still remain hidden hypotheses until stored target evidence satisfies the corresponding authorization/property condition.\n'''
    if start_marker in source:
        start = source.index(start_marker)
        try:
            end = source.index(end_marker, start)
        except ValueError as exc:
            raise RuntimeError("Analysis 6.17 doc end anchor not found") from exc
        source = source[:start] + replacement + source[end:]
    elif "## Cutover contract" not in source:
        raise RuntimeError("Analysis 6.17 doc stage anchor not found")
    DOC.write_text(source, encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def update_manifest() -> None:
    entries: dict[str, str] = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            digest, rel = raw.split("  ", 1)
        except ValueError as exc:
            raise RuntimeError(f"Malformed manifest line: {raw!r}") from exc
        entries[rel] = digest

    permanent = (
        "app/bug_candidates.py",
        "app/raw_family_collectors/__init__.py",
        "app/raw_family_collectors/authorization.py",
        "docs/ANALYSIS_ENGINE_6_17_AUTHORIZATION_RAW_COLLECTORS.md",
        "tests/test_physical_raw_collector_authorization_v6170.py",
    )
    for rel in permanent:
        path = ROOT / rel
        if not path.is_file():
            raise RuntimeError(f"Manifest target missing: {rel}")
        entries[rel] = sha256(path)

    MANIFEST.write_text(
        "".join(f"{digest}  {rel}\n" for rel, digest in sorted(entries.items())),
        encoding="utf-8",
    )


def main() -> None:
    patch_bug_candidates()
    patch_test_contract()
    patch_doc()
    update_manifest()


if __name__ == "__main__":
    main()
