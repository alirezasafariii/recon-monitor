from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# Preserve the 6.12 precision boundary: a plain /v1 or /v2 route is normal API
# versioning and must not create an inventory hypothesis by itself. Versioned
# inventory becomes security-relevant only with a legacy/non-production marker
# or explicit stored target evidence of inventory drift.
execution_path = ROOT / "app" / "family_detectors" / "execution.py"
old = '''    version_hits = re.findall(r"(?:^|[/_.-])(v\\d+(?:\\.\\d+)?|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", surface_text, re.I)
    if version_hits:
        normalized_versions = {str(token).lower() for token in version_hits}
        packet = _packet_for(result, "improper_inventory_management")
        _add_identity(packet, "improper_inventory_management", "api_version_surface", "endpoint", "Versioned, legacy, or non-production API surface is present.", "inventory_surface", 16)
        if normalized_versions & {"legacy", "old", "deprecated"}:
            _add_identity(packet, "improper_inventory_management", "legacy_endpoint_surface", "endpoint", "Legacy/deprecated API inventory semantics are present.", "inventory_surface", 12)
        if normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add_identity(packet, "improper_inventory_management", "nonproduction_surface", "endpoint", "Non-production/pre-release API inventory semantics are present.", "inventory_surface", 12)
        if status in SUCCESS_STATUSES and normalized_versions & {"legacy", "old", "deprecated"}:
            _add(packet, "support", _signal("improper_inventory_management", "deprecated_version_still_reachable", "http_response", "Stored legacy/deprecated API endpoint remains reachable.", source_group="inventory_behavior", weight=28, basis="legacy_route_success"))
        if status in SUCCESS_STATUSES and normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add(packet, "support", _signal("improper_inventory_management", "undocumented_host_observed", "http_response", "Stored non-production/pre-release API surface is reachable.", source_group="inventory_behavior", weight=22, basis="nonproduction_route_success"))
'''
new = '''    version_hits = re.findall(r"(?:^|[/_.-])(v\\d+(?:\\.\\d+)?|beta|alpha|legacy|old|deprecated|staging|stage|dev|test)(?:[/_.-]|$)", surface_text, re.I)
    normalized_versions = {str(token).lower() for token in version_hits}
    risky_inventory_markers = normalized_versions & {"legacy", "old", "deprecated", "staging", "stage", "dev", "test", "beta", "alpha"}
    explicit_inventory_condition = any(
        _flag(flat, signal)
        for signal in EXECUTION_PROFILES["improper_inventory_management"].condition_signals
    )
    if version_hits and (risky_inventory_markers or explicit_inventory_condition):
        packet = _packet_for(result, "improper_inventory_management")
        _add_identity(packet, "improper_inventory_management", "api_version_surface", "endpoint", "Versioned inventory is combined with legacy/non-production semantics or explicit stored drift evidence.", "inventory_surface", 16)
        if normalized_versions & {"legacy", "old", "deprecated"}:
            _add_identity(packet, "improper_inventory_management", "legacy_endpoint_surface", "endpoint", "Legacy/deprecated API inventory semantics are present.", "inventory_surface", 12)
        if normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add_identity(packet, "improper_inventory_management", "nonproduction_surface", "endpoint", "Non-production/pre-release API inventory semantics are present.", "inventory_surface", 12)
        if status in SUCCESS_STATUSES and normalized_versions & {"legacy", "old", "deprecated"}:
            _add(packet, "support", _signal("improper_inventory_management", "deprecated_version_still_reachable", "http_response", "Stored legacy/deprecated API endpoint remains reachable.", source_group="inventory_behavior", weight=28, basis="legacy_route_success"))
        if status in SUCCESS_STATUSES and normalized_versions & {"staging", "stage", "dev", "test", "beta", "alpha"}:
            _add(packet, "support", _signal("improper_inventory_management", "undocumented_host_observed", "http_response", "Stored non-production/pre-release API surface is reachable.", source_group="inventory_behavior", weight=22, basis="nonproduction_route_success"))
'''
replace_once(execution_path, old, new)

# Analysis 6.18 retained two local variables solely for the old inline API10
# correlation path. Analysis 6.20 moves API10 to execution + physical collector,
# so the old 6.18 regression should now explicitly require their absence.
old_test = ROOT / "tests" / "test_physical_raw_collector_file_remote_v6180.py"
replace_once(
    old_test,
    '''        self.assertIn("ssrf_tokens = _contains_any", source)
        self.assertIn("generic_url_fields =", source)
        self.assertIn("if ssrf_tokens or generic_url_fields:", source)
''',
    '''        # Analysis 6.20 removed the API10 inline correlation variables; SSRF itself
        # remains owned by the 6.18 physical file/remote collector.
        self.assertNotIn("ssrf_tokens = _contains_any", source)
        self.assertNotIn("generic_url_fields =", source)
        self.assertNotIn("if ssrf_tokens or generic_url_fields:", source)
''',
)

# Add an explicit regression to the 6.20 suite for the precision boundary.
api_test = ROOT / "tests" / "test_physical_raw_collector_api_configuration_v6200.py"
text = api_test.read_text(encoding="utf-8")
anchor = '''    def test_surface_only_near_misses_stay_hidden(self):
'''
insert = '''    def test_plain_api_version_is_not_inventory_signal_by_itself(self):
        execution = execute_detector_intelligence(
            target="fixture.invalid", endpoint="/api/v1/users", method="GET",
            endpoint_schema={}, details={"status_code": 200}, category="api", business_context="general",
        )
        self.assertNotIn("improper_inventory_management", execution)

'''
if text.count(anchor) != 1:
    raise RuntimeError("6.20 API test insertion anchor drift")
api_test.write_text(text.replace(anchor, insert + anchor, 1), encoding="utf-8")

# Refresh only files modified after the main 6.20 cutover manifest build.
manifest = ROOT / "MANIFEST.sha256"
lines = manifest.read_text(encoding="utf-8").splitlines()
changed = {
    "app/family_detectors/execution.py": execution_path,
    "tests/test_physical_raw_collector_file_remote_v6180.py": old_test,
    "tests/test_physical_raw_collector_api_configuration_v6200.py": api_test,
}
out = []
seen = set()
for line in lines:
    if "  " not in line:
        out.append(line)
        continue
    _, relative = line.split("  ", 1)
    relative = relative.strip()
    if relative in changed:
        digest = hashlib.sha256(changed[relative].read_bytes()).hexdigest()
        out.append(f"{digest}  {relative}")
        seen.add(relative)
    else:
        out.append(line)
for relative, path in changed.items():
    if relative not in seen:
        out.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
manifest.write_text("\n".join(out) + "\n", encoding="utf-8")
