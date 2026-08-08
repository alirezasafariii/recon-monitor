from __future__ import annotations

import importlib.util
import json
import shutil
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from core import APP_VERSION, AppPaths, Database, ReconError, json_dumps, safe_json_loads, utc_now


class PluginProtocol(Protocol):
    metadata: Mapping[str, Any]
    def healthcheck(self) -> tuple[bool, str]: ...
    def plan(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def execute(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass(slots=True)
class PluginInfo:
    name: str
    version: str
    category: str
    path: Path
    enabled: bool
    metadata: dict[str, Any]



PLUGIN_CATEGORIES = {"passive", "mixed", "analysis", "safe-active", "active", "custom"}
PLUGIN_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def validate_manifest(data: Mapping[str, Any], manifest_dir: Path) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    name = str(data.get("name") or "")
    if not PLUGIN_NAME_RE.fullmatch(name): errors.append("name must use lowercase letters, digits, dot, underscore or dash")
    version = str(data.get("version") or "")
    if not version: errors.append("version is required")
    category = str(data.get("category") or "custom")
    if category not in PLUGIN_CATEGORIES: errors.append(f"unsupported category: {category}")
    entrypoint = str(data.get("entrypoint") or "plugin.py")
    resolved = (manifest_dir / entrypoint).resolve()
    try: resolved.relative_to(manifest_dir.resolve())
    except ValueError: errors.append("entrypoint escapes plugin directory")
    if not resolved.exists(): errors.append("entrypoint does not exist")
    timeout = int(data.get("timeout_seconds", 60) or 60)
    if timeout < 1 or timeout > 900: errors.append("timeout_seconds must be between 1 and 900")
    limits = data.get("resource_limits", {})
    if limits is not None and not isinstance(limits, dict): errors.append("resource_limits must be an object")
    normalized = dict(data)
    normalized.update({"name": name, "version": version or "0", "category": category, "entrypoint": entrypoint, "timeout_seconds": timeout, "resource_limits": limits or {}, "input_schema": data.get("input_schema", {}), "output_evidence_types": data.get("output_evidence_types", [])})
    return not errors, errors, normalized

BUILTINS = {
    "subdomains": ("passive", ["subfinder", "assetfinder"]),
    "dns": ("passive", ["dnsx"]),
    "urls": ("mixed", ["waybackurls", "katana"]),
    "javascript": ("analysis", []),
    "endpoint-validation": ("safe-active", []),
    "fingerprint": ("passive", ["httpx"]),
    "ports": ("active", ["naabu"]),
    "nuclei": ("active", ["nuclei"]),
}


class PluginManager:
    def __init__(self, paths: AppPaths, db: Database):
        self.paths = paths; self.db = db

    def sync_builtins(self) -> None:
        for name, (category, tools) in BUILTINS.items():
            metadata = {"name": name, "version": APP_VERSION, "category": category, "tools": tools, "builtin": True}
            self.db.execute(
                "INSERT INTO plugin_registry(name,version,category,enabled,path,metadata_json) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET version=excluded.version,category=excluded.category,path=excluded.path,metadata_json=excluded.metadata_json",
                (name, APP_VERSION, category, 1, f"builtin:{name}", json_dumps(metadata)),
            )

    def discover_external(self) -> list[PluginInfo]:
        infos: list[PluginInfo] = []
        self.paths.plugins.mkdir(parents=True, exist_ok=True)
        for manifest in sorted(self.paths.plugins.glob("*/plugin.json")):
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                ok, errors, data = validate_manifest(raw, manifest.parent)
                name = str(data.get("name") or manifest.parent.name); version = str(data.get("version", "0")); category = str(data.get("category", "custom"))
                module_path = manifest.parent / str(data.get("entrypoint", "plugin.py"))
                info = PluginInfo(name, version, category, module_path, bool(data.get("enabled", True) and ok), {**data, "manifest_valid": ok, "manifest_errors": errors})
                infos.append(info)
                self.db.execute(
                    "INSERT INTO plugin_registry(name,version,category,enabled,path,metadata_json,health_status,last_health) VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET version=excluded.version,category=excluded.category,enabled=excluded.enabled,path=excluded.path,metadata_json=excluded.metadata_json,health_status=excluded.health_status,last_health=excluded.last_health",
                    (name,version,category,int(info.enabled),str(module_path),json_dumps(info.metadata),"unknown" if ok else "invalid_manifest",utc_now()),
                )
            except Exception as exc:
                self.db.execute("INSERT INTO plugin_health_history(plugin_name,version,status,details_json,created_at) VALUES(?,?,?,?,?)",(manifest.parent.name,"","manifest_error",json_dumps({"error":str(exc)}),utc_now()))
                continue
        return infos

    def list(self) -> list[dict[str, Any]]:
        self.sync_builtins(); self.discover_external()
        return [dict(r) for r in self.db.all("SELECT * FROM plugin_registry ORDER BY category,name")]

    def health(self) -> list[dict[str, Any]]:
        results=[]
        for row in self.list():
            metadata=safe_json_loads(row.get("metadata_json"), {}, expected_type=dict)
            missing=[tool for tool in metadata.get("tools",[]) if not shutil.which(tool)]
            manifest_errors=list(metadata.get("manifest_errors",[])) if isinstance(metadata.get("manifest_errors",[]),list) else []
            ok=not missing and not manifest_errors
            problems=[]
            if missing: problems.append("missing tools: "+", ".join(missing))
            if manifest_errors: problems.append("manifest: "+"; ".join(map(str,manifest_errors)))
            detail="ok" if ok else " | ".join(problems)
            status="ok" if ok else "degraded" if not manifest_errors else "invalid_manifest"
            now=utc_now()
            self.db.execute("UPDATE plugin_registry SET health_status=?,last_health=? WHERE name=?", (status,now,row["name"]))
            self.db.execute("INSERT INTO plugin_health_history(plugin_name,version,status,details_json,created_at) VALUES(?,?,?,?,?)",(row["name"],str(row.get("version") or ""),status,json_dumps({"detail":detail,"missing_tools":missing,"manifest_errors":manifest_errors,"contract":{"timeout_seconds":metadata.get("timeout_seconds"),"resource_limits":metadata.get("resource_limits",{}),"output_evidence_types":metadata.get("output_evidence_types",[])}}),now))
            results.append({"name":row["name"],"ok":ok,"status":status,"detail":detail,"contract":{"timeout_seconds":metadata.get("timeout_seconds"),"resource_limits":metadata.get("resource_limits",{}),"output_evidence_types":metadata.get("output_evidence_types",[])}})
        return results

    def load_external(self, name: str) -> PluginProtocol:
        row=self.db.one("SELECT path,metadata_json,enabled FROM plugin_registry WHERE name=?",(name,))
        if not row or not int(row["enabled"]): raise ReconError(f"Plugin unavailable: {name}")
        path=Path(str(row["path"])); spec=importlib.util.spec_from_file_location(f"recon_plugin_{name}",path)
        if not spec or not spec.loader: raise ReconError(f"Cannot load plugin: {name}")
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        plugin=getattr(module,"plugin",None)
        if plugin is None: raise ReconError(f"Plugin {name} must export 'plugin'")
        return plugin
