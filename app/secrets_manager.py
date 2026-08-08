from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from core import AppPaths, ReconError, atomic_write_text

SERVICE_PREFIX = "recon-monitor"


def _service(name: str) -> str:
    clean = "".join(ch for ch in name.strip().lower() if ch.isalnum() or ch in "-_.")
    if not clean: raise ReconError("Invalid secret name")
    return f"{SERVICE_PREFIX}-{clean}"


def keychain_available() -> bool:
    return platform.system() == "Darwin" and bool(__import__('shutil').which("security"))


def set_secret(name: str, value: str) -> None:
    if not keychain_available(): raise ReconError("macOS Keychain is unavailable")
    if not value: raise ReconError("Secret value cannot be empty")
    subprocess.run(["security","add-generic-password","-U","-a",os.environ.get("USER","recon-monitor"),"-s",_service(name),"-w",value],check=True,stdout=subprocess.DEVNULL)


def get_secret(name: str) -> str:
    if not keychain_available(): return ""
    result=subprocess.run(["security","find-generic-password","-a",os.environ.get("USER","recon-monitor"),"-s",_service(name),"-w"],text=True,capture_output=True)
    return result.stdout.strip() if result.returncode==0 else ""


def delete_secret(name: str) -> None:
    if not keychain_available(): raise ReconError("macOS Keychain is unavailable")
    subprocess.run(["security","delete-generic-password","-a",os.environ.get("USER","recon-monitor"),"-s",_service(name)],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def known_secret_names(paths: AppPaths) -> list[str]:
    names=[]
    registry=paths.state/"keychain-secrets.txt"
    if registry.exists(): names=[x.strip() for x in registry.read_text().splitlines() if x.strip()]
    return sorted(set(names))


def register_secret_name(paths: AppPaths, name: str) -> None:
    names=known_secret_names(paths); names.append(name)
    atomic_write_text(paths.state/"keychain-secrets.txt", "\n".join(sorted(set(names)))+"\n",0o600)


def unregister_secret_name(paths: AppPaths, name: str) -> None:
    atomic_write_text(paths.state/"keychain-secrets.txt", "\n".join(x for x in known_secret_names(paths) if x!=name)+"\n",0o600)
