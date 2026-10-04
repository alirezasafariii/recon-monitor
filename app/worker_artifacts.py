from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping

from core import ReconError, safe_json_loads, sha256_bytes, utc_now


WORKER_ARTIFACT_VERSION = 1
MAX_DOWNLOAD_BYTES = 1024 * 1024


class WorkerArtifactError(ReconError):
    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def download_limit(payload: Mapping[str, Any]) -> int:
    limit = payload.get("max_bytes", MAX_DOWNLOAD_BYTES)
    if type(limit) is not int or limit <= 0:
        raise WorkerArtifactError("Invalid remote download byte limit")
    return min(limit, MAX_DOWNLOAD_BYTES)


def worker_supports_artifacts(metadata: Any) -> bool:
    versions = metadata.get("download_artifact_versions") if isinstance(metadata, dict) else None
    return isinstance(versions, list) and any(type(v) is int and v == WORKER_ARTIFACT_VERSION for v in versions)


def encode_artifact(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes) or len(data) > MAX_DOWNLOAD_BYTES:
        raise WorkerArtifactError("Remote download exceeds artifact limit")
    return {"version": WORKER_ARTIFACT_VERSION, "encoding": "base64", "size": len(data),
            "sha256": sha256_bytes(data), "data": base64.b64encode(data).decode("ascii")}


def _artifact_metadata(artifact: Any, max_bytes: int) -> tuple[str, int]:
    if not isinstance(artifact, dict) or type(artifact.get("version")) is not int or artifact["version"] != WORKER_ARTIFACT_VERSION:
        raise WorkerArtifactError("Invalid remote artifact version")
    digest, size = artifact.get("sha256"), artifact.get("size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise WorkerArtifactError("Invalid remote artifact SHA-256")
    if type(size) is not int or not 0 <= size <= max_bytes:
        raise WorkerArtifactError("Invalid remote artifact size")
    return digest, size


def decode_artifact(payload: Mapping[str, Any], result: Mapping[str, Any]) -> bytes:
    artifact = result.get("artifact")
    if artifact is None:
        raise WorkerArtifactError("Remote download artifact is missing", retryable=True)
    digest, size = _artifact_metadata(artifact, download_limit(payload))
    if artifact.get("encoding") != "base64" or type(result.get("content_length")) is not int or result["content_length"] != size:
        raise WorkerArtifactError("Invalid remote artifact encoding or content length")
    encoded = artifact.get("data")
    if not isinstance(encoded, str) or len(encoded) != 4 * ((size + 2) // 3):
        raise WorkerArtifactError("Invalid remote artifact payload length")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WorkerArtifactError("Invalid remote artifact base64") from exc
    if len(data) != size or sha256_bytes(data) != digest:
        raise WorkerArtifactError("Remote artifact size or SHA-256 mismatch")
    if result.get("status_code") == 206:
        content_range = result.get("content_range")
        if not isinstance(content_range, str) or not complete_download(206, {"content-range": content_range}, data):
            raise WorkerArtifactError("Remote download is incomplete")
    return data


def complete_download(status: int, headers: Mapping[str, str], data: bytes) -> bool:
    """A bounded prefix or short response must never become a complete JS file."""
    declared = headers.get("content-length", "")
    if declared:
        try:
            if int(declared) != len(data):
                return False
        except ValueError:
            return False
    if status == 206:
        match = re.fullmatch(r"bytes 0-(\d+)/(\d+)", headers.get("content-range", "").strip())
        return bool(match and int(match[1]) + 1 == len(data) == int(match[2]))
    return 200 <= status < 300


def without_artifact_body(result: Mapping[str, Any]) -> dict[str, Any]:
    stored = dict(result)
    if isinstance(stored.get("artifact"), dict):
        stored["artifact"] = {k: v for k, v in stored["artifact"].items() if k != "data"}
    return stored


def load_work_artifact(store: Any, work: Mapping[str, Any], result: Mapping[str, Any], max_bytes: int) -> bytes:
    artifact = result.get("artifact")
    digest, size = _artifact_metadata(artifact, max_bytes)
    if artifact.get("stored") is not True:
        raise WorkerArtifactError("Remote artifact was not stored by the controller")
    reference = store.db.one("SELECT sha256 FROM cas_references WHERE owner_kind='work_item' AND owner_key=?", (str(work["id"]),))
    if not reference or reference["sha256"] != digest:
        raise WorkerArtifactError("Remote work artifact reference is missing")
    data = store.get(digest)
    if len(data) != size or sha256_bytes(data) != digest:
        raise WorkerArtifactError("Stored remote artifact size or SHA-256 mismatch")
    return data


class _LeaseRejected(Exception):
    pass


def receive_work_artifact(paths: Any, db: Any, work_id: int, result: Mapping[str, Any], *, worker_id: str, lease_token_hash: str) -> bool:
    from storage import ContentAddressedStore

    store = ContentAddressedStore(paths, db)
    try:
        with store.transaction():
            work = db.one(
                "SELECT * FROM work_items WHERE id=? AND status='running' AND worker_id=? "
                "AND lease_token_hash=? AND COALESCE(lease_expires_at,'')>=?",
                (work_id, worker_id, lease_token_hash, utc_now()),
            )
            if not work:
                raise _LeaseRejected()
            payload = safe_json_loads(work["payload_json"], {}, expected_type=dict)
            data = decode_artifact(payload, result)
            budget = db.one("SELECT used,limit_value FROM run_budgets WHERE run_id=? AND target=? AND metric='download_bytes'", (work["run_id"], work["target"]))
            if budget and budget["limit_value"] and budget["used"] + len(data) > budget["limit_value"]:
                raise WorkerArtifactError("Remote artifact exceeds run download budget")
            digest, _path, _created = store.put(data, content_type=str(result.get("content_type") or "application/octet-stream"))
            if sha256_bytes(store.get(digest)) != digest:
                raise WorkerArtifactError("Stored remote artifact failed verification", retryable=True)
            stored = without_artifact_body(result)
            stored["artifact"] = {"version": WORKER_ARTIFACT_VERSION, "sha256": digest, "size": len(data), "stored": True}
            stored["_worker_outcome"] = {"ok": True, "retry": False, "reason": "artifact_ready", "received_at": utc_now()}
            store.set_reference("work_item", str(work_id), digest)
            if not db.work_receive_artifact(work_id, stored, worker_id=worker_id, lease_token_hash=lease_token_hash):
                raise _LeaseRejected()
            if budget:
                db.execute("UPDATE run_budgets SET used=used+?,updated_at=? WHERE run_id=? AND target=? AND metric='download_bytes'", (len(data), utc_now(), work["run_id"], work["target"]))
    except _LeaseRejected:
        return False
    return True
