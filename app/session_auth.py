from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from core import AppPaths, Database, ReconError, atomic_write_text, parse_int, utc_now
from dashboard_auth import hash_password, verify_password

SESSION_TTL_SECONDS = 8 * 3600
ROLE_LEVEL = {"viewer": 10, "analyst": 20, "lead_analyst": 25, "admin": 30}


@dataclass(slots=True)
class Session:
    username: str
    role: str
    csrf: str
    expires_at: int
    token: str

    def allows(self, required: str) -> bool:
        return ROLE_LEVEL.get(self.role, 0) >= ROLE_LEVEL.get(required, 999)


def create_user(paths: AppPaths, username: str, password: str, role: str = "admin") -> None:
    username=username.strip(); role=role.strip().lower()
    if role not in ROLE_LEVEL: raise ReconError("Role must be viewer, analyst, lead_analyst, or admin")
    if not username or any(ch in username for ch in ":\r\n") or len(username)>100: raise ReconError("Invalid username")
    salt,digest,iterations=hash_password(password)
    db=Database(paths.db)
    try:
        now=utc_now()
        db.execute("INSERT INTO users(username,password_salt,password_hash,password_iterations,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(username) DO UPDATE SET password_salt=excluded.password_salt,password_hash=excluded.password_hash,password_iterations=excluded.password_iterations,role=excluded.role,enabled=1,updated_at=excluded.updated_at",(username,salt,digest,iterations,role,now,now))
        db.audit("dashboard_user_upserted", actor=username, entity_type="user", entity_value=username, details={"role":role})
    finally: db.close()


def disable_user(paths: AppPaths, username: str) -> None:
    db=Database(paths.db)
    try:
        db.execute("UPDATE users SET enabled=0,updated_at=? WHERE username=?",(utc_now(),username))
        db.audit("dashboard_user_disabled", entity_type="user", entity_value=username)
    finally: db.close()


def list_users(paths: AppPaths) -> list[dict[str, Any]]:
    db=Database(paths.db)
    try: return [dict(r) for r in db.all("SELECT username,role,enabled,created_at,updated_at FROM users ORDER BY username")]
    finally: db.close()


def verify_user(paths: AppPaths, username: str, password: str) -> tuple[bool,str]:
    db=Database(paths.db)
    try:
        row=db.one("SELECT * FROM users WHERE username=? AND enabled=1",(username,))
        if not row:
            return False,""
        locked_until=str(row["locked_until"] or "") if "locked_until" in row.keys() else ""
        if locked_until and locked_until > utc_now():
            return False,""
        ok=verify_password(password,str(row["password_salt"]),str(row["password_hash"]),int(row["password_iterations"]))
        if ok:
            db.execute("UPDATE users SET failed_login_count=0,locked_until=NULL,last_login_at=?,updated_at=? WHERE username=?",(utc_now(),utc_now(),username))
            return True,str(row["role"])
        failures=int(row["failed_login_count"] or 0)+1 if "failed_login_count" in row.keys() else 1
        locked=None
        if failures>=5:
            import datetime as _dt
            locked=(_dt.datetime.now(_dt.timezone.utc)+_dt.timedelta(minutes=15)).replace(microsecond=0).isoformat().replace("+00:00","Z")
        db.execute("UPDATE users SET failed_login_count=?,locked_until=?,updated_at=? WHERE username=?",(failures,locked,utc_now(),username))
        return False,""
    finally:
        db.close()


def _session_path(paths: AppPaths, token: str) -> Path:
    digest=hashlib.sha256(token.encode()).hexdigest()
    return paths.sessions/f"{digest}.json"


def create_session(paths: AppPaths, username: str, role: str, ttl_seconds: int = SESSION_TTL_SECONDS) -> Session:
    token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); expires=int(time.time())+ttl_seconds
    payload={"username":username,"role":role,"csrf":csrf,"expires_at":expires,"created_at":utc_now()}
    atomic_write_text(_session_path(paths,token),json.dumps(payload,sort_keys=True)+"\n",0o600)
    return Session(username,role,csrf,expires,token)


def parse_session(paths: AppPaths, cookie_header: str) -> Session | None:
    cookie=SimpleCookie();
    try: cookie.load(cookie_header or "")
    except Exception: return None
    morsel=cookie.get("recon_session")
    if not morsel: return None
    token=morsel.value; path=_session_path(paths,token)
    if not path.exists(): return None
    try: data=json.loads(path.read_text())
    except Exception: path.unlink(missing_ok=True); return None
    expires=int(data.get("expires_at",0))
    if expires<int(time.time()): path.unlink(missing_ok=True); return None
    return Session(str(data.get("username","")),str(data.get("role","viewer")),str(data.get("csrf","")),expires,token)


def destroy_session(paths: AppPaths, token: str) -> None:
    _session_path(paths,token).unlink(missing_ok=True)


def cleanup_sessions(paths: AppPaths) -> int:
    removed=0; now=int(time.time())
    for path in paths.sessions.glob("*.json"):
        try: expires=int(json.loads(path.read_text()).get("expires_at",0))
        except Exception: expires=0
        if expires<now: path.unlink(missing_ok=True); removed+=1
    return removed


def session_cookie(session: Session, *, secure: bool = False) -> str:
    flags=[f"recon_session={session.token}","Path=/","HttpOnly","SameSite=Strict",f"Max-Age={max(0,session.expires_at-int(time.time()))}"]
    if secure: flags.append("Secure")
    return "; ".join(flags)


def expired_cookie() -> str:
    return "recon_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
