from __future__ import annotations

import hashlib
import json
from typing import Any

from core import Config, Database, ReconError, utc_now

TABLES = ["runs","run_targets","assets","dns_records","urls","alerts","asset_edges","endpoint_intelligence","technology_observations","change_incidents","asset_lifecycle"]
ROW_KEY_PREFIX = "pk:v1:"


def _primary_key_columns(db: Database, table: str) -> tuple[str, ...]:
    # Bind identity and payload to the same source table, even if a temporary
    # Analysis view shadows its name on this SQLite connection.
    schema = db.all(f'PRAGMA main.table_info("{table}")')
    columns = tuple(
        row["name"]
        for row in sorted(schema, key=lambda row: row["pk"])
        if row["pk"]
    )
    if not columns:
        raise ReconError(f"PostgreSQL mirror table has no primary key: {table}")
    return columns


def _row_key(table: str, row: dict[str, Any], columns: tuple[str, ...]) -> str:
    identity = []
    for column in columns:
        if row.get(column) is None:
            raise ReconError(f"PostgreSQL mirror primary key is missing or null: {table}.{column}")
        identity.append((column, row[column]))
    # Hash the complete, typed primary key, never a payload prefix. JSON keeps
    # composite values unambiguous; non-key edits cannot change row identity.
    key = json.dumps(identity, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return ROW_KEY_PREFIX + hashlib.sha256(key.encode("utf-8")).hexdigest()


def _connect(config: Config):
    dsn=config.get("POSTGRES_DSN","")
    if not dsn: raise ReconError("POSTGRES_DSN is not configured")
    try:
        import psycopg
    except ImportError as exc:
        raise ReconError("Install psycopg to use the PostgreSQL mirror: python3 -m pip install 'psycopg[binary]'") from exc
    return psycopg.connect(dsn)


def status(config: Config) -> dict[str, Any]:
    try:
        with _connect(config) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                return {"ok":True,"server":cur.fetchone()[0]}
    except Exception as exc:
        return {"ok":False,"error":str(exc)}


def initialize(config: Config) -> dict[str, Any]:
    with _connect(config) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE SCHEMA IF NOT EXISTS recon_monitor")
            cur.execute("CREATE TABLE IF NOT EXISTS recon_monitor.mirror_rows(table_name text NOT NULL,row_key text NOT NULL,payload jsonb NOT NULL,synced_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(table_name,row_key))")
        conn.commit()
    return {"initialized":True}


def sync(config: Config, db: Database) -> dict[str, Any]:
    initialize(config)
    counts = {}
    with _connect(config) as conn:
        with conn.cursor() as cur:
            for table in TABLES:
                columns = _primary_key_columns(db, table)
                rows = [dict(row) for row in db.all(f'SELECT * FROM main."{table}"')]
                for row in rows:
                    row_key = _row_key(table, row, columns)
                    cur.execute(
                        "INSERT INTO recon_monitor.mirror_rows(table_name,row_key,payload,synced_at) "
                        "VALUES(%s,%s,%s::jsonb,now()) ON CONFLICT(table_name,row_key) "
                        "DO UPDATE SET payload=excluded.payload,synced_at=excluded.synced_at",
                        (table, row_key, json.dumps(row, default=str)),
                    )
                # Replace legacy content-derived keys in the same transaction.
                # A later read, write, or cleanup failure rolls back both the
                # new payloads and this cleanup; unrelated tables are kept.
                cur.execute(
                    "DELETE FROM recon_monitor.mirror_rows "
                    "WHERE table_name=%s AND row_key NOT LIKE %s",
                    (table, ROW_KEY_PREFIX + "%"),
                )
                counts[table] = len(rows)
        conn.commit()
    return {"synced_at": utc_now(), "tables": counts}
