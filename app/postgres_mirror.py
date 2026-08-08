from __future__ import annotations

import json
from typing import Any

from core import Config, Database, ReconError, utc_now

TABLES = ["runs","run_targets","assets","dns_records","urls","alerts","asset_edges","endpoint_intelligence","technology_observations","change_incidents","asset_lifecycle"]


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
    initialize(config); counts={}
    with _connect(config) as conn:
        with conn.cursor() as cur:
            for table in TABLES:
                rows=[dict(r) for r in db.all(f"SELECT * FROM {table}")]
                count=0
                for index,row in enumerate(rows):
                    key=json.dumps(row,sort_keys=True,default=str)[:400]
                    import hashlib
                    row_key=hashlib.sha256(key.encode()).hexdigest()
                    cur.execute("INSERT INTO recon_monitor.mirror_rows(table_name,row_key,payload,synced_at) VALUES(%s,%s,%s::jsonb,now()) ON CONFLICT(table_name,row_key) DO UPDATE SET payload=excluded.payload,synced_at=excluded.synced_at",(table,row_key,json.dumps(row,default=str)))
                    count+=1
                counts[table]=count
        conn.commit()
    return {"synced_at":utc_now(),"tables":counts}
