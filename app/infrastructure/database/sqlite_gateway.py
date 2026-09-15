"""SQLite gateway.

Thin adapter around the existing database implementation. This keeps
repository code independent from the concrete database object while the
migration from core.py happens incrementally.
"""

from __future__ import annotations

from typing import Any


class SQLiteGateway:
    def __init__(self, database: Any):
        self._database = database

    def execute(self, query: str, params: tuple = ()):
        return self._database.execute(query, params)

    def one(self, query: str, params: tuple = ()):
        return self._database.one(query, params)

    def all(self, query: str, params: tuple = ()):
        return self._database.all(query, params)
