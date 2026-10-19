"""Track explicit SQLite close calls, including exception and GC paths."""
import gc
import sqlite3
import traceback
import tracemalloc
import weakref
from unittest.mock import patch


class _ClosingConnection(sqlite3.Connection):
    def close(self):
        super().close()
        for record in getattr(self, '_resource_records', ()):
            record['closed'] = True


class SQLiteResourceGuard:
    def __init__(self):
        self.records = []

    def __enter__(self):
        original = sqlite3.connect

        def connect(*args, **kwargs):
            factory = kwargs.get('factory', sqlite3.Connection)
            if factory is sqlite3.Connection:
                kwargs['factory'] = _ClosingConnection
            elif not issubclass(factory, _ClosingConnection):
                raise AssertionError('Resource guard needs a close-aware connection factory')
            connection = original(*args, **kwargs)
            allocation = tracemalloc.get_object_traceback(connection)
            record = {'closed': False, 'connection': weakref.ref(connection),
                      'stack': ''.join(traceback.format_stack(limit=10)),
                      'allocation': '\n'.join(allocation.format()) if allocation else ''}
            if not hasattr(connection, '_resource_records'):
                connection._resource_records = []
            connection._resource_records.append(record)
            self.records.append(record)
            return connection

        self._patch = patch('sqlite3.connect', side_effect=connect)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()

    def assert_all_closed(self):
        gc.collect()
        leaks = [row for row in self.records if not row['closed']]
        if leaks:
            raise AssertionError(f'{len(leaks)} SQLite connection(s) were never explicitly closed\n'
                                 + '\n'.join(row['stack'] + row['allocation'] for row in leaks))
