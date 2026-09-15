"""Renew outbox ownership while a slow transport is running."""

import contextlib
import datetime as dt
import sqlite3
import threading


def renew_recon_lease(connection, lease_id, *, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat().replace('+00:00', 'Z')
    expires = (now + dt.timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
    return connection.execute(
        "UPDATE recon_alert_notification_outbox SET lease_expires_at=? "
        "WHERE lease_id=? AND status='delivering' AND lease_expires_at>?",
        (expires, lease_id, stamp),
    ).rowcount


@contextlib.contextmanager
def maintain_recon_lease(db, lease_id, *, enabled=True):
    stop = threading.Event()

    def renew():
        connection = sqlite3.connect(str(db.path), timeout=10, isolation_level=None)
        try:
            while not stop.wait(30):
                try:
                    renew_recon_lease(connection, lease_id)
                except sqlite3.OperationalError:
                    # Ownership is checked again before each send and acknowledgement.
                    continue
        finally:
            connection.close()

    worker = threading.Thread(target=renew, daemon=True)
    if enabled:
        worker.start()
    try:
        yield
    finally:
        stop.set()
        if enabled:
            worker.join()
