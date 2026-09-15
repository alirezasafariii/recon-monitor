"""Outbound product policy: findings stay in Analysis; alerts describe changes."""

CHANGE_CATEGORIES = frozenset({
    'new_subdomain', 'dns_change', 'new_url', 'new_js', 'changed_js',
    'js_indicator', 'endpoint_added', 'validated_endpoint', 'new_live_http',
    'fingerprint_change', 'new_port', 'js_reappeared', 'js_disappeared',
})
FINDING_NOTIFICATION_TYPES = frozenset({
    'potential_finding', 'nuclei_finding', 'high_value_case', 'new_finding',
    'validated_candidate', 'bug_candidate',
})


def suppress_finding_delivery(db):
    """Quarantine legacy pending events without deleting findings or audit history."""
    placeholders = ','.join('?' for _ in FINDING_NOTIFICATION_TYPES)
    db.execute(
        f"UPDATE notification_events SET mode='silent',status='suppressed' "
        f"WHERE event_type IN ({placeholders}) AND status IN ('queued','failed')",
        tuple(sorted(FINDING_NOTIFICATION_TYPES)),
    )
    if db.one("SELECT 1 FROM sqlite_master WHERE name='finding_notification_outbox'"):
        db.execute(
            "UPDATE finding_notification_outbox SET status='suppressed',mode='silent',"
            "lease_id='',lease_expires_at='' WHERE status<>'delivered'"
        )
    if db.one("SELECT 1 FROM sqlite_master WHERE name='finding_notification_dead_letters'"):
        from core import utc_now
        db.execute("UPDATE finding_notification_dead_letters SET resolved_at=?,resolution='change_only_policy' "
                   "WHERE resolved_at=''", (utc_now(),))
