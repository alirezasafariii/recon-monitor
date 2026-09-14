"""Alert eligibility is surface change, never vulnerability discovery."""
CHANGE_CATEGORIES = frozenset({
    'new_subdomain', 'dns_change', 'new_url', 'new_js', 'changed_js',
    'js_indicator', 'endpoint_added', 'validated_endpoint', 'new_live_http',
    'fingerprint_change', 'new_port', 'js_reappeared', 'js_disappeared',
})
FINDING_NOTIFICATION_TYPES = frozenset({
    'nuclei_finding', 'high_value_case', 'new_finding', 'potential_finding',
    'validated_candidate', 'bug_candidate',
})
