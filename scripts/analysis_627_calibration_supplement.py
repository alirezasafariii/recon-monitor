from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "app" / "family_detectors" / "execution.py"
text = path.read_text(encoding="utf-8")

old = 'BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "invite", "create account", "redeem", "claim", "coupon", "promo", "comment", "post", "message", "review")\n'
new = 'BUSINESS_FLOW_MARKERS = ("purchase", "checkout", "ticket", "order", "reserve", "reservation", "booking", "signup", "register", "invite", "create account", "password reset", "password-reset", "account recovery", "recover account", "redeem", "claim", "coupon", "promo", "comment", "post", "message", "review")\n'
if old not in text:
    raise SystemExit("business flow marker anchor missing")
text = text.replace(old, new, 1)

old = '''        if status in SUCCESS_STATUSES and _flag(flat, "public_fetch") and source_contents:
            _add(packet, "support", _signal("source_map_exposure", "public_observation", "stored_source_map", "Stored target observation confirms the source map with embedded source content is publicly fetchable.", source_group="public_reachability", weight=32, basis="public_fetch_with_embedded_source_content"))
'''
new = '''        if status in SUCCESS_STATUSES and _flag(flat, "public_fetch") and source_contents:
            _add(packet, "support", _signal("source_map_exposure", "public_observation", "stored_source_map", "Stored target observation confirms the source map with embedded source content is publicly fetchable.", source_group="public_reachability", weight=32, basis="public_fetch_with_embedded_source_content"))
        if status in SUCCESS_STATUSES and _flag(flat, "public_fetch") and not source_contents:
            _add(packet, "contradict", _signal("source_map_exposure", "empty_map", "stored_source_map", "Stored publicly reachable source map contains no embedded source content; reachability alone is not treated as sensitive source exposure.", source_group="source_map_control", weight=-32, basis="public_map_without_embedded_source_content"))
'''
if old not in text:
    raise SystemExit("source-map public observation anchor missing")
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
