#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


reporting_path = ROOT / "app" / "reporting.py"
source = reporting_path.read_text(encoding="utf-8")
import_old = "from notification_transports import deliver_notification_message\n"
import_new = (
    "from notification_transports import deliver_notification_message\n"
    "from recon_alert_outbox import deliver_recon_alert_outbox, enqueue_recon_alert_event\n"
)
if "from recon_alert_outbox import" not in source:
    if import_old not in source:
        raise SystemExit("reporting notification transport import anchor not found")
    source = source.replace(import_old, import_new, 1)

start_marker = "    notified = False\n    if immediate:\n"
end_marker = "\n    return {\n        \"events\": len(events),"
start = source.find(start_marker)
end = source.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("create_alerts_and_notify delivery block anchors not found")
replacement = '''    notified = False
    queued = 0
    delivery: dict[str, Any] = {
        "due": 0,
        "attempted": 0,
        "delivered": 0,
        "retry_pending": 0,
        "failed": 0,
        "batches": [],
    }
    if immediate:
        immediate.sort(key=lambda x: int(x.get("risk_score", 0)), reverse=True)
        for event in immediate:
            payload = {
                "category": str(event.get("category") or "security_change"),
                "severity": str(event.get("severity") or "INFO"),
                "risk_score": int(event.get("risk_score") or 0),
                "title": str(event.get("title") or "Recon change"),
                "item": str(event.get("item") or ""),
                "change_class": str(event.get("change_class") or event.get("category") or "change"),
                "confirmation_state": str(event.get("confirmation_state") or "confirmed"),
            }
            queued_event = enqueue_recon_alert_event(
                ctx.db,
                alert_id=int(event["alert_id"]),
                target=ctx.policy.name,
                run_id=ctx.run_id,
                payload=payload,
            )
            if queued_event.get("queued") and not queued_event.get("deduplicated"):
                queued += 1

        # Preserve immediate best-effort behavior while making failure durable.
        # Target-wide claiming also retries any older due Alert occurrence for
        # this target; batching remains separated by run_id inside the outbox.
        delivery = deliver_recon_alert_outbox(
            config=ctx.config,
            logger=ctx.logger,
            db=ctx.db,
            target=ctx.policy.name,
            limit=max(50, min(500, len(immediate))),
            transport=deliver_notification_message,
        )
        notified = int(delivery.get("delivered", 0) or 0) > 0
'''
source = source[:start] + replacement + source[end:]

return_anchor = '        "notified": notified,\n        "baseline_suppressed": False,'
return_replacement = (
    '        "notified": notified,\n'
    '        "queued": queued,\n'
    '        "delivery": delivery,\n'
    '        "baseline_suppressed": False,'
)
if return_anchor not in source:
    raise SystemExit("notification return anchor not found")
source = source.replace(return_anchor, return_replacement, 1)

baseline_anchor = '            "notified": False,\n            "baseline_suppressed": bool(events),'
baseline_replacement = (
    '            "notified": False,\n'
    '            "queued": 0,\n'
    '            "delivery": {"due": 0, "attempted": 0, "delivered": 0, "retry_pending": 0, "failed": 0, "batches": []},\n'
    '            "baseline_suppressed": bool(events),'
)
if baseline_anchor not in source:
    raise SystemExit("baseline notification return anchor not found")
source = source.replace(baseline_anchor, baseline_replacement, 1)
reporting_path.write_text(source, encoding="utf-8")

transport_test = ROOT / "tests" / "test_recon_alert_transport_consolidation.py"
test_source = transport_test.read_text(encoding="utf-8")
old = '''            with patch.object(reporting, "deliver_notification_message", return_value=failed) as retry_send:
                retry = create_alerts_and_notify(ctx, baseline=False)
            self.assertEqual(retry["immediate"], 1)
            retry_send.assert_called_once()
'''
new = '''            with patch.object(reporting, "deliver_notification_message", return_value=failed) as retry_send:
                retry = create_alerts_and_notify(ctx, baseline=False)
            self.assertEqual(retry["immediate"], 1)
            self.assertEqual(retry["queued"], 0)
            retry_send.assert_not_called()
            outbox = db.one("SELECT status,attempt_count FROM recon_alert_notification_outbox")
            self.assertEqual(outbox["status"], "retry_pending")
            self.assertEqual(outbox["attempt_count"], 1)
'''
if old not in test_source:
    raise SystemExit("transport retry expectation anchor not found")
test_source = test_source.replace(old, new, 1)
transport_test.write_text(test_source, encoding="utf-8")

manifest_path = ROOT / "MANIFEST.sha256"
manifest_lines = manifest_path.read_text(encoding="utf-8").splitlines()
updates = [
    "app/reporting.py",
    "app/recon_alert_outbox.py",
    "tools/deliver_recon_alerts.py",
    "tests/test_recon_alert_outbox.py",
    "tests/test_recon_alert_transport_consolidation.py",
    "docs/RECON_ALERT_OUTBOX.md",
]
existing: dict[str, int] = {}
for index, line in enumerate(manifest_lines):
    parts = line.split("  ", 1)
    if len(parts) == 2:
        existing[parts[1]] = index
for relative in updates:
    value = f"{sha256(ROOT / relative)}  {relative}"
    if relative in existing:
        manifest_lines[existing[relative]] = value
    else:
        manifest_lines.append(value)
manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
