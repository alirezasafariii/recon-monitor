from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "app" / "family_reasoners.py"
text = path.read_text(encoding="utf-8")
old = '''    "business_logic": FamilyReasonerProfile(
        "Does the server accept a workflow, value, or state transition that violates the intended business invariant?",
        (0.26, 0.54),
        ("race_condition", "sensitive_business_flow_abuse", "broken_function_authorization"),
        confounder_penalty=0.20,
    ),
'''
new = '''    "business_logic": FamilyReasonerProfile(
        "Does the server accept a workflow, value, or state transition that violates the intended business invariant?",
        (0.34, 0.46),
        ("race_condition", "sensitive_business_flow_abuse", "broken_function_authorization"),
        confounder_penalty=0.20,
    ),
'''
if old not in text:
    raise SystemExit("business logic reasoner profile marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
