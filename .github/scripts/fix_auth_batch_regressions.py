from pathlib import Path


reasoning_test = Path("tests/_family_reasoning_v867_legacy.py")
text = reasoning_test.read_text()
old = '''            support = [
                {"type": sorted(group)[0], "source": f"source-{index}", "source_group": f"group-{index}"}
                for index, group in enumerate(groups[:-1], start=1)
            ]
'''
new = '''            # When decisive evidence is intentionally allowed to satisfy
            # weaker structural groups, choose a preceding-group signal that
            # does not also satisfy the omitted final group. This preserves the
            # actual invariant under test: without the final required condition,
            # the hypothesis must stay hidden.
            omitted_group = set(groups[-1])
            support = []
            for index, group in enumerate(groups[:-1], start=1):
                candidates = set(group) - omitted_group
                chosen = sorted(candidates or set(group))[0]
                support.append({
                    "type": chosen,
                    "source": f"source-{index}",
                    "source_group": f"group-{index}",
                })
'''
if old not in text:
    raise SystemExit("family reasoning test anchor missing")
reasoning_test.write_text(text.replace(old, new, 1))

coverage_test = Path("tests/test_final_analyzers_bfla_ssrf_specs.py")
text = coverage_test.read_text()
old = '''                "dom_xss",
                "cors_misconfiguration",
            ),
'''
new = '''                "dom_xss",
                "cors_misconfiguration",
                "authentication_session",
                "open_redirect",
                "postmessage_trust",
                "graphql_authorization",
            ),
'''
if old not in text:
    raise SystemExit("migrated family tuple anchor missing")
coverage_test.write_text(text.replace(old, new, 1))
