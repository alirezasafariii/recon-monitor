from app.differential_integration import enrich_analysis_context


def test_enrich_analysis_context_contains_signal_metadata():
    context = enrich_analysis_context(
        {"auth_state": "protected"},
        {"auth_state": "public"},
    )

    assert context["differential_version"] == "0.2.0"
    assert context["differential_signals"]

    signal = context["differential_signals"][0]
    assert signal["type"] == "auth_boundary_change"
    assert signal["category"] == "access_control"
    assert signal["evidence"]
    assert signal["requires_validation"] is True
