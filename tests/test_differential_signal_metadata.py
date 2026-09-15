from app.differential_analysis import DifferentialAnalyzer


def test_auth_signal_contains_security_context():
    signals = DifferentialAnalyzer().compare(
        {"auth_state": "protected"},
        {"auth_state": "public"},
    )

    signal = next(s for s in signals if s.signal_type == "auth_boundary_change")

    assert signal.category == "access_control"
    assert signal.requires_validation is True
    assert signal.evidence


def test_endpoint_exposure_contains_evidence():
    signals = DifferentialAnalyzer().compare(
        {"exists": False},
        {"exists": True, "path": "/api/export"},
    )

    signal = next(s for s in signals if s.signal_type == "new_endpoint_exposure")

    assert signal.category == "exposure"
    assert "/api/export" in signal.evidence[0]
