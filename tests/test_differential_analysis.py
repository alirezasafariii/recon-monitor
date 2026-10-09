from app.differential_analysis import DifferentialAnalyzer


def test_protected_endpoint_becomes_public():
    signals = DifferentialAnalyzer().compare(
        {"status_code": 401},
        {"status_code": 200},
    )

    assert any(s.signal_type == "protected_to_public_transition" for s in signals)


def test_auth_boundary_change():
    signals = DifferentialAnalyzer().compare(
        {"auth_state": "protected"},
        {"auth_state": "public"},
    )

    assert any(s.signal_type == "auth_boundary_change" for s in signals)


def test_no_signal_for_identical_response():
    signals = DifferentialAnalyzer().compare(
        {"status_code": 200},
        {"status_code": 200},
    )

    assert signals == []


def test_new_endpoint_detection():
    signals = DifferentialAnalyzer().compare(
        {"exists": False},
        {"exists": True, "path": "/api/export"},
    )

    assert any(s.signal_type == "new_endpoint_exposure" for s in signals)
