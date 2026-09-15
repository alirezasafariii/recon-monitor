from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_domain_does_not_depend_on_sqlite():
    domain = ROOT / "app" / "domain"
    if not domain.exists():
        return

    for path in domain.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "sqlite3" not in text
        assert "import sqlite" not in text


def test_infrastructure_layer_exists():
    assert (ROOT / "app" / "infrastructure").exists()
