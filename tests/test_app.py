from pathlib import Path

from fastapi.testclient import TestClient

from main import app


def test_home_renders_upcoming_and_nomination_form(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Upcoming reading" in response.text
    assert "Register a paper" in response.text
