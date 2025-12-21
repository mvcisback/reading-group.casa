import sqlite3
from datetime import date, timedelta
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


def test_authenticated_user_can_vote_on_multiple_papers(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        assert response.status_code == 200

        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers", data={"title": "Paper B"})

        first_vote = client.post("/papers/1/vote")
        assert first_vote.status_code == 200

        second_vote = client.post("/papers/2/vote")
        assert second_vote.status_code == 200

        homepage = client.get("/")
        assert "Signed in as" in homepage.text
        assert '<span class="font-semibold text-white">reader</span>' in homepage.text
        assert "1 votes" in homepage.text

        already_voted = client.post("/papers/1/vote")
        assert already_voted.status_code == 400


def test_selecting_multiple_papers_records_dates(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)
    scheduled_date = date.today().isoformat()

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers", data={"title": "Paper B"})
        client.post("/papers/1/select")
        client.post("/papers/2/select")
        homepage = client.get("/")

    assert homepage.status_code == 200
    assert scheduled_date in homepage.text
    assert homepage.text.count(scheduled_date) >= 2

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, selected, selected_at FROM papers ORDER BY id").fetchall()

    assert rows[0]["selected"] == 1
    assert rows[0]["selected_at"] == scheduled_date
    assert rows[1]["selected"] == 1
    assert rows[1]["selected_at"] == scheduled_date


def test_selecting_paper_with_custom_date_records_date(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)
    custom_date = (date.today() + timedelta(days=10)).isoformat()

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper C"})
        client.post("/papers/1/select", data={"selected_date": custom_date})
        homepage = client.get("/")

    assert homepage.status_code == 200
    assert custom_date in homepage.text

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT selected, selected_at FROM papers WHERE id = 1").fetchone()

    assert row["selected"] == 1
    assert row["selected_at"] == custom_date


def test_unselecting_paper_clears_selection(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper D"})
        client.post("/papers/1/select")
        client.post("/papers/1/unselect")
        homepage = client.get("/")

    assert homepage.status_code == 200
    assert "No papers have been selected yet" in homepage.text

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT selected, selected_at FROM papers WHERE id = 1").fetchone()

    assert row["selected"] == 0
    assert row["selected_at"] is None
