import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from main import app


def test_home_renders_queue_and_management_links(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Queue" in response.text
    assert "Nominate a paper" in response.text
    assert "Housekeeping dashboard" in response.text
    assert "Need to add or clean papers?" in response.text


def test_authenticated_user_can_prioritize_multiple_papers(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        assert response.status_code == 200

        client.post("/papers", data={"title": "Paper A"})
        first_priority = client.post("/papers/1/vote", data={"priority": 3})
        assert first_priority.status_code == 200
        second_priority = client.post("/papers/1/vote", data={"priority": 4})
        assert second_priority.status_code == 200

        response = client.get("/vote")

    assert "Critical priority" in response.text

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT priority_level FROM votes WHERE paper_id = 1").fetchone()

    assert row["priority_level"] == 4


def test_priority_endpoint_validates_choice(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        response = client.post("/papers/1/vote", data={"priority": 5})

    assert response.status_code == 400
    assert "Select a valid priority" in response.text


def test_priority_queue_orders_by_priority_and_age(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers", data={"title": "Paper B"})
        client.post("/papers", data={"title": "Paper C"})
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers/3/vote", data={"priority": 3})
        client.post("/papers/1/vote", data={"priority": 2})
        client.post("/papers/2/vote", data={"priority": 2})

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT papers.title
            FROM papers
            LEFT JOIN votes ON votes.paper_id = papers.id
            GROUP BY papers.id
            ORDER BY COALESCE(AVG(votes.priority_level), 0) DESC, papers.created_at ASC, papers.title ASC
            """
        ).fetchall()

    assert [row["title"] for row in rows] == ["Paper C", "Paper A", "Paper B"]


def test_authenticated_user_can_archive_and_unarchive_paper(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        archive_response = client.post("/papers/1/archive")
        assert archive_response.status_code == 200

        with sqlite3.connect(app.state.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT archived FROM papers WHERE id = 1").fetchone()
        assert row["archived"] == 1

        unarchive_response = client.post("/papers/1/unarchive")
        assert unarchive_response.status_code == 200

        with sqlite3.connect(app.state.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT archived FROM papers WHERE id = 1").fetchone()
        assert row["archived"] == 0


def test_archive_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper A"})
        response = client.post("/papers/1/archive")

    assert response.status_code == 401


def test_unarchive_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers/1/archive")
        client.cookies.clear()
        response = client.post("/papers/1/unarchive")

    assert response.status_code == 401


def test_authenticated_user_can_delete_paper(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        delete_response = client.post("/papers/1/delete")
        assert delete_response.status_code == 200

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id FROM papers WHERE id = 1").fetchone()

    assert row is None


def test_delete_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post("/papers", data={"title": "Paper A"})
        response = client.post("/papers/1/delete")

    assert response.status_code == 401


def test_nominate_page_available(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/nominate")

    assert response.status_code == 200
    assert "Register a new paper" in response.text


def test_housekeeping_page_available(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/housekeeping")

    assert response.status_code == 200
    assert "Archive or delete papers" in response.text
