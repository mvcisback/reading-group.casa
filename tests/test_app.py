import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from main import (
    app,
    ASSIGNED_READER_PRIORITY_BONUS,
    READY_TO_PRESENT_PRIORITY_BONUS,
    SESSION_COOKIE,
)


def test_home_renders_queue_and_management_links(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200


def test_homepage_json_context(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/?format=json")

    assert response.status_code == 200
    data = response.json()
    assert "queue_papers" in data
    assert "backlog_papers" in data
    assert data["user"] is None
    assert "request" not in data


def test_vote_page_json_context_required_login_and_authenticated(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        login_response = client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        assert login_response.status_code == 200
        response = client.get("/vote", headers={"Accept": "application/json"})

    assert response.status_code == 200
    data = response.json()
    assert data["user"]["username"] == "reader"
    assert "queue_papers" in data


def test_vote_page_json_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/vote", headers={"Accept": "application/json"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Log in to manage papers"


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
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers", data={"title": "Paper B"})
        client.post("/papers", data={"title": "Paper C"})
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


def test_assign_reader_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.cookies.clear()
        response = client.post("/papers/1/assign")

    assert response.status_code == 401


def test_only_assigned_reader_can_toggle_readiness(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers/1/assign", data={"panel": "refresh"})
        first_cookie = client.cookies.get(SESSION_COOKIE)
        client.post(
            "/users/register",
            data={"username": "other", "password": "securepass"},
        )
        response = client.post("/papers/1/mark-ready")
        assert response.status_code == 403
        client.cookies.set(SESSION_COOKIE, first_cookie)
        ready_response = client.post("/papers/1/mark-ready", data={"panel": "refresh"})
        assert ready_response.status_code == 200
        with sqlite3.connect(app.state.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT ready_to_present FROM papers WHERE id = 1").fetchone()
        assert row["ready_to_present"] == 1
        not_ready_response = client.post("/papers/1/mark-not-ready", data={"panel": "refresh"})
        assert not_ready_response.status_code == 200

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT ready_to_present FROM papers WHERE id = 1").fetchone()
    assert row["ready_to_present"] == 0


def test_assigned_reader_updates_priority_order(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers", data={"title": "Paper B"})
        client.post("/papers/2/assign", data={"panel": "refresh"})
        rows_before = _fetch_priority_rows(app.state.db_path)
        assert rows_before[0]["id"] == 2
        assert rows_before[0]["priority_sort_score"] == ASSIGNED_READER_PRIORITY_BONUS
        client.post("/papers/2/mark-ready", data={"panel": "refresh"})
        rows_after = _fetch_priority_rows(app.state.db_path)
        assert rows_after[0]["priority_sort_score"] == ASSIGNED_READER_PRIORITY_BONUS + READY_TO_PRESENT_PRIORITY_BONUS

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT ready_to_present FROM papers WHERE id = 2").fetchone()
    assert row["ready_to_present"] == 1


def _fetch_priority_rows(db_path: str) -> list[sqlite3.Row]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            """
            SELECT
                papers.id,
                COALESCE(AVG(votes.priority_level), 0)
                + CASE WHEN papers.assigned_reader_id IS NOT NULL THEN ? ELSE 0 END
                + CASE WHEN papers.ready_to_present = 1 THEN ? ELSE 0 END AS priority_sort_score
            FROM papers
            LEFT JOIN votes ON votes.paper_id = papers.id
            WHERE papers.archived = 0
            GROUP BY papers.id
            ORDER BY priority_sort_score DESC, papers.created_at ASC, papers.title ASC
            """,
            (
                ASSIGNED_READER_PRIORITY_BONUS,
                READY_TO_PRESENT_PRIORITY_BONUS,
            ),
        ).fetchall()


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


def test_authenticated_user_can_mark_paper_covered(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers/1/assign", data={"panel": "refresh"})
        covered_response = client.post("/papers/1/mark-covered", headers={"HX-Request": "true"})
        assert covered_response.status_code == 200

    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT archived, covered, assigned_reader_id, ready_to_present FROM papers WHERE id = 1"
        ).fetchone()

    assert row["archived"] == 1
    assert row["covered"] == 1
    assert row["assigned_reader_id"] is None
    assert row["ready_to_present"] == 0


def test_mark_paper_covered_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.cookies.clear()
        response = client.post("/papers/1/mark-covered")

    assert response.status_code == 401


def test_mark_paper_covered_rejects_archived(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.post("/papers/1/archive")
        response = client.post("/papers/1/mark-covered")

    assert response.status_code == 400


def test_archive_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.cookies.clear()
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
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Paper A"})
        client.cookies.clear()
        response = client.post("/papers/1/delete")

    assert response.status_code == 401


def test_nominate_page_available(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        response = client.get("/nominate")

    assert response.status_code == 200
    assert "Register a new paper" in response.text


def test_nominate_page_redirects_when_logged_out(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/nominate", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_nominate_requires_login(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.post("/papers", data={"title": "Paper A"})

    assert response.status_code == 401
    assert "Log in to manage papers" in response.text


def test_vote_page_redirects_when_logged_out(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/vote", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_vote_page_available_when_logged_in(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        response = client.get("/vote")

    assert response.status_code == 200
    assert "Assign each paper a priority to move it through the queue." in response.text


def test_housekeeping_page_available(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        response = client.get("/housekeeping")

    assert response.status_code == 200
    assert "Archive or delete papers" in response.text


def test_housekeeping_queue_includes_next_paper(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        client.post(
            "/users/register",
            data={"username": "reader", "password": "securepass"},
        )
        client.post("/papers", data={"title": "Upcoming Paper"})
        response = client.get("/housekeeping")

    assert response.status_code == 200
    assert "Upcoming Paper" in response.text
    assert "No papers are currently in the queue." not in response.text


def test_housekeeping_page_redirects_when_logged_out(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/housekeeping", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_missing_page_renders_custom_404(tmp_path: Path) -> None:
    db_path = tmp_path / "reading_group.db"
    app.state.db_path = str(db_path)

    with TestClient(app) as client:
        response = client.get("/definitely-missing")

    assert response.status_code == 404
    assert "Page not found" in response.text
    assert "Return to queue" in response.text
