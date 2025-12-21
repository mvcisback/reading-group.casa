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
