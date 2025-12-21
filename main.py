import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Iterable

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Reading Group Coordinator")
templates = Jinja2Templates(directory="templates")
SESSION_COOKIE = "reading_group_session"


def _db_path() -> str:
    override = getattr(app.state, "db_path", None)
    if override:
        return override
    return os.environ.get("READING_GROUP_DB", "reading_group.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _create_papers_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            paper_url TEXT,
            votes INTEGER NOT NULL DEFAULT 0,
            selected INTEGER NOT NULL DEFAULT 0
        )
        """
    )


def _ensure_papers_table(conn: sqlite3.Connection) -> None:
    desired_columns = {"id", "title", "paper_url", "votes", "selected"}
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='papers'"
    ).fetchone()
    if not exists:
        _create_papers_table(conn)
        return

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(papers)")]
    if set(columns) != desired_columns:
        conn.execute("DROP TABLE IF EXISTS papers_old")
        conn.execute("ALTER TABLE papers RENAME TO papers_old")
        _create_papers_table(conn)
        conn.execute(
            """
            INSERT INTO papers (id, title, paper_url, votes, selected)
            SELECT id, title, paper_url, votes, selected FROM papers_old
            """
        )
        conn.execute("DROP TABLE papers_old")


def _ensure_users_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def _ensure_votes_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            paper_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, paper_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(paper_id) REFERENCES papers(id) ON DELETE CASCADE
        )
        """
    )


def _ensure_sessions_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )


def _init_db() -> None:
    with _connect() as conn:
        _ensure_papers_table(conn)
        _ensure_users_table(conn)
        _ensure_votes_table(conn)
        _ensure_sessions_table(conn)
        conn.commit()


def _fetch_papers() -> list[sqlite3.Row]:
    with _connect() as conn:
        cursor = conn.execute(
            "SELECT * FROM papers ORDER BY selected DESC, votes DESC, title ASC"
        )
        return cursor.fetchall()


def _resolve_upcoming(papers: Iterable[sqlite3.Row]) -> sqlite3.Row | None:
    for paper in papers:
        if paper["selected"]:
            return paper
    return next(iter(papers), None)


def _get_user_from_token(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    return conn.execute(
        """
        SELECT users.id, users.username
        FROM users
        JOIN sessions ON sessions.user_id = users.id
        WHERE sessions.token = ?
        """,
        (token,),
    ).fetchone()


def _current_user(request: Request) -> sqlite3.Row | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with _connect() as conn:
        return _get_user_from_token(conn, token)


def _build_context(request: Request) -> dict:
    papers = _fetch_papers()
    upcoming = _resolve_upcoming(papers)
    user = _current_user(request)
    return {
        "request": request,
        "papers": papers,
        "upcoming": upcoming,
        "user": user,
    }


def _hx_or_redirect(request: Request):
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/refresh.html", _build_context(request))
    return RedirectResponse("/", status_code=303)


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${key.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    salt_hex, key_hex = password_hash.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hmac.compare_digest(candidate, key)


def _create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?, ?)",
        (token, user_id),
    )
    return token


@app.on_event("startup")
def startup_event() -> None:
    _init_db()


@app.get("/", response_class=HTMLResponse)
def homepage(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", _build_context(request))


@app.post("/papers")
def register_paper(
    request: Request,
    title: str = Form(...),
    paper_url: str = Form(""),
):
    normalized_title = title.strip()
    if not normalized_title:
        raise HTTPException(status_code=400, detail="Paper title cannot be empty")

    with _connect() as conn:
        conn.execute(
            "INSERT INTO papers (title, paper_url) VALUES (?, ?)",
            (
                normalized_title,
                paper_url.strip() or None,
            ),
        )
        conn.commit()

    return _hx_or_redirect(request)


@app.post("/papers/{paper_id}/vote")
def vote_on_paper(paper_id: int, request: Request):
    with _connect() as conn:
        user = _get_user_from_token(conn, request.cookies.get(SESSION_COOKIE))
        if not user:
            raise HTTPException(status_code=401, detail="Log in to cast votes")
        paper = conn.execute("SELECT id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        try:
            conn.execute(
                "INSERT INTO votes (user_id, paper_id) VALUES (?, ?)",
                (user["id"], paper_id),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="You already voted for this paper")
        conn.execute("UPDATE papers SET votes = votes + 1 WHERE id = ?", (paper_id,))
        conn.commit()

    return _hx_or_redirect(request)


@app.post("/papers/{paper_id}/select")
def select_paper(paper_id: int, request: Request):
    with _connect() as conn:
        conn.execute("UPDATE papers SET selected = 0 WHERE selected != 0")
        result = conn.execute("UPDATE papers SET selected = 1 WHERE id = ?", (paper_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Paper not found")
        conn.commit()

    return _hx_or_redirect(request)


@app.post("/users/register")
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    normalized_username = username.strip()
    if not normalized_username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (normalized_username, _hash_password(password)),
            )
            user_id = cursor.lastrowid
            token = _create_session(conn, user_id)
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Username already taken")

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return response


@app.post("/users/login")
def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    normalized_username = username.strip()
    if not normalized_username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (normalized_username,),
        ).fetchone()
        if not user or not _verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Invalid username or password")
        token = _create_session(conn, user["id"])
        conn.commit()

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return response


@app.post("/users/logout")
def logout_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    with _connect() as conn:
        if token:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
