import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path

import typer
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Reading Group Coordinator")
templates = Jinja2Templates(directory="templates")
SESSION_COOKIE = "reading_group_session"
PRIORITY_LEVELS = {1, 2, 3, 4}
PRIORITY_LABELS = {
    0: "Unranked",
    1: "Low",
    2: "Medium",
    3: "High",
    4: "Critical",
}
PRIORITY_BUCKETS = [
    (1, "Low", "bg-slate-500"),
    (2, "Medium", "bg-sky-500"),
    (3, "High", "bg-amber-500"),
    (4, "Critical", "bg-rose-500"),
]
QUEUE_SIZE = 3
ASSIGNED_READER_PRIORITY_BONUS = 0.5
READY_TO_PRESENT_PRIORITY_BONUS = 1.0


class PaperNominationForm(BaseModel):
    title: str = Field(..., description="Title of the paper being nominated.")
    paper_url: str | None = Field(None, description="Optional reference link for the paper.")

    @field_validator("title")
    def _normalize_title(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Paper title cannot be empty")
        return cleaned

    @field_validator("paper_url", mode="before")
    def _normalize_url(cls, value: str | None) -> str | None:
        if value:
            trimmed = value.strip()
            return trimmed or None
        return None

    @classmethod
    def as_form(cls, title: str = Form(...), paper_url: str = Form("")) -> "PaperNominationForm":
        return cls(title=title, paper_url=paper_url)


class PriorityVoteForm(BaseModel):
    priority: int = Field(..., description="Priority level (1=Low to 4=Critical).")

    @classmethod
    def as_form(cls, priority: int = Form(...)) -> "PriorityVoteForm":
        return cls(priority=priority)


class CredentialsForm(BaseModel):
    username: str = Field(..., description="User name for authentication.")
    password: str = Field(..., description="Password for authentication.")

    @field_validator("username")
    def _normalize_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Username and password are required")
        return cleaned

    @field_validator("password")
    def _require_password(cls, value: str) -> str:
        if not value:
            raise ValueError("Username and password are required")
        return value

    @classmethod
    def as_form(cls, username: str = Form(...), password: str = Form(...)) -> "CredentialsForm":
        return cls(username=username, password=password)


cli = typer.Typer(invoke_without_command=True)


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


def _priority_label(score: float) -> str:
    if score >= 3.5:
        return PRIORITY_LABELS[4]
    if score >= 2.5:
        return PRIORITY_LABELS[3]
    if score >= 1.5:
        return PRIORITY_LABELS[2]
    if score > 0:
        return PRIORITY_LABELS[1]
    return PRIORITY_LABELS[0]


def _create_papers_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE papers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            paper_url TEXT,
            archived INTEGER NOT NULL DEFAULT 0,
            covered INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            assigned_reader_id INTEGER,
            ready_to_present INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(assigned_reader_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )


def _ensure_papers_table(conn: sqlite3.Connection) -> None:
    desired_columns = {"id", "title", "paper_url", "created_at", "archived", "covered", "assigned_reader_id", "ready_to_present"}
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
            INSERT INTO papers (id, title, paper_url, archived, covered, created_at, assigned_reader_id, ready_to_present)
            SELECT id, title, paper_url, archived, 0, created_at, assigned_reader_id, ready_to_present FROM papers_old
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


def _create_votes_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            paper_id INTEGER NOT NULL,
            priority_level INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, paper_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(paper_id) REFERENCES papers(id) ON DELETE CASCADE
        )
        """
    )


def _ensure_votes_table(conn: sqlite3.Connection) -> None:
    desired_columns = {"id", "user_id", "paper_id", "priority_level", "created_at"}
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='votes'"
    ).fetchone()
    if not exists:
        _create_votes_table(conn)
        return

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(votes)")]
    if set(columns) != desired_columns:
        conn.execute("DROP TABLE IF EXISTS votes_old")
        conn.execute("ALTER TABLE votes RENAME TO votes_old")
        _create_votes_table(conn)
        conn.execute("DROP TABLE votes_old")


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
        _ensure_users_table(conn)
        _ensure_papers_table(conn)
        _ensure_votes_table(conn)
        _ensure_sessions_table(conn)
        conn.commit()


def _fetch_papers(user_id: int | None) -> list[dict]:
    return _fetch_papers_by_archive(user_id, archived=0)


def _fetch_archived_papers(user_id: int | None) -> list[dict]:
    return _fetch_papers_by_archive(user_id, archived=1)


def _fetch_covered_papers(user_id: int | None) -> list[dict]:
    return _fetch_papers_by_archive(user_id, archived=1, covered=1)


def _fetch_papers_by_archive(user_id: int | None, archived: int, covered: int | None = None) -> list[dict]:
    priority_sort_score_expr = (
        "COALESCE(AVG(votes.priority_level), 0)"
        f" + CASE WHEN papers.assigned_reader_id IS NOT NULL THEN {ASSIGNED_READER_PRIORITY_BONUS} ELSE 0 END"
        f" + CASE WHEN papers.ready_to_present = 1 THEN {READY_TO_PRESENT_PRIORITY_BONUS} ELSE 0 END"
    )
    filters = ["papers.archived = ?"]
    params = [archived]
    if covered is not None:
        filters.append("papers.covered = ?")
        params.append(covered)
    filter_clause = " AND ".join(filters)
    with _connect() as conn:
        cursor = conn.execute(
            f"""
            SELECT
                papers.*,
                COALESCE(AVG(votes.priority_level), 0) AS priority_score,
                COUNT(votes.id) AS priority_votes,
                COALESCE(SUM(CASE WHEN votes.priority_level = 1 THEN 1 ELSE 0 END), 0) AS priority_count_1,
                COALESCE(SUM(CASE WHEN votes.priority_level = 2 THEN 1 ELSE 0 END), 0) AS priority_count_2,
                COALESCE(SUM(CASE WHEN votes.priority_level = 3 THEN 1 ELSE 0 END), 0) AS priority_count_3,
                COALESCE(SUM(CASE WHEN votes.priority_level = 4 THEN 1 ELSE 0 END), 0) AS priority_count_4,
                MAX(CASE WHEN votes.user_id = ? THEN votes.priority_level END) AS user_priority,
                MAX(assigned_reader.username) AS assigned_reader_username,
                {priority_sort_score_expr} AS priority_sort_score
            FROM papers
            LEFT JOIN votes ON votes.paper_id = papers.id
            LEFT JOIN users AS assigned_reader ON assigned_reader.id = papers.assigned_reader_id
            WHERE {filter_clause}
            GROUP BY papers.id
            ORDER BY priority_sort_score DESC, papers.created_at ASC, papers.title ASC
            """,
            (user_id, *params),
        )
        rows = cursor.fetchall()
    return _decorate_papers(rows)


def _decorate_papers(rows: list[sqlite3.Row]) -> list[dict]:
    decorated = []
    for row in rows:
        paper = dict(row)
        score = float(paper["priority_score"] or 0)
        votes = int(paper["priority_votes"] or 0)
        paper["priority_score"] = score
        paper["priority_votes"] = votes
        paper["priority_label"] = _priority_label(score)
        paper["priority_score_display"] = f"{score:.1f}" if votes else "—"
        assigned_reader_id = paper.get("assigned_reader_id")
        paper["assigned_reader_id"] = int(assigned_reader_id) if assigned_reader_id is not None else None
        paper["assigned_reader_username"] = paper.get("assigned_reader_username")
        paper["ready_to_present"] = bool(paper.get("ready_to_present"))
        histogram = []
        for bucket_id, bucket_label, bucket_color in PRIORITY_BUCKETS:
            count = int(paper.get(f"priority_count_{bucket_id}") or 0)
            percent = round(count * 100 / votes, 1) if votes else 0
            histogram.append(
                {
                    "label": bucket_label,
                    "count": count,
                    "percent": min(percent, 100),
                    "bar_class": bucket_color,
                }
            )
        paper["priority_histogram"] = histogram
        user_priority = paper.get("user_priority")
        paper["user_priority"] = int(user_priority) if user_priority else None
        paper["user_priority_label"] = (
            PRIORITY_LABELS[paper["user_priority"]]
            if paper["user_priority"]
            else None
        )
        decorated.append(paper)
    return decorated


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


def _require_authenticated_user(request: Request, conn: sqlite3.Connection) -> sqlite3.Row:
    user = _get_user_from_token(conn, request.cookies.get(SESSION_COOKIE))
    if not user:
        raise HTTPException(status_code=401, detail="Log in to manage papers")
    return user


def _build_context(request: Request) -> dict:
    user = _current_user(request)
    user_id = user["id"] if user else None
    papers = _fetch_papers(user_id)
    queue_candidates = papers[:QUEUE_SIZE + 1]
    next_paper = queue_candidates[0] if queue_candidates else None
    queue_papers = queue_candidates[1:] if queue_candidates else []
    backlog_papers = papers[QUEUE_SIZE + 1:]
    archived_papers = _fetch_archived_papers(user_id)
    covered_papers = _fetch_covered_papers(user_id)
    return {
        "request": request,
        "papers": papers,
        "next_paper": next_paper,
        "queue_papers": queue_papers,
        "housekeeping_queue_papers": queue_candidates,
        "backlog_papers": backlog_papers,
        "archived_papers": archived_papers,
        "covered_papers": covered_papers,
        "user": user,
    }


def _hx_or_redirect(request: Request, template_name: str = "partials/refresh.html", redirect_path: str = "/"):
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(template_name, _build_context(request))
    return RedirectResponse(redirect_path, status_code=303)


def _panel_template(panel: str | None = None) -> tuple[str, str]:
    if panel == "candidates":
        return "partials/candidates.html", "/vote"
    if panel == "housekeeping":
        return "partials/housekeeping-panel.html", "/housekeeping"
    return "partials/refresh.html", "/"


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


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    detail = getattr(exc, "detail", None) or "The page you were looking for does not exist."
    return templates.TemplateResponse(
        "404.html",
        {"request": request, "error_detail": detail},
        status_code=404,
    )


@app.get("/", response_class=HTMLResponse)
def homepage(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", _build_context(request))


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", _build_context(request))


@app.get("/vote", response_class=HTMLResponse)
def vote_page(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("vote.html", _build_context(request))


@app.get("/about", response_class=HTMLResponse)
def about_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("about.html", _build_context(request))


@app.get("/nominate", response_class=HTMLResponse)
def nominate_page(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("nominate.html", _build_context(request))


@app.get("/housekeeping", response_class=HTMLResponse)
def housekeeping_page(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("housekeeping.html", _build_context(request))


@app.post("/papers", summary="Nominate a paper")
def register_paper(
    request: Request,
    payload: PaperNominationForm = Depends(PaperNominationForm.as_form),
):
    """
    Submit a new paper nomination for the reading queue.

    - **title**: Non-empty title of the paper.
    - **paper_url**: Optional reference link or DOI.
    """

    with _connect() as conn:
        _require_authenticated_user(request, conn)
        conn.execute(
            "INSERT INTO papers (title, paper_url) VALUES (?, ?)",
            (
                payload.title,
                payload.paper_url,
            ),
        )
        conn.commit()

    return _hx_or_redirect(
        request,
        template_name="partials/nominate-panel.html",
        redirect_path="/nominate",
    )


@app.post("/papers/{paper_id}/vote", summary="Set paper priority")
def vote_on_paper(
    paper_id: int,
    request: Request,
    payload: PriorityVoteForm = Depends(PriorityVoteForm.as_form),
):
    """
    Cast or update the priority level for a paper.

    - **priority**: Integer between 1 (Low) and 4 (Critical).
    """
    if payload.priority not in PRIORITY_LEVELS:
        raise HTTPException(status_code=400, detail="Select a valid priority")
    with _connect() as conn:
        user = _get_user_from_token(conn, request.cookies.get(SESSION_COOKIE))
        if not user:
            raise HTTPException(status_code=401, detail="Log in to cast votes")
        paper = conn.execute("SELECT id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        conn.execute(
            """
            INSERT INTO votes (user_id, paper_id, priority_level)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, paper_id) DO UPDATE SET
                priority_level = excluded.priority_level,
                created_at = CURRENT_TIMESTAMP
            """,
            (user["id"], paper_id, payload.priority),
        )
        conn.commit()

    return _hx_or_redirect(
        request,
        template_name="partials/candidates.html",
        redirect_path="/vote",
    )


@app.post("/papers/{paper_id}/assign", summary="Assign a reader")
def assign_reader(paper_id: int, request: Request, panel: str = Form("refresh")):
    """
    Assign the authenticated user as the reader for the requested paper.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        user = _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT id, assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id and assigned_reader_id != user["id"]:
            raise HTTPException(status_code=400, detail="Paper already has a reader assigned")
        conn.execute(
            "UPDATE papers SET assigned_reader_id = ?, ready_to_present = 0 WHERE id = ?",
            (user["id"], paper_id),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/unassign", summary="Unassign the reader")
def unassign_reader(paper_id: int, request: Request, panel: str = Form("refresh")):
    """
    Release the authenticated reader from the assigned paper.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        user = _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if not assigned_reader_id:
            raise HTTPException(status_code=400, detail="Paper has no assigned reader")
        if assigned_reader_id != user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can release this paper")
        conn.execute(
            "UPDATE papers SET assigned_reader_id = NULL, ready_to_present = 0 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/mark-ready", summary="Mark paper ready")
def mark_paper_ready(paper_id: int, request: Request, panel: str = Form("refresh")):
    """
    Flag the assigned paper as ready to present.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        user = _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id != user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can update readiness")
        conn.execute(
            "UPDATE papers SET ready_to_present = 1 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/mark-not-ready", summary="Mark paper not ready")
def mark_paper_not_ready(paper_id: int, request: Request, panel: str = Form("refresh")):
    """
    Mark the assigned paper as not ready to present.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        user = _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id != user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can update readiness")
        conn.execute(
            "UPDATE papers SET ready_to_present = 0 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/archive", summary="Archive a paper")
def archive_paper(paper_id: int, request: Request):
    """
    Archive a paper and clear any ready-to-present flag.
    """
    with _connect() as conn:
        _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT id, archived FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        if paper["archived"]:
            raise HTTPException(status_code=400, detail="Paper already archived")
        conn.execute("UPDATE papers SET archived = 1, covered = 0 WHERE id = ?", (paper_id,))
        conn.commit()
    return _hx_or_redirect(
        request,
        template_name="partials/housekeeping-panel.html",
        redirect_path="/housekeeping",
    )


@app.post("/papers/{paper_id}/mark-covered", summary="Mark paper covered")
def mark_paper_covered(paper_id: int, request: Request, panel: str = Form("refresh")):
    """
    Mark and archive the paper as covered, removing any reader assignment.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        _require_authenticated_user(request, conn)
        paper = conn.execute("SELECT id, archived FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        if paper["archived"]:
            raise HTTPException(status_code=400, detail="Paper already archived")
        conn.execute(
            """
            UPDATE papers
            SET archived = 1,
                covered = 1,
                assigned_reader_id = NULL,
                ready_to_present = 0
            WHERE id = ?
            """,
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(
        request,
        template_name=template_name,
        redirect_path=redirect_path,
    )


@app.post("/papers/{paper_id}/unarchive", summary="Restore a paper")
def unarchive_paper(paper_id: int, request: Request):
    """
    Restore an archived paper to the active queue.
    """
    with _connect() as conn:
        _require_authenticated_user(request, conn)
        result = conn.execute(
            "UPDATE papers SET archived = 0, covered = 0 WHERE id = ? AND archived = 1",
            (paper_id,),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Paper not found")
        conn.commit()
    return _hx_or_redirect(
        request,
        template_name="partials/housekeeping-panel.html",
        redirect_path="/housekeeping",
    )


@app.post("/papers/{paper_id}/delete", summary="Delete a paper")
def delete_paper(paper_id: int, request: Request):
    """
    Permanently remove the paper from the backlog.
    """
    with _connect() as conn:
        _require_authenticated_user(request, conn)
        result = conn.execute("DELETE FROM papers WHERE id = ?", (paper_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Paper not found")
        conn.commit()
    return _hx_or_redirect(
        request,
        template_name="partials/housekeeping-panel.html",
        redirect_path="/housekeeping",
    )


@app.post("/users/register", summary="Create a new user")
def register_user(
    request: Request,
    credentials: CredentialsForm = Depends(CredentialsForm.as_form),
):
    """
    Register a new reader and issue an authenticated session.

    - **username**: Unique identifier for the reader account.
    - **password**: Secret used for future logins.
    """
    normalized_username = credentials.username
    if not normalized_username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (normalized_username, _hash_password(credentials.password)),
            )
            user_id = cursor.lastrowid
            token = _create_session(conn, user_id)
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Username already taken")

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return response


@app.post("/users/login", summary="Log in a user")
def login_user(
    request: Request,
    credentials: CredentialsForm = Depends(CredentialsForm.as_form),
):
    """
    Authenticate a reader and return a session cookie.

    - **username**: Registered username.
    - **password**: Password used during registration.
    """
    normalized_username = credentials.username
    if not normalized_username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?",
            (normalized_username,),
        ).fetchone()
        if not user or not _verify_password(credentials.password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Invalid username or password")
        token = _create_session(conn, user["id"])
        conn.commit()

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return response


@app.post("/users/logout", summary="Log out")
def logout_user(request: Request):
    """
    Clear the session cookie and log out the current reader.
    """
    token = request.cookies.get(SESSION_COOKIE)
    with _connect() as conn:
        if token:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


def _configure_db_path(db_path: Path) -> None:
    resolved_path = str(db_path)
    app.state.db_path = resolved_path
    os.environ["READING_GROUP_DB"] = resolved_path


def _run_server(db_path: Path, host: str, port: int, reload: bool) -> None:
    _configure_db_path(db_path)
    import uvicorn

    uvicorn.run("main:app", host=host, port=port, reload=reload)


@cli.callback(invoke_without_command=True)
def main_cli(
    ctx: typer.Context,
    db_path: Path = typer.Option(
        Path("reading_group.db"),
        "--db-path",
        "-d",
        help="Path to the SQLite database file.",
    ),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Server host."),
    port: int = typer.Option(8000, "--port", "-p", help="Server port."),
    reload: bool = typer.Option(
        True,
        "--reload/--no-reload",
        help="Enable uvicorn auto-reload when running locally.",
    ),
) -> None:
    if ctx.invoked_subcommand is None:
        _run_server(db_path, host, port, reload)


if __name__ == "__main__":
    cli()
