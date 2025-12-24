import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import typer
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="Reading Group Coordinator")
templates = Jinja2Templates(directory="templates")
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
UI_PREFIX = ""
UI_ROOT = "/"

SECRET_KEY = os.environ.get("READING_GROUP_SECRET_KEY", "insecure_default_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
PBKDF2_ITERATIONS = 600_000
TOKEN_ISSUER = "reading_group"
SESSION_COOKIE = "reading_group_session"
SECURE_COOKIES = os.environ.get("READING_GROUP_SECURE_COOKIE", "0") == "1"
ENFORCE_HTTPS = os.environ.get("READING_GROUP_ENFORCE_HTTPS", "0") == "1"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver", "reading-group.example.com"]

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

if ENFORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "interest-cohort=()")
        response.headers.setdefault("X-XSS-Protection", "0")
        if ENFORCE_HTTPS:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

app.add_middleware(SecurityHeadersMiddleware)

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded"},
    )

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False)

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


class TokenData(BaseModel):
    username: str
    typ: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenForm(BaseModel):
    refresh_token: str = Field(..., description="Refresh token issued alongside the access token")


def _create_token(username: str, token_type: str, expires_delta: timedelta) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": username,
        "typ": token_type,
        "iss": TOKEN_ISSUER,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _create_access_token(username: str) -> str:
    return _create_token(username, "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))


def _create_refresh_token(username: str) -> str:
    return _create_token(username, "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


def _verify_token(token: str, expected_type: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    if payload.get("typ") != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return TokenData(username=username, typ=expected_type)


def _token_from_cookie(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _token_from_header(request: Request) -> str | None:
    authorization = request.headers.get("Authorization")
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1]
    return None


def _extract_token_from_request(request: Request, token: str | None = None) -> str | None:
    if token:
        return token
    return _token_from_header(request) or _token_from_cookie(request)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=SECURE_COOKIES,
        max_age=int(ACCESS_TOKEN_EXPIRE_MINUTES * 60),
    )


def _delete_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)


async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
) -> sqlite3.Row:
    actual_token = _extract_token_from_request(request, token)
    if not actual_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Log in to manage papers")
    token_data = _verify_token(actual_token, "access")
    with _connect() as conn:
        user = _get_user_by_username(conn, token_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Log in to manage papers")
    return user


def _get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()


def _current_user(request: Request) -> sqlite3.Row | None:
    token = _extract_token_from_request(request)
    if not token:
        return None
    try:
        token_data = _verify_token(token, "access")
    except HTTPException:
        return None
    with _connect() as conn:
        return _get_user_by_username(conn, token_data.username)


def _token_response_for_user(username: str) -> TokenResponse:
    access_token = _create_access_token(username)
    refresh_token = _create_refresh_token(username)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


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


def _init_db() -> None:
    with _connect() as conn:
        _ensure_users_table(conn)
        _ensure_papers_table(conn)
        _ensure_votes_table(conn)
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


def _build_context(request: Request, user_row: sqlite3.Row | None = None) -> dict:
    if user_row is None:
        user_row = _current_user(request)
    user_id = user_row["id"] if user_row else None
    user = dict(user_row) if user_row else None
    papers = _fetch_papers(user_id)
    queue_candidates = papers[:QUEUE_SIZE + 1]
    next_paper = queue_candidates[0] if queue_candidates else None
    queue_papers = queue_candidates[1:] if queue_candidates else []
    backlog_papers = papers[QUEUE_SIZE + 1:]
    archived_papers = _fetch_archived_papers(user_id)
    covered_papers = _fetch_covered_papers(user_id)
    context = {
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
    return context


def _client_wants_json(request: Request) -> bool:
    format_hint = request.query_params.get("format")
    if format_hint:
        return format_hint.lower() == "json"
    accept_header = request.headers.get("Accept", "")
    return "application/json" in accept_header.lower()


def _context_without_request(context: dict) -> dict:
    return {key: value for key, value in context.items() if key != "request"}


def _render_template_or_json(
    request: Request,
    template_name: str,
    user_row: sqlite3.Row | None = None,
) -> Response:
    context = _build_context(request, user_row)
    if _client_wants_json(request):
        return JSONResponse(_context_without_request(context))
    return templates.TemplateResponse(template_name, context)


def _hx_or_redirect(request: Request, template_name: str = "partials/refresh.html", redirect_path: str = UI_ROOT):
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(template_name, _build_context(request))
    return RedirectResponse(redirect_path, status_code=303)


def _redirect_to_ui_json(request: Request, target: str = UI_ROOT) -> RedirectResponse:
    params = dict(request.query_params)
    params["format"] = "json"
    return RedirectResponse(f"{target}?{urlencode(params, doseq=True)}", status_code=303)


@app.get("/api/queue", summary="Redirect to UI queue JSON")
def api_queue(request: Request):
    return _redirect_to_ui_json(request)


@app.get("/api/papers", summary="Redirect to UI papers JSON")
def api_papers(request: Request):
    return _redirect_to_ui_json(request)


def _panel_template(panel: str | None = None) -> tuple[str, str]:
    if panel == "candidates":
        return "partials/candidates.html", f"{UI_PREFIX}/vote"
    if panel == "housekeeping":
        return "partials/housekeeping-panel.html", f"{UI_PREFIX}/housekeeping"
    return "partials/refresh.html", UI_ROOT


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${key.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    salt_hex, key_hex = password_hash.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(candidate, key)


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


@app.get(f"{UI_PREFIX}/", response_class=HTMLResponse)
def homepage(request: Request) -> Response:
    return _render_template_or_json(request, "index.html")


@app.get(f"{UI_PREFIX}/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    return _render_template_or_json(request, "login.html")


@app.get(f"{UI_PREFIX}/vote", response_class=HTMLResponse)
def vote_page(request: Request) -> Response:
    user = _current_user(request)
    if not user:
        if _client_wants_json(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Log in to manage papers")
        return RedirectResponse(f"{UI_PREFIX}/login", status_code=303)
    return _render_template_or_json(request, "vote.html", user_row=user)


@app.get(f"{UI_PREFIX}/about", response_class=HTMLResponse)
def about_page(request: Request) -> Response:
    return _render_template_or_json(request, "about.html")


@app.get(f"{UI_PREFIX}/nominate", response_class=HTMLResponse)
def nominate_page(request: Request) -> Response:
    user = _current_user(request)
    if not user:
        if _client_wants_json(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Log in to manage papers")
        return RedirectResponse(f"{UI_PREFIX}/login", status_code=303)
    return _render_template_or_json(request, "nominate.html", user_row=user)


@app.get(f"{UI_PREFIX}/housekeeping", response_class=HTMLResponse)
def housekeeping_page(request: Request) -> Response:
    user = _current_user(request)
    if not user:
        if _client_wants_json(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Log in to manage papers")
        return RedirectResponse(f"{UI_PREFIX}/login", status_code=303)
    return _render_template_or_json(request, "housekeeping.html", user_row=user)


@app.post("/papers", summary="Nominate a paper")
def register_paper(
    request: Request,
    payload: PaperNominationForm = Depends(PaperNominationForm.as_form),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Submit a new paper nomination for the reading queue.

    - **title**: Non-empty title of the paper.
    - **paper_url**: Optional reference link or DOI.
    """

    with _connect() as conn:
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
        redirect_path=f"{UI_PREFIX}/nominate",
    )


@app.post("/papers/{paper_id}/vote", summary="Set paper priority")
def vote_on_paper(
    paper_id: int,
    request: Request,
    payload: PriorityVoteForm = Depends(PriorityVoteForm.as_form),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Cast or update the priority level for a paper.

    - **priority**: Integer between 1 (Low) and 4 (Critical).
    """
    if payload.priority not in PRIORITY_LEVELS:
        raise HTTPException(status_code=400, detail="Select a valid priority")
    with _connect() as conn:
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
            (_current_user["id"], paper_id, payload.priority),
        )
        conn.commit()

    return _hx_or_redirect(
        request,
        template_name="partials/candidates.html",
        redirect_path=f"{UI_PREFIX}/vote",
    )


@app.post("/papers/{paper_id}/assign", summary="Assign a reader")
def assign_reader(
    paper_id: int,
    request: Request,
    panel: str = Form("refresh"),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Assign the authenticated user as the reader for the requested paper.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        paper = conn.execute("SELECT id, assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id and assigned_reader_id != _current_user["id"]:
            raise HTTPException(status_code=400, detail="Paper already has a reader assigned")
        conn.execute(
            "UPDATE papers SET assigned_reader_id = ?, ready_to_present = 0 WHERE id = ?",
            (_current_user["id"], paper_id),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/unassign", summary="Unassign the reader")
def unassign_reader(
    paper_id: int,
    request: Request,
    panel: str = Form("refresh"),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Release the authenticated reader from the assigned paper.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if not assigned_reader_id:
            raise HTTPException(status_code=400, detail="Paper has no assigned reader")
        if assigned_reader_id != _current_user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can release this paper")
        conn.execute(
            "UPDATE papers SET assigned_reader_id = NULL, ready_to_present = 0 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/mark-ready", summary="Mark paper ready")
def mark_paper_ready(
    paper_id: int,
    request: Request,
    panel: str = Form("refresh"),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Flag the assigned paper as ready to present.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id != _current_user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can update readiness")
        conn.execute(
            "UPDATE papers SET ready_to_present = 1 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/mark-not-ready", summary="Mark paper not ready")
def mark_paper_not_ready(
    paper_id: int,
    request: Request,
    panel: str = Form("refresh"),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Mark the assigned paper as not ready to present.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
        paper = conn.execute("SELECT assigned_reader_id FROM papers WHERE id = ?", (paper_id,)).fetchone()
        if not paper:
            raise HTTPException(status_code=404, detail="Paper not found")
        assigned_reader_id = paper["assigned_reader_id"]
        if assigned_reader_id != _current_user["id"]:
            raise HTTPException(status_code=403, detail="Only the assigned reader can update readiness")
        conn.execute(
            "UPDATE papers SET ready_to_present = 0 WHERE id = ?",
            (paper_id,),
        )
        conn.commit()
    return _hx_or_redirect(request, template_name, redirect_path)


@app.post("/papers/{paper_id}/archive", summary="Archive a paper")
def archive_paper(
    paper_id: int,
    request: Request,
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Archive a paper and clear any ready-to-present flag.
    """
    with _connect() as conn:
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
        redirect_path=f"{UI_PREFIX}/housekeeping",
    )


@app.post("/papers/{paper_id}/mark-covered", summary="Mark paper covered")
def mark_paper_covered(
    paper_id: int,
    request: Request,
    panel: str = Form("refresh"),
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Mark and archive the paper as covered, removing any reader assignment.
    """
    template_name, redirect_path = _panel_template(panel)
    with _connect() as conn:
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
def unarchive_paper(
    paper_id: int,
    request: Request,
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Restore an archived paper to the active queue.
    """
    with _connect() as conn:
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
        redirect_path=f"{UI_PREFIX}/housekeeping",
    )


@app.post("/papers/{paper_id}/delete", summary="Delete a paper")
def delete_paper(
    paper_id: int,
    request: Request,
    _current_user: sqlite3.Row = Depends(get_current_user),
):
    """
    Permanently remove the paper from the backlog.
    """
    with _connect() as conn:
        result = conn.execute("DELETE FROM papers WHERE id = ?", (paper_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Paper not found")
        conn.commit()
    return _hx_or_redirect(
        request,
        template_name="partials/housekeeping-panel.html",
        redirect_path=f"{UI_PREFIX}/housekeeping",
    )


@app.post("/users/register", summary="Create a new user")
@limiter.limit("30/minute")
def register_user(
    request: Request,
    credentials: CredentialsForm = Depends(CredentialsForm.as_form),
):
    """
    Register a new reader and issue an authenticated access token.

    - **username**: Unique identifier for the reader account.
    - **password**: Secret used for future logins.
    """
    normalized_username = credentials.username
    if not normalized_username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (normalized_username, _hash_password(credentials.password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Username already taken")

    tokens = _token_response_for_user(normalized_username)
    response = RedirectResponse(UI_ROOT, status_code=303)
    _set_session_cookie(response, tokens.access_token)
    return response


@app.post("/users/login", summary="Log in a user")
@limiter.limit("5/minute")
def login_user(
    request: Request,
    credentials: CredentialsForm = Depends(CredentialsForm.as_form),
):
    """
    Authenticate a reader and return an access token.

    - **username**: Registered username.
    - **password**: Password used during registration.
    """
    normalized_username = credentials.username
    if not normalized_username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    with _connect() as conn:
        user = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (normalized_username,),
        ).fetchone()
    if not user or not _verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    tokens = _token_response_for_user(user["username"])
    response = RedirectResponse(UI_ROOT, status_code=303)
    _set_session_cookie(response, tokens.access_token)
    return response


@app.post("/token", response_model=TokenResponse, summary="Exchange credentials for tokens")
@limiter.limit("10/minute")
def exchange_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username.strip()
    if not username or not form_data.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    with _connect() as conn:
        user = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not user or not _verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return _token_response_for_user(user["username"])


@app.post("/token/refresh", response_model=TokenResponse, summary="Refresh an access token")
@limiter.limit("10/minute")
def refresh_access_token(request: Request, payload: RefreshTokenForm):
    token_data = _verify_token(payload.refresh_token, "refresh")
    with _connect() as conn:
        user = _get_user_by_username(conn, token_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    return _token_response_for_user(user["username"])


@app.post("/users/logout", summary="Log out")
def logout_user():
    """
    Clear the session cookie and log out the current reader.
    """
    response = RedirectResponse(UI_ROOT, status_code=303)
    _delete_session_cookies(response)
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
