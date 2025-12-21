import os
import sqlite3
from typing import Iterable

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Reading Group Coordinator")
templates = Jinja2Templates(directory="templates")


def _db_path() -> str:
    override = getattr(app.state, "db_path", None)
    if override:
        return override
    return os.environ.get("READING_GROUP_DB", "reading_group.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS papers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                authors TEXT,
                paper_url TEXT,
                notes_url TEXT,
                votes INTEGER NOT NULL DEFAULT 0,
                selected INTEGER NOT NULL DEFAULT 0
            )
            """
        )
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


def _build_context(request: Request) -> dict:
    papers = _fetch_papers()
    upcoming = _resolve_upcoming(papers)
    return {"request": request, "papers": papers, "upcoming": upcoming}


def _hx_or_redirect(request: Request):
    if request.headers.get("HX-Request"):
        return templates.TemplateResponse("partials/refresh.html", _build_context(request))
    return RedirectResponse("/", status_code=303)


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
    authors: str = Form(""),
    paper_url: str = Form(""),
    notes_url: str = Form(""),
):
    normalized_title = title.strip()
    if not normalized_title:
        raise HTTPException(status_code=400, detail="Paper title cannot be empty")

    with _connect() as conn:
        conn.execute(
            "INSERT INTO papers (title, authors, paper_url, notes_url) VALUES (?, ?, ?, ?)",
            (
                normalized_title,
                authors.strip() or None,
                paper_url.strip() or None,
                notes_url.strip() or None,
            ),
        )
        conn.commit()

    return _hx_or_redirect(request)


@app.post("/papers/{paper_id}/vote")
def vote_on_paper(paper_id: int, request: Request):
    with _connect() as conn:
        result = conn.execute("UPDATE papers SET votes = votes + 1 WHERE id = ?", (paper_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Paper not found")
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
