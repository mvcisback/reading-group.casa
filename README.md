# Reading Group

Lightweight FastAPI + htmx application for nominating, voting on, and selecting papers for your reading group.

## Features
- Register new papers along with optional reference links.
- Create an account, log in, and vote once per paper so you can back every contender that matters to you.
- Select a single paper as the next reading assignment.
- Highlight the upcoming paper with any provided reference link.
- Frontend powered by htmx and styled with Tailwind via CDN.

## Getting Started
```bash
pip install .
uvicorn main:app --reload
```
Use `python main.py` as an alternative that delegates to `uvicorn` with sensible defaults.

## Database
Data is stored in `reading_group.db` (SQLite) in the project root. The database is created automatically on first launch and does not require migrations yet.

## Testing
```bash
nix develop --command bash -c "uv run pytest"
```

The existing test suite uses FastAPI's `TestClient` to verify that the home page renders successfully.
