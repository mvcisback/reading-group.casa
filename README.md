# Reading Group

Lightweight FastAPI + htmx application for nominating, voting on, and selecting papers for your reading group.

## Features
- Register new papers along with optional reference links.
- Create an account, log in, and vote once per paper so you can back every contender that matters to you.
- Schedule multiple papers with dates so everyone knows which reads are coming up and can reschedule or unselect when plans change.
- Highlight the scheduled selections and their reference links.
- Frontend powered by htmx and styled with Tailwind via CDN.

## Getting Started
```bash
pip install .
uvicorn main:app --reload
```
Use `python main.py` (or `python main.py --db-path /tmp/reading_group.db`) instead to start the bundled CLI, which exposes `--db-path`, `--host`, `--port`, and `--reload/--no-reload` flags.

## Running with Nix
```bash
nix run
```
This runs the Typer CLI inside `main.py` via the uv2nix-generated virtualenv. Pass CLI arguments after `--` if you need to override the database location or networking options, for example `nix run -- --db-path /tmp/reading_group.db`.

## Database
Data is stored in `reading_group.db` (SQLite) in the project root. The database is created automatically on first launch and does not require migrations yet.

## Testing
```bash
nix develop --command bash -c "uv run pytest"
```

The existing test suite uses FastAPI's `TestClient` to verify that the home page renders successfully.
