# Reading Group 1.0

Reading Group is a lightweight FastAPI + htmx application for nominating, voting on, and selecting papers with your study group.

[![Demo Video](https://img.youtube.com/vi/V4SoJ31IgZY/hqdefault.jpg)](https://youtu.be/V4SoJ31IgZY)

## Release 1.0 highlights
- Stable priority queue ordering with per-paper aggregated vote tracking and scheduled selections.
- Persistent state in SQLite with a small CLI wrapper (`main.py`) that exposes `--db-path`, `--host`, `--port`, and reload toggles for local experimentation.
- HTMX-driven surface refreshes plus Tailwind (via CDN) keep the UI responsive while minimizing frontend complexity.

## Features
- Register new papers along with optional reference links.
- Create an account, log in, and vote once per paper so you can back every contender that matters to you.
- Schedule multiple papers with dates so everyone knows which reads are coming up and can reschedule or unselect when plans change.
- Highlight the scheduled selections and their reference links.
- Frontend powered by HTMX and styled with Tailwind via CDN.

## Getting Started
```bash
pip install .
uvicorn main:app --reload
```
Alternatively, run `python main.py` (or `python main.py --db-path /tmp/reading_group.db`) to start the bundled CLI and control the SQLite path and network bindings directly.

## Running with Nix
```bash
nix run
```
The default app (alias `server`) boots `main.py` inside the uv2nix-managed virtualenv, so `nix run` and `nix run .#server` both start the HTTP service configured for local experimentation. Use `nix run .#cli` to run the helper CLI in `cli.py` and pass extra arguments after `--` (e.g., `nix run -- --db-path /tmp/reading_group.db`).

## Database
Data lives in `reading_group.db` (SQLite) in the project root. The schema is created automatically on first launch and there are no migrations yet.

## Testing
```bash
nix develop --command bash -c "uv run pytest"
```
Tests spin up FastAPI's `TestClient` after pointing `app.state.db_path` at a temporary file so the suite never mutates the real database.

## Recommended release steps
- Confirm the changelog (or release notes) captures the 1.0 highlights and any breaking changes.
- Run `cz bump` to determine the new version, update `pyproject.toml`, and refresh `uv.lock` (letting the tool touch affected lockfiles and dependencies).
- Run `nix develop --command bash -c "uv run pytest"` to verify all suites still pass before tagging.
- Tag the release (e.g., `v1.0.0`) and push the annotated tag to the remote.
- Publish documentation or announcements so your community knows about the hardening achieved in 1.0.
