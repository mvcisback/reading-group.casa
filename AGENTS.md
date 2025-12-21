# AGENTS GUIDE

## High-level overview
- This is a lightweight FastAPI service that coordinates a reading group: register papers with optional reference links, vote once per session, and select the next title.
- HTMX drives the surface: every form submission targets the `#papers-panel` container and the backend returns `templates/partials/refresh.html` to refresh only the dynamic portion of the page.
- Tailwind CSS (via CDN) and semantic HTML keep the UI tidy without managing local stylesheets.
- Data persists in SQLite (`reading_group.db`), created automatically on startup by `_init_db()` in `main.py`.

## Essential commands
| Purpose | Command |
| --- | --- |
| Start the dev server | `uvicorn main:app --reload` (or `python main.py` for the built-in wrapper) |
| Run the automated tests | `nix develop --command bash -c "uv run pytest"` (uses uv-managed `.venv`) |
| Install the package locally | `pip install .` |
| Add/manage Python deps | `nix develop --command bash -c "uv add --dev <package>"` |
| Enter the nix dev shell | `nix develop` (uses `flake.nix`) |

## Code organization
- `main.py` hosts the FastAPI app, database helpers, and the three POST handlers: `/papers` (register), `/papers/{id}/vote`, and `/papers/{id}/select`. `_hx_or_redirect()` chooses between an HTMX fragment and a redirect.
- Templates are under `templates/`. `base.html` defines the shell (header/main/footer). `index.html` extends it, renders the nomination form, and embeds the `#papers-panel` container.
- `templates/partials/refresh.html` renders the upcoming selection plus the candidate list. It is reused for both full-page renders and HTMX responses.
- `tests/test_app.py` uses `fastapi.testclient.TestClient` to assert the homepage renders; it overrides `app.state.db_path` with a `tmp_path` file before instantiating the client so tests never touch the real DB.

## Naming & style / patterns
- Keep new templates semantic (`<section>`, `<article>`, `<header>`, `<main>`). Use Tailwind utility classes for layout.
- HTML forms set `hx-post`, `hx-target="#papers-panel"`, and `hx-swap="innerHTML"` so responses automatically update the candidate/upcoming panel.
- The `selected` column stores `0/1`. `_resolve_upcoming()` reads papers ordered by `selected DESC, votes DESC, title ASC` so the chosen paper always appears first.
- `main.py` enforces a stripped, non-empty title when registering. The optional `paper_url` is normalized to `None` if blank so only the title/link pair is stored.

## Persistence & configuration
- Default database path: `reading_group.db` in the repo root. Override with the `READING_GROUP_DB` environment variable or by assigning `app.state.db_path` before tests or scripts run.
- SQLite connection is created anew for each operation (`check_same_thread=False` with `row_factory=sqlite3.Row`). No migrations or schema versioning exist yet.

## Testing approach
- Tests live under `tests/` and rely on FastAPI's `TestClient` to hit `/` and verify key copy renders.
- Mock the filesystem-backed DB by pointing `app.state.db_path` at a temp file before instantiating `TestClient` so the startup hook can create the schema.

## Nix dev shell
- `flake.nix` wires up `pyproject-nix`, `uv2nix`, and the Python package defined in `pyproject.toml`.
- `nix develop` gives you a dev shell with `uvicorn`, the `reading-group-venv`, and exports `PYTHONPATH` to the workspace root so imports resolve cleanly.
- Dependency management uses `uv` from the dev shell; edit `uv.lock` by running `nix develop --command bash -c "uv add --dev <package>"`, which also updates the virtual env automatically.
- Use `nix develop --command bash -c "uv run pytest"` for all test runs so you exercise the `.venv` created by `uv`.

## Gotchas & notes
- HTMX requests are detected via the `HX-Request` header. `_hx_or_redirect()` renders `templates/partials/refresh.html` for HTMX and issues a 303 redirect for standard submissions.
- When adding new forms or buttons that should refresh live content, ensure they hit `/papers` or `/papers/{id}/...` with the correct `hx-target`. If you accidentally return a full page for an HTMX request, the DOM swap will replace more than intended.
- Voting requires signing in; the `reading_group_session` cookie identifies the authenticated account and lets it cast one vote per paper. Attempting to vote without logging in returns HTTP 401, and voting for the same paper a second time returns HTTP 400 with an explanatory detail.
- Tailwind is loaded through `https://cdn.tailwindcss.com`; there is no build step for CSS. Keep the markup focused on utility classes.
- Because the DB lives in the workspace root, delete `reading_group.db` when you need to reset nominations; the schema is recreated automatically on next run.
