import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import typer

cli = typer.Typer(help="Command-line helpers for the reading group service.")
DEFAULT_SCHEME = "http"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_SESSION_FILE = Path.home() / ".reading_group_cli" / "session.json"
HOUSEKEEPING_ACTION_MAP = {
    "assign": "assign",
    "unassign": "unassign",
    "ready": "mark-ready",
    "not-ready": "mark-not-ready",
    "archive": "archive",
    "cover": "mark-covered",
    "unarchive": "unarchive",
    "delete": "delete",
}
PANEL_REQUIRED_ACTIONS = {"assign", "unassign", "ready", "not-ready", "cover"}


def _resolve_base_url(base_url: str | None, scheme: str, host: str, port: int) -> str:
    if base_url:
        return base_url.rstrip("/")
    return f"{scheme}://{host}:{port}"


def _ensure_session_dir(session_file: Path) -> None:
    session_file.parent.mkdir(parents=True, exist_ok=True)


def _load_session(session_file: Path) -> dict[str, Any] | None:
    if not session_file.exists():
        return None
    try:
        with session_file.open() as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return None
        if "access_token" not in data:
            return None
        return data
    except (OSError, json.JSONDecodeError):
        return None


def _save_session(session_file: Path, username: str, tokens: dict[str, Any]) -> None:
    _ensure_session_dir(session_file)
    payload = {
        "username": username,
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
    }
    with session_file.open("w") as handle:
        json.dump(payload, handle)


def _clear_session(session_file: Path) -> bool:
    if session_file.exists():
        session_file.unlink()
        return True
    return False


def _handle_http_error(error: httpx.HTTPStatusError) -> None:
    response = error.response
    message = (response.text or response.reason_phrase).strip()
    typer.secho(f"Request failed ({response.status_code}): {message}", fg="red")
    raise typer.Exit(code=1)


async def _fetch_tokens(ctx: typer.Context, username: str, password: str) -> dict[str, Any]:
    async with httpx.AsyncClient(base_url=ctx.obj["base_url"]) as client:
        response = await client.post("/token", data={"username": username, "password": password})
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _handle_http_error(exc)
        return response.json()


async def _resolve_access_token(
    ctx: typer.Context, username: str | None, password: str | None
) -> str:
    if username:
        if password is None:
            raise typer.Exit(code=1)
        tokens = await _fetch_tokens(ctx, username, password)
        return tokens["access_token"]
    session = _load_session(ctx.obj["session_file"])
    if session and session.get("access_token"):
        return session["access_token"]
    typer.secho("Log in or provide --username/--password", fg="red")
    raise typer.Exit(code=1)


async def _fetch_ui_context(ctx: typer.Context) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient(base_url=ctx.obj["base_url"], follow_redirects=True) as client:
        response = await client.get("/", params={"format": "json"}, headers=headers)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _handle_http_error(exc)
        return response.json()


def _describe_paper(paper: dict[str, Any]) -> str:
    title = paper.get("title") or "Untitled paper"
    pieces = [title.strip() or "Untitled paper"]
    score = paper.get("priority_score_display") or "—"
    votes = paper.get("priority_votes")
    votes_text = f"{votes} votes" if votes is not None else "no votes"
    pieces.append(f"{paper.get('priority_label', 'Unranked')} ({score}, {votes_text})")
    assigned = paper.get("assigned_reader_username")
    if assigned:
        pieces.append(f"assigned to {assigned}")
    if paper.get("ready_to_present"):
        pieces.append("ready to present")
    url = paper.get("paper_url")
    if url:
        pieces.append(url)
    return " · ".join(pieces)


def _print_section(title: str, papers: list[dict[str, Any]]) -> None:
    if not papers:
        typer.echo(f"{title}: none")
        return
    typer.echo(f"{title} ({len(papers)}):")
    for paper in papers:
        paper_id = paper.get("id")
        id_label = f"[{paper_id}]" if paper_id is not None else "[?]"
        typer.echo(f"  {id_label} {_describe_paper(paper)}")


@cli.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    host: str = typer.Option(DEFAULT_HOST, help="Server host."),
    port: int = typer.Option(DEFAULT_PORT, help="Server port."),
    scheme: str = typer.Option(DEFAULT_SCHEME, help="Protocol scheme."),
    base_url: str | None = typer.Option(None, help="Full base URL (overrides host/port)."),
    session_file: Path = typer.Option(DEFAULT_SESSION_FILE, help="Session file path."),
) -> None:
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj["base_url"] = _resolve_base_url(base_url, scheme, host, port)
    ctx.obj["session_file"] = session_file.expanduser()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@cli.command()
def login(
    ctx: typer.Context,
    username: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True),
    store: bool = typer.Option(True, "--store/--no-store", help="Persist the session for later commands."),
) -> None:
    tokens = asyncio.run(_fetch_tokens(ctx, username, password))
    typer.secho(f"Logged in as {username}", fg="green")
    if store:
        _save_session(ctx.obj["session_file"], username, tokens)
        typer.secho(f"Session persisted at {ctx.obj['session_file']}", fg="green")


@cli.command()
def logout(ctx: typer.Context) -> None:
    if _clear_session(ctx.obj["session_file"]):
        typer.secho("Session cleared", fg="green")
    else:
        typer.echo("No session to clear")


@cli.command()
def session(ctx: typer.Context) -> None:
    session_data = _load_session(ctx.obj["session_file"])
    if session_data:
        typer.echo(f"Logged in as {session_data.get('username')} using {ctx.obj['base_url']}")
    else:
        typer.echo("Not logged in")


@cli.command()
def queue(
    ctx: typer.Context,
    show_backlog: bool = typer.Option(True, "--show-backlog/--hide-backlog", help="Include backlog papers."),
    show_housekeeping: bool = typer.Option(False, help="Show archived/covered papers."),
) -> None:
    payload = asyncio.run(_fetch_ui_context(ctx))
    next_paper = payload.get("next_paper")
    if next_paper:
        paper_id = next_paper.get("id")
        id_label = f"[{paper_id}]" if paper_id is not None else "[?]"
        typer.echo("Next paper:")
        typer.echo(f"  {id_label} {_describe_paper(next_paper)}")
    _print_section("Upcoming queue", payload.get("queue_papers", []))
    if show_backlog:
        _print_section("Backlog", payload.get("backlog_papers", []))
    if show_housekeeping:
        _print_section("Housekeeping queue", payload.get("housekeeping_queue_papers", []))
        _print_section("Archived", payload.get("archived_papers", []))
        _print_section("Covered", payload.get("covered_papers", []))


def _token_from_credentials(
    ctx: typer.Context, username: str | None, password: str | None
) -> str:
    try:
        return asyncio.run(_resolve_access_token(ctx, username, password))
    except typer.Exit:
        raise


async def _post_action(
    ctx: typer.Context,
    path: str,
    data: dict[str, Any] | None = None,
    access_token: str | None = None,
) -> None:
    headers: dict[str, str] = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    async with httpx.AsyncClient(base_url=ctx.obj["base_url"], follow_redirects=True) as client:
        response = await client.post(path, data=data or {}, headers=headers)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _handle_http_error(exc)


def _require_password_for_username(username: str | None, password: str | None) -> str | None:
    if username and password is None:
        return typer.prompt("Password", hide_input=True)
    return password


@cli.command()
def register(
    ctx: typer.Context,
    title: str = typer.Option(..., prompt=True),
    paper_url: str | None = typer.Option(None, help="Optional link for the paper."),
    username: str | None = typer.Option(None, "-u", "--username", help="Username for authentication."),
    password: str | None = typer.Option(None, "-p", "--password", help="Password for authentication."),
) -> None:
    password = _require_password_for_username(username, password)
    access_token = _token_from_credentials(ctx, username, password)
    payload = {"title": title}
    if paper_url:
        payload["paper_url"] = paper_url
    asyncio.run(_post_action(ctx, "/papers", data=payload, access_token=access_token))
    typer.secho("Paper registered", fg="green")


@cli.command()
def vote(
    ctx: typer.Context,
    paper_id: int = typer.Option(..., help="Paper identifier."),
    priority: int = typer.Option(..., help="Priority level 1-4."),
    username: str | None = typer.Option(None, "-u", "--username", help="Reader username."),
    password: str | None = typer.Option(None, "-p", "--password", help="Reader password."),
) -> None:
    password = _require_password_for_username(username, password)
    access_token = _token_from_credentials(ctx, username, password)
    asyncio.run(_post_action(ctx, f"/papers/{paper_id}/vote", data={"priority": priority}, access_token=access_token))
    typer.secho("Vote submitted", fg="green")


def _post_housekeeping(
    ctx: typer.Context,
    action_path: str,
    paper_id: int,
    panel: str | None,
    access_token: str,
    panel_required: bool,
) -> None:
    path = f"/papers/{paper_id}/{action_path}"
    data = {"panel": panel} if panel_required and panel else None
    asyncio.run(_post_action(ctx, path, data=data, access_token=access_token))
    typer.secho(f"Action completed: {action_path} on paper {paper_id}", fg="green")


@cli.command()
def housekeeping(
    ctx: typer.Context,
    action: str = typer.Option("status", help="Action to apply (status, assign, unassign, ready, not-ready, archive, cover, unarchive, delete)."),
    paper_id: int | None = typer.Option(None, help="ID of the paper to act on."),
    panel: str = typer.Option("refresh", help="Panel identifier for HTMX interactions."),
    username: str | None = typer.Option(None, "-u", "--username", help="Reader username."),
    password: str | None = typer.Option(None, "-p", "--password", help="Reader password."),
) -> None:
    normalized = action.lower()
    if normalized == "status":
        payload = asyncio.run(_fetch_ui_context(ctx))
        _print_section("Archived", payload.get("archived_papers", []))
        _print_section("Covered", payload.get("covered_papers", []))
        return
    if normalized not in HOUSEKEEPING_ACTION_MAP:
        typer.secho("Unknown action", fg="red")
        raise typer.Exit(code=1)
    if paper_id is None:
        typer.secho("paper-id is required for housekeeping actions", fg="red")
        raise typer.Exit(code=1)
    password = _require_password_for_username(username, password)
    access_token = _token_from_credentials(ctx, username, password)
    action_path = HOUSEKEEPING_ACTION_MAP[normalized]
    panel_needed = normalized in PANEL_REQUIRED_ACTIONS
    _post_housekeeping(ctx, action_path, paper_id, panel, access_token, panel_needed)


if __name__ == "__main__":
    cli()
