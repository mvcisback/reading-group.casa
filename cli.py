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
PRIORITY_LABEL_VALUES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
PRIORITY_COLOR_MAP = {
    "Critical": "red",
    "High": "yellow",
    "Medium": "green",
    "Low": "cyan",
    "Unranked": "white",
}

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


async def _fetch_ui_context(ctx: typer.Context, access_token: str | None = None) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    async with httpx.AsyncClient(base_url=ctx.obj["base_url"], follow_redirects=True) as client:
        response = await client.get("/", params={"format": "json"}, headers=headers)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _handle_http_error(exc)
        return response.json()


def _style_priority_label(label: str) -> str:
    color = PRIORITY_COLOR_MAP.get(label, "white")
    bold = color in {"red", "yellow"}
    return typer.style(label, fg=color, bold=bold)


def _describe_paper(paper: dict[str, Any]) -> str:
    title = paper.get("title") or "Untitled paper"
    return (title.strip() or "Untitled paper")


SECTION_BORDER = "─" * 36
SPARKLINE_LEVELS = "▁▂▃▄▅▆▇█"


def _sparkline_for_paper(paper: dict[str, Any]) -> str:
    counts = [paper.get(f"priority_count_{level}", 0) or 0 for level in range(1, 5)]
    total = sum(counts)
    if total == 0:
        return "────"
    max_index = len(SPARKLINE_LEVELS) - 1
    bars = []
    for count in counts:
        ratio = count / total
        index = min(max_index, round(ratio * max_index))
        bars.append(SPARKLINE_LEVELS[index])
    return "".join(bars)


def _paper_status_tags(paper: dict[str, Any]) -> str:
    tags = []
    assigned = paper.get("assigned_reader_username")
    if assigned:
        tags.append(f"👤 {assigned}")
    else:
        tags.append("⚠️ unassigned")
    if paper.get("ready_to_present"):
        tags.append("✅ ready")
    return " | ".join(tags)


def _queue_metrics(papers: list[dict[str, Any]]) -> str:
    if not papers:
        return ""
    total_votes = sum(paper.get("priority_votes") or 0 for paper in papers)
    score_sum = sum((paper.get("priority_score") or 0) for paper in papers)
    avg_score = score_sum / len(papers)
    assigned = sum(1 for paper in papers if paper.get("assigned_reader_username"))
    ready = sum(1 for paper in papers if paper.get("ready_to_present"))
    return f"votes {total_votes} · avg {avg_score:.1f} · assigned {assigned} · ready {ready}"


def _find_paper_by_id(payload: dict[str, Any], paper_id: int) -> dict[str, Any] | None:
    for paper in payload.get("papers", []):
        if paper.get("id") == paper_id:
            return paper
    return None


def _format_histogram(paper: dict[str, Any]) -> str:
    histogram = paper.get("priority_histogram") or []
    segments = []
    for bucket in histogram:
        label = bucket.get("label", "?")
        count = bucket.get("count", 0)
        percent = bucket.get("percent", 0)
        segments.append(f"{label[0]}:{count}({percent:.0f}%)")
    return " ".join(segments)


def _format_paper_line(paper: dict[str, Any], *, show_details: bool = False) -> str:
    paper_id = paper.get("id")
    id_label = f"[{paper_id}]" if paper_id is not None else "[?]"
    title = _describe_paper(paper)
    truncated_title = title if len(title) <= 34 else f"{title[:31]}..."
    priority_label = paper.get("priority_label", "Unranked")
    styled_priority = _style_priority_label(priority_label)
    score = paper.get("priority_score_display") or "—"
    votes = paper.get("priority_votes") or 0
    sparkline = _sparkline_for_paper(paper)
    status = _paper_status_tags(paper)
    base = (
        f"● {id_label:<5} {truncated_title:<34} {styled_priority:<12} "
        f"{score:>4} {sparkline} {status}"
    )
    if show_details:
        base += f" ({votes} votes)"
        url = paper.get("paper_url")
        if url:
            base += f" → {typer.style(url, fg='blue', underline=True)}"
    return base


def _print_header(text: str, color: str = "bright_white") -> None:
    typer.secho(f"┌ {text} {SECTION_BORDER}", fg=color, bold=True)


def _print_footer() -> None:
    typer.secho(f"└{SECTION_BORDER}{SECTION_BORDER}", fg="bright_black")


def _print_section(title: str, papers: list[dict[str, Any]]) -> None:
    if not papers:
        typer.secho(f"{title}: none", fg="bright_black")
        return
    _print_header(f"{title} ({len(papers)})", color="cyan")
    for paper in papers:
        typer.echo(f"  {_format_paper_line(paper)}")
    _print_footer()


def _display_queue_payload(
    payload: dict[str, Any],
    show_backlog: bool,
    show_housekeeping: bool,
) -> None:
    next_paper = payload.get("next_paper")
    if next_paper:
        _print_header("Next paper:", color="bright_green")
        typer.echo(f"  {_format_paper_line(next_paper)}")
        _print_footer()
    queue = payload.get("queue_papers", [])
    metrics = _queue_metrics(queue)
    if metrics:
        typer.secho(f"╞ {metrics}", fg="bright_white", bold=True)
    _print_section("Upcoming queue", queue)
    if show_backlog:
        backlog = payload.get("backlog_papers", [])
        _print_section("Backlog", backlog)
    if show_housekeeping:
        _print_section("Housekeeping queue", payload.get("housekeeping_queue_papers", []))
        _print_section("Archived", payload.get("archived_papers", []))
        _print_section("Covered", payload.get("covered_papers", []))


def _show_queue(ctx: typer.Context, show_backlog: bool = True, show_housekeeping: bool = False) -> None:
    payload = asyncio.run(_fetch_ui_context(ctx))
    _display_queue_payload(payload, show_backlog=show_backlog, show_housekeeping=show_housekeeping)


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
        _show_queue(ctx)


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
    _show_queue(ctx, show_backlog=show_backlog, show_housekeeping=show_housekeeping)


def _token_from_credentials(
    ctx: typer.Context, username: str | None, password: str | None
) -> str:
    try:
        return asyncio.run(_resolve_access_token(ctx, username, password))
    except typer.Exit:
        raise


async def _perform_action_request(
    ctx: typer.Context,
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    access_token: str | None = None,
) -> None:
    headers: dict[str, str] = {}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    async with httpx.AsyncClient(base_url=ctx.obj["base_url"], follow_redirects=True) as client:
        response = await client.request(method, path, data=data or {}, headers=headers)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _handle_http_error(exc)


async def _post_action(
    ctx: typer.Context,
    path: str,
    data: dict[str, Any] | None = None,
    access_token: str | None = None,
) -> None:
    await _perform_action_request(ctx, "POST", path, data=data, access_token=access_token)


def _require_password_for_username(username: str | None, password: str | None) -> str | None:
    if username and password is None:
        return typer.prompt("Password", hide_input=True)
    return password


def _parse_priority_value(value: str) -> int | None:
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized.isdigit():
        numeric = int(normalized)
        if 1 <= numeric <= 4:
            return numeric
    return PRIORITY_LABEL_VALUES.get(normalized)


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"{value!r} is not a boolean value")


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
    show: bool = typer.Option(False, "--show", help="List unvoted papers without casting new votes."),
    username: str | None = typer.Option(None, "-u", "--username", help="Reader username."),
    password: str | None = typer.Option(None, "-p", "--password", help="Reader password."),
) -> None:
    password = _require_password_for_username(username, password)
    access_token = _token_from_credentials(ctx, username, password)
    payload = asyncio.run(_fetch_ui_context(ctx, access_token=access_token))
    papers = payload.get("papers", [])
    unvoted = [paper for paper in papers if paper.get("user_priority") is None]
    if not unvoted:
        typer.secho("No unvoted papers remaining", fg="green")
        return
    if show:
        _print_header("Papers awaiting your vote:", color="bright_magenta")
        for paper in unvoted:
            typer.echo(f"  {_format_paper_line(paper)}")
        _print_footer()
        return
    for paper in unvoted:
        paper_id = paper.get("id")
        typer.echo(f"Voting for {_format_paper_line(paper)}")
        while True:
            response = (
                typer.prompt(
                    "Priority (1-4, Low/Medium/High/Critical; skip/quit to move on)",
                    default="",
                    show_default=False,
                )
                .strip()
            )
            if not response or response.lower() in {"skip", "s"}:
                typer.echo("Skipping paper")
                break
            if response.lower() in {"quit", "q"}:
                typer.secho("Stopped voting session", fg="yellow")
                return
            priority_value = _parse_priority_value(response)
            if priority_value is None:
                typer.secho("Enter 1-4 or priority label (Low, Medium, High, Critical)", fg="yellow")
                continue
            if paper_id is None:
                typer.secho("Paper missing id; cannot vote", fg="red")
                break
            asyncio.run(
                _post_action(
                    ctx,
                    f"/papers/{paper_id}/vote",
                    data={"priority": priority_value},
                    access_token=access_token,
                )
            )
            typer.secho(f"Voted priority {priority_value}", fg="green")
            break


@cli.command()
def show(
    ctx: typer.Context,
    paper_id: int = typer.Argument(..., help="Paper id to inspect."),
) -> None:
    payload = asyncio.run(_fetch_ui_context(ctx))
    paper = _find_paper_by_id(payload, paper_id)
    if paper is None:
        typer.secho("Paper not found", fg="red")
        raise typer.Exit(code=1)
    _print_header(f"Paper {paper_id}", color="bright_magenta")
    typer.echo(f"  {_format_paper_line(paper, show_details=True)}")
    status = _paper_status_tags(paper)
    if status:
        typer.echo(f"  Status: {status}")
    histogram = _format_histogram(paper)
    if histogram:
        typer.echo(f"  Histogram: {histogram}")
    _print_footer()


MODIFY_ACTIONS_HELP = (
    "Actions as key:value pairs (e.g., pri:High, archived:True).\n"
    "Valid keys:\n"
    "  pri/priority=<1-4|low|medium|high|critical> (leave value empty to clear the vote)\n"
    "  archived/archive=<True|False>\n"
    "  cover/covered=<True|False>\n"
    "  ready=<True|False>\n"
    "  assign=<True|False>\n"
    "  delete=True"
)


@cli.command()
def modify(
    ctx: typer.Context,
    paper_id: int = typer.Argument(..., help="Paper id to modify."),
    actions: list[str] = typer.Argument(..., help=MODIFY_ACTIONS_HELP),
    username: str | None = typer.Option(None, "-u", "--username", help="Reader username."),
    password: str | None = typer.Option(None, "-p", "--password", help="Reader password."),
) -> None:
    if not actions:
        typer.secho("Provide at least one action", fg="red")
        raise typer.Exit(code=1)
    password = _require_password_for_username(username, password)
    access_token = _token_from_credentials(ctx, username, password)
    for action in actions:
        if ":" not in action:
            typer.secho("Actions must be in key:value format", fg="red")
            raise typer.Exit(code=1)
        key, value = action.split(":", 1)
        key = key.strip().lower()
        raw_value = value.strip()
        path: str | None = None
        label: str | None = None
        data: dict[str, Any] | None = None
        method = "POST"
        try:
            if key in {"pri", "priority"}:
                if raw_value == "":
                    method = "DELETE"
                    path = f"/papers/{paper_id}/vote"
                    label = "priority cleared"
                else:
                    priority_value = _parse_priority_value(raw_value)
                    if priority_value is None:
                        typer.secho("Unknown priority label", fg="red")
                        raise typer.Exit(code=1)
                    path = f"/papers/{paper_id}/vote"
                    data = {"priority": priority_value}
                    label = f"priority {priority_value}"
            elif not raw_value:
                typer.secho("Provide a value for every action", fg="red")
                raise typer.Exit(code=1)
            elif key in {"archived", "archive"}:
                bool_value = _parse_bool(raw_value)
                path = f"/papers/{paper_id}/{'archive' if bool_value else 'unarchive'}"
                label = "archived" if bool_value else "restored"
            elif key in {"cover", "covered"}:
                bool_value = _parse_bool(raw_value)
                path = (
                    f"/papers/{paper_id}/mark-covered" if bool_value else f"/papers/{paper_id}/unarchive"
                )
                label = "marked as covered" if bool_value else "restored"
            elif key == "ready":
                bool_value = _parse_bool(raw_value)
                path = f"/papers/{paper_id}/{'mark-ready' if bool_value else 'mark-not-ready'}"
                label = "ready" if bool_value else "not ready"
            elif key == "assign":
                bool_value = _parse_bool(raw_value)
                path = f"/papers/{paper_id}/{'assign' if bool_value else 'unassign'}"
                label = "assigned" if bool_value else "unassigned"
            elif key == "delete":
                bool_value = _parse_bool(raw_value)
                if not bool_value:
                    typer.echo("Ignoring delete=False")
                    continue
                path = f"/papers/{paper_id}/delete"
                label = "deleted"
            else:
                typer.secho(f"Unknown action '{key}'", fg="red")
                raise typer.Exit(code=1)
        except ValueError as exc:
            typer.secho(str(exc), fg="red")
            raise typer.Exit(code=1)
        if path is None:
            continue
        asyncio.run(_perform_action_request(ctx, method, path, data=data, access_token=access_token))
        typer.secho(f"{label or 'Updated'} for paper {paper_id}", fg="green")


if __name__ == "__main__":
    cli()
