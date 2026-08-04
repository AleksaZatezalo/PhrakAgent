"""Interactive-chat input helpers: readline setup and the /help renderer.

Kept out of ``cli.py`` so the command layer stays focused on dispatch. These
functions handle Tab-completion of slash commands, prefix-filtered history
navigation, persistent history, and rendering the command list.
"""

from __future__ import annotations

from .banner import CYAN, GREEN, GREY, RESET


def command_names(app) -> list[str]:
    """All slash-command names available in chat, including dynamic agents."""
    names = ["help", "agents", "ask", "run", "route",
             "clone", "config", "quit"]
    names += list(app.registry.names())
    # de-dupe while preserving order
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(n, None)
    return list(seen)


def setup_readline(app) -> list[str]:
    """Enable arrow-key history filtering + Tab autocomplete for /commands.

    Returns the list of command names so the caller can offer 'did you mean'
    suggestions. Degrades gracefully if readline is unavailable.
    """
    import difflib
    import os

    try:
        import readline
    except ImportError:  # e.g. Windows without pyreadline
        return command_names(app)

    commands = command_names(app)

    def completer(text, state):
        # Only complete when the user is typing a slash command.
        if not text.startswith("/"):
            return None
        stem = text[1:].lower()
        # exact prefix matches first, then close ("did you mean") matches
        matches = [c for c in commands if c.startswith(stem)]
        if not matches:
            matches = difflib.get_close_matches(stem, commands, n=8, cutoff=0.4)
        results = [f"/{c} " for c in matches]
        return results[state] if state < len(results) else None

    readline.set_completer(completer)
    # Treat '/' as part of the completion token so "/he<Tab>" works.
    readline.set_completer_delims(" \t\n")

    # libedit (macOS default) needs different bind syntax than GNU readline.
    if "libedit" in (getattr(readline, "__doc__", "") or ""):
        readline.parse_and_bind("bind ^I rl_complete")
        readline.parse_and_bind("bind '\\e[A' ed-search-prev-history")
        readline.parse_and_bind("bind '\\e[B' ed-search-next-history")
    else:
        readline.parse_and_bind("tab: complete")
        # Up/Down filter history by the current line prefix instead of a
        # plain chronological walk.
        readline.parse_and_bind('"\\e[A": history-search-backward')
        readline.parse_and_bind('"\\e[B": history-search-forward')

    # Persist history across sessions, under the workspace's .phrack dir.
    hist_file = str(app.config.history_file())
    try:
        os.makedirs(os.path.dirname(hist_file), exist_ok=True)
        if os.path.exists(hist_file):
            readline.read_history_file(hist_file)
        readline.set_history_length(1000)
        import atexit

        atexit.register(lambda: _save_history(readline, hist_file))
    except OSError:
        pass

    return commands


def _save_history(readline, hist_file) -> None:
    try:
        readline.write_history_file(hist_file)
    except OSError:
        pass


def chat_help(app) -> None:
    """Print the grouped list of chat slash commands."""
    groups: list[tuple[str, list[tuple[str, str]]]] = [
        ("analyze", [
            ("/ask <text>", "answer a question grounded in the codebase (RAG)"),
            ("/run <text>", "full multi-agent assessment + saved report"),
            ("/route <text>", "auto-route to the single best-fit agent"),
        ]),
        ("agents", [(f"/{n} <text>", app.registry.get(n).description)
                    for n in app.registry.names()]
                   + [("/agents [--verbose]", "list agents (and their tools)")]),
        ("system", [
            ("/clone <url> [dest] [--index]", "shallow-clone a repo to analyze"),
            ("/config [--show]", "setup wizard (or show redacted config)"),
            ("/help", "show this list"),
            ("/quit", "exit PHRAK"),
            ("<text>", "just chat — PHRAK reads code and answers, keeping context"),
        ]),
    ]
    all_rows = [r for _, rows in groups for r in rows]
    width = max(len(c) for c, _ in all_rows)
    for title, rows in groups:
        print(f"\n  {GREEN}{title}:{RESET}")
        for cmd, desc in rows:
            print(f"    {CYAN}{cmd.ljust(width)}{RESET}  {GREY}{desc}{RESET}")
    print()
