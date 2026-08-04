"""
Description: PHRAK Agent — startup banner and hacker-aesthetic terminal styling.
Author: Aleksa Zatezalo
Date Created: 08-01-2026
"""

from __future__ import annotations

import os
import sys

from . import __version__

# ------------------------------------------------------------------- colors
_ENABLED = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

# Raw ANSI codes, kept so colors can be toggled at runtime (--no-color).
_CODES = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "GREEN": "\033[32m",
    "BGREEN": "\033[92m",
    "CYAN": "\033[36m",
    "BCYAN": "\033[96m",
    "RED": "\033[91m",
    "GREY": "\033[90m",
    "WHITE": "\033[97m",
    "MAGENTA": "\033[95m",
    "YELLOW": "\033[93m",
}


def _c(code: str) -> str:
    return code if _ENABLED else ""


def _refresh() -> None:
    """Recompute the module-level color constants from _ENABLED.

    Most call sites import these names lazily (inside functions), so a refresh
    propagates to nearly all output; a `--no-color` change takes effect for
    everything printed afterwards."""
    g = globals()
    for name, code in _CODES.items():
        g[name] = _c(code)


# Initialise the public color constants (RESET, GREEN, BGREEN, ...).
RESET = BOLD = DIM = GREEN = BGREEN = CYAN = BCYAN = RED = GREY = WHITE = MAGENTA = (
    YELLOW
) = ""
_refresh()


def set_color(enabled: bool) -> None:
    """Force color on/off at runtime (e.g. --no-color)."""
    global _ENABLED
    _ENABLED = bool(enabled)
    _refresh()


# ANSI-Shadow "PHRAK AGENT"
_ART = r"""
 ██████╗ ██╗  ██╗██████╗  █████╗ ██╗  ██╗
 ██╔══██╗██║  ██║██╔══██╗██╔══██╗██║ ██╔╝
 ██████╔╝███████║██████╔╝███████║█████╔╝      
 ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██╔═██╗
 ██║     ██║  ██║██║  ██║██║  ██║██║  ██╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
"""


def _rule(char: str = "─", color: str = GREEN, width: int = 52) -> str:
    return f"{color}{char * width}{RESET}"


def print_banner(app=None) -> None:
    """Full boot banner. Pass the built App to show live status."""
    lines = []
    lines.append("")
    lines.append(_rule("═", BGREEN))

    for row in _ART.strip("\n").splitlines():
        lines.append(f"{BGREEN}{BOLD}{row}{RESET}")

    lines.append(_rule("═", BGREEN))

    if app is not None:
        cfg = app.config
        agents = app.registry.names()
        status = [
            f"{CYAN}▸{RESET} model      {WHITE}{cfg.llm.provider}:{cfg.llm.model}{RESET}",
            f"{CYAN}▸{RESET} agents     {WHITE}{len(agents)} online{RESET} "
            f"{GREY}[{', '.join(agents)}]{RESET}",
            f"{CYAN}▸{RESET} workspace  {WHITE}{cfg.paths.workspace}{RESET}",
        ]
        lines.append(f"{BGREEN}  [ system online ]{RESET}")
        lines.extend("  " + s for s in status)
        lines.append(_rule("─", BGREEN))
        lines.append(
            f"  {DIM}code review · threat modeling · security test cases{RESET}"
        )
    lines.append("")
    print("\n".join(lines))


def mini_banner() -> str:
    """One-liner for non-interactive commands."""
    return f"{BGREEN}{BOLD}Phrak Agent{RESET} {GREY}v{__version__}{RESET}"


def phrak_print(msg: str) -> None:
    """Styled status line, e.g. for step progress."""
    print(f"{GREEN}[{BGREEN}phrak{GREEN}]{RESET} {msg}")
