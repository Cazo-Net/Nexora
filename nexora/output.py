"""Terminal output helpers: ANSI colors and section headers.

Colors are enabled by the CLI dispatcher (see ``enable_colors``); library
modules just call ``c("green")`` / ``header("TITLE")`` and get empty
strings when colors are off.
"""
from __future__ import annotations

import os
import sys

COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}

_ENABLED = False


def _enable_windows_ansi() -> None:
    """Enable ANSI escape processing on Windows 10+ consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
    except Exception:
        pass


def enable_colors(force: bool = False) -> None:
    """Enable/disable colored output (called once by the CLI)."""
    global _ENABLED
    if force:
        _enable_windows_ansi()
    _ENABLED = bool(force)


def colors_enabled() -> bool:
    return _ENABLED


def c(name: str) -> str:
    """Return an ANSI color code, or '' when colors are disabled."""
    return COLORS.get(name, "") if _ENABLED else ""


def header(title: str) -> None:
    """Print a section header: ``== TITLE ============``."""
    width = 66
    print(f"\n{c('bold')}{c('cyan')}== {title} "
          + "=" * max(1, width - len(title) - 3)
          + f"{c('reset')}")


def sev_color(severity: str) -> str:
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return c("red")
    if s == "MEDIUM":
        return c("yellow")
    if s == "LOW":
        return c("green")
    return c("gray")
