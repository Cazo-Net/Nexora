"""Nexora startup banner — Metasploit-style ASCII art.

The art is baked in (generated once with figlet's ``banner3`` font) so
there is no runtime dependency. Printed by both CLI entry points unless
``--json``, ``--no-banner`` or ``NEXORA_NO_BANNER`` is in effect.
"""
from __future__ import annotations

import platform
import sys

from . import __version__
from .output import c

# figlet -f banner3 "NEXORA"  (trailing spaces trimmed)
ART = """\
##    ## ######## ##     ##  #######  ########     ###
###   ## ##        ##   ##  ##     ## ##     ##   ## ##
####  ## ##         ## ##   ##     ## ##     ##  ##   ##
## ## ## ######      ###    ##     ## ########  ##     ##
##  #### ##         ## ##   ##     ## ##   ##   #########
##   ### ##        ##   ##  ##     ## ##    ##  ##     ##
##    ## ######## ##     ##  #######  ##     ## ##     ##"""

SUBTITLE = "Advanced Internet Intelligence Engine"
TAGLINE = "key-free OSINT  -  domain / IP / email / username  -  25+ sources"
REPO = "github.com/Cazo-Net/Nexora"


def _os_label() -> str:
    try:
        sysname = platform.system()
        release = platform.release()
        if sysname == "Linux":
            # spot common distros for the footer (Kali, Ubuntu, ...)
            pretty = ""
            try:
                with open("/etc/os-release", "r", encoding="utf-8",
                          errors="ignore") as fh:
                    for line in fh:
                        if line.startswith("PRETTY_NAME="):
                            pretty = line.split("=", 1)[1].strip().strip('"')
                            break
            except Exception:
                pass
            return pretty or f"Linux {release}"
        if sysname == "Windows":
            return f"Windows {release}"
        return f"{sysname} {release}"
    except Exception:
        return "unknown"


def print_banner(stream=None) -> None:
    """Print the banner (respects color state in nexora.output)."""
    out = stream or sys.stdout
    bold, cyan, magenta, gray, reset = (
        c("bold"), c("cyan"), c("magenta"), c("gray"), c("reset"))
    for line in ART.splitlines():
        print(f"{bold}{cyan}{line}{reset}", file=out)
    print(f"{bold}{magenta}  {SUBTITLE}{reset}", file=out)
    print(f"{gray}  {TAGLINE}{reset}", file=out)
    print(f"{gray}  v{__version__}  -  {_os_label()}  -  "
          f"Python {sys.version.split()[0]}  -  {REPO}{reset}", file=out)
    print(file=out)
