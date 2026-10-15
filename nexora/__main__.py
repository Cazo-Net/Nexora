"""Allow `python -m nexora ...` as an alternative to the `osint` command."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
