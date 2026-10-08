"""Compatibility launcher for the canonical desktop application."""

from desktop.app import *  # noqa: F401,F403
from desktop.app import main


if __name__ == "__main__":
    main()
