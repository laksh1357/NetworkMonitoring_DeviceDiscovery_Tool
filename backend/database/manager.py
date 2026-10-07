"""Compatibility-facing database service boundary.

The existing SQLite implementation remains the source of truth for this
step. Keeping the adapter here gives future services a stable import path
without changing the on-disk schema or behavior.
"""

from database_manager import NetworkDatabase

__all__ = ["NetworkDatabase"]
