"""SHA-256 helpers for database-local audit log integrity verification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any


def _combine(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def canonical_event(event: dict[str, Any]) -> bytes:
    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def event_leaf_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_event(event)).hexdigest()


def merkle_root(leaf_hashes: Iterable[str]) -> str:
    frontier: dict[int, bytes] = {}
    count = 0
    for value in leaf_hashes:
        node = bytes.fromhex(value)
        level = 0
        while level in frontier:
            node = _combine(frontier.pop(level), node)
            level += 1
        frontier[level] = node
        count += 1
    return merkle_frontier_root(frontier, count)


def merkle_frontier_root(frontier: dict[int, bytes], count: int) -> str:
    if count == 0:
        if frontier:
            raise ValueError("Merkle frontier must be empty when there are no leaves")
        return hashlib.sha256(b"").hexdigest()
    expected_levels = {
        level for level in range(count.bit_length()) if count & (1 << level)
    }
    if set(frontier) != expected_levels:
        raise ValueError("Merkle frontier does not match its leaf count")
    peaks = [frontier[level] for level in sorted(frontier, reverse=True)]
    root = peaks[0]
    for peak in peaks[1:]:
        root = _combine(root, peak)
    return root.hex()
