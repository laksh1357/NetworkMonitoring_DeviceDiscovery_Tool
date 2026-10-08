"""Small, dependency-free configuration primitives."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanSettings:
    """Configuration shared by discovery and future monitoring schedulers."""

    max_workers: int = 64
    host_timeout: float = 1.0

    def __post_init__(self) -> None:
        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if self.host_timeout <= 0:
            raise ValueError("host_timeout must be greater than zero")

