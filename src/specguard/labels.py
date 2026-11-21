"""Sensitivity labels. Ordered so that a higher value means more sensitive."""

from __future__ import annotations

from enum import IntEnum


class Label(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3

    @classmethod
    def parse(cls, value: str) -> "Label":
        if not isinstance(value, str):
            raise ValueError(f"sensitivity label must be a string, got {type(value).__name__}")
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown sensitivity label: {value!r}") from None

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()
