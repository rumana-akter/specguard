"""Locations of the bundled example repository and evaluation data."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    env = os.environ.get("SPECGUARD_HOME")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def default_repo() -> Path:
    return project_root() / "examples" / "sensorhub"


def default_eval_dir() -> Path:
    return project_root() / "eval"
