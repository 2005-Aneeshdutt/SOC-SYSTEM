from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Central configuration.

    In a real deployment you would externalize these via env vars + a config system.
    """

    session_gap_minutes: int = 30
    window_minutes: int = 5
    max_sequence_len: int = 64

    # Correlation heuristics
    correlation_window_minutes: int = 20
    incident_min_signals: int = 2


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except ValueError:
        return default


@dataclass(frozen=True)
class Thresholds:
    """Thresholds and cutoffs used at inference time."""

    signal_min_score: float = 0.25
    severity_medium: float = 0.45
    severity_high: float = 0.75


THRESHOLDS = Thresholds(
    signal_min_score=_env_float("SOCLSIM_SIGNAL_MIN_SCORE", 0.25),
    severity_medium=_env_float("SOCLSIM_SEVERITY_MEDIUM", 0.45),
    severity_high=_env_float("SOCLSIM_SEVERITY_HIGH", 0.75),
)


SETTINGS = Settings(
    session_gap_minutes=_env_int("SOCLSIM_SESSION_GAP_MINUTES", 30),
    window_minutes=_env_int("SOCLSIM_WINDOW_MINUTES", 5),
    max_sequence_len=_env_int("SOCLSIM_MAX_SEQUENCE_LEN", 64),
    correlation_window_minutes=_env_int("SOCLSIM_CORRELATION_WINDOW_MINUTES", 20),
    incident_min_signals=_env_int("SOCLSIM_INCIDENT_MIN_SIGNALS", 2),
)


