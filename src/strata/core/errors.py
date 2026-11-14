"""Typed error taxonomy shared by engines, transports, and the orchestrator.

The orchestrator needs to distinguish an expected operational failure (scope,
network, budget) from a programming error. Only expected failures are contained;
unknown exceptions are surfaced unless strict stage mode is enabled.
"""

from __future__ import annotations

from dataclasses import dataclass


class StrataError(Exception):
    """Base class for expected, classified Strata failures."""

    code = "STRATA_ERROR"


class ScopeViolation(StrataError):
    code = "SCOPE_VIOLATION"


class NetworkFailure(StrataError):
    code = "NETWORK_FAILURE"


class InvalidInput(StrataError):
    code = "INVALID_INPUT"


class StageSkipped(StrataError):
    code = "STAGE_SKIPPED"


class StageFailed(StrataError):
    code = "STAGE_FAILED"


class BudgetExceeded(StrataError):
    code = "BUDGET_EXCEEDED"


@dataclass(frozen=True)
class ErrorInfo:
    code: str
    message: str
    expected: bool


def classify_exception(exc: BaseException) -> ErrorInfo:
    """Map an exception to a stable code without hiding unexpected errors."""
    message = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__

    if isinstance(exc, StrataError):
        return ErrorInfo(code=exc.code, message=str(exc) or message, expected=True)
    if isinstance(exc, PermissionError):
        return ErrorInfo(code="SCOPE_VIOLATION", message=str(exc) or message, expected=True)
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return ErrorInfo(code="NETWORK_FAILURE", message=message, expected=True)
    if isinstance(exc, OSError):
        return ErrorInfo(code="NETWORK_FAILURE", message=message, expected=True)
    if isinstance(exc, ValueError):
        return ErrorInfo(code="INVALID_INPUT", message=message, expected=True)
    if isinstance(exc, RuntimeError):
        return ErrorInfo(code="STAGE_FAILED", message=message, expected=True)
    return ErrorInfo(code="UNEXPECTED", message=message, expected=False)


__all__ = [
    "BudgetExceeded",
    "ErrorInfo",
    "InvalidInput",
    "NetworkFailure",
    "ScopeViolation",
    "StageFailed",
    "StageSkipped",
    "StrataError",
    "classify_exception",
]
