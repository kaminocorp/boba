"""Exception hierarchy for Boba."""


class BobaError(Exception):
    """Base exception for all Boba errors."""


class ToolNotFoundError(BobaError):
    """CLI tool binary not found in PATH."""


class ToolTimeoutError(BobaError):
    """Tool execution exceeded timeout."""


class ToolExecutionError(BobaError):
    """Tool exited with non-zero code."""

    def __init__(self, message: str, exit_code: int, stderr: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class ScopeViolationError(BobaError):
    """Target is outside the defined scope."""


class HuntNotFoundError(BobaError):
    """Hunt ID does not exist in the context database."""


class BrowserError(BobaError):
    """Error during browser automation (Playwright)."""


class SessionError(BobaError):
    """Error in session management (create, login, apply)."""


class OOBError(BobaError):
    """Error in out-of-band listener management (Interactsh)."""


class AnalysisError(BobaError):
    """Error during finding analysis (dedup, chaining, scoring)."""


class ReportError(BobaError):
    """Error during report generation or formatting."""
