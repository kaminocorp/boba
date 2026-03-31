"""HttpHistorySink — persistence bridge for all HTTP exchanges."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from boba.core.config import get_bodies_dir
from boba.core.context import HuntContext

logger = logging.getLogger(__name__)

# Bodies larger than this are stored as files, with a truncated preview inline.
BODY_INLINE_LIMIT = 64 * 1024  # 64 KB
BODY_PREVIEW_LIMIT = 4 * 1024  # 4 KB


class HttpHistorySink:
    """Writes HTTP exchanges to the http_history table.

    Both BrowserManager and HttpClient write through this single interface.
    Handles inline vs. file-referenced body storage.
    """

    def __init__(self, hunt_context: HuntContext, hunt_id: str):
        self._context = hunt_context
        self._hunt_id = hunt_id
        self._body_dir: Path | None = None

    def _get_body_dir(self) -> Path:
        if self._body_dir is None:
            self._body_dir = get_bodies_dir(self._hunt_id)
        return self._body_dir

    # ── Write ──

    def record(
        self,
        method: str,
        url: str,
        request_headers: dict,
        request_body: str | bytes | None,
        status_code: int | None,
        response_headers: dict | None,
        response_body: bytes | None,
        elapsed_ms: float,
        source: str = "manual",
        session_name: str | None = None,
        tool_run_id: int | None = None,
        resource_type: str | None = None,
        parent_request_id: int | None = None,
        tags: list[str] | None = None,
    ) -> int:
        """Persist one HTTP exchange. Returns the http_history row ID."""
        parsed = urlparse(url)

        # Normalize bodies to strings for storage
        req_body_str, req_body_ref = self._prepare_body(request_body, "req")
        resp_body_str, resp_body_ref = self._prepare_body(response_body, "resp")

        resp_length = len(response_body) if response_body else None
        resp_content_type = (response_headers or {}).get("content-type")

        record = {
            "method": method,
            "url": url,
            "host": parsed.hostname or "",
            "path": parsed.path or "/",
            "query": parsed.query or None,
            "source": source,
            "session_name": session_name,
            "tool_run_id": tool_run_id,
            "request_headers": request_headers or {},
            "request_body": req_body_str,
            "request_body_ref": req_body_ref,
            "content_type": (request_headers or {}).get("content-type"),
            "status_code": status_code,
            "response_headers": response_headers or {},
            "response_body": resp_body_str,
            "response_body_ref": resp_body_ref,
            "response_length": resp_length,
            "response_content_type": resp_content_type,
            "elapsed_ms": elapsed_ms,
            "resource_type": resource_type,
            "parent_request_id": parent_request_id,
            "tags": tags or [],
            "is_redirect": (status_code or 0) in (301, 302, 303, 307, 308),
            "redirect_url": (response_headers or {}).get("location"),
        }
        return self._context.insert_http_record(self._hunt_id, record)

    def _prepare_body(
        self, body: str | bytes | None, prefix: str
    ) -> tuple[str | None, str | None]:
        """Handle body storage: inline for small, file-referenced for large.

        Returns (inline_text, file_ref_path).
        """
        if body is None:
            return None, None

        if isinstance(body, str):
            body_bytes = body.encode("utf-8", errors="replace")
        else:
            body_bytes = body

        if len(body_bytes) <= BODY_INLINE_LIMIT:
            # Store inline
            return body_bytes.decode("utf-8", errors="replace"), None

        # Store in file, keep truncated preview inline
        preview = body_bytes[:BODY_PREVIEW_LIMIT].decode("utf-8", errors="replace")
        try:
            body_dir = self._get_body_dir()
            body_dir.mkdir(parents=True, exist_ok=True)
            file_path = body_dir / f"{prefix}_{uuid.uuid4().hex[:12]}.bin"
            file_path.write_bytes(body_bytes)
            return preview, str(file_path)
        except OSError as exc:
            logger.warning("Failed to write body file, storing truncated inline: %s", exc)
            return preview, None

    # ── Read ──

    def get(self, request_id: int) -> dict[str, Any] | None:
        """Get a single HTTP exchange by ID, including full body."""
        return self._context.get_http_record(request_id)

    def get_full_body(self, request_id: int, which: str = "response") -> bytes | None:
        """Read full body, from inline or file reference."""
        record = self._context.get_http_record(request_id)
        if not record:
            return None

        ref_field = f"{which}_body_ref"
        body_field = f"{which}_body" if which == "response" else "request_body"

        ref_path = record.get(ref_field)
        if ref_path:
            path = Path(ref_path)
            if path.exists():
                return path.read_bytes()

        # Fall back to inline
        inline = record.get(body_field)
        if inline:
            return inline.encode("utf-8", errors="replace") if isinstance(inline, str) else inline
        return None

    def query(
        self,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        source: str | None = None,
        session_name: str | None = None,
        path_prefix: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query HTTP history with filters."""
        return self._context.query_http_history(
            self._hunt_id,
            host=host,
            method=method,
            status_code=status_code,
            source=source,
            session_name=session_name,
            path_prefix=path_prefix,
            limit=limit,
        )

    # ── Annotate ──

    def tag(self, request_id: int, tags: list[str]) -> None:
        """Add tags to a request."""
        self._context.update_http_record_tags(request_id, tags)

    def annotate(self, request_id: int, notes: str) -> None:
        """Add notes to a request."""
        self._context.update_http_record_notes(request_id, notes)
