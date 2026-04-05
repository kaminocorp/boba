"""PoC packaging — compile evidence artifacts into a directory."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from boba.core.context import HuntContext
from boba.core.models import PoCPackage

logger = logging.getLogger(__name__)


def package_poc(
    context: HuntContext,
    hunt_id: str,
    finding_id: int | None = None,
    chain_id: int | None = None,
    output_dir: str = ".",
) -> PoCPackage:
    """Compile evidence artifacts into a PoC directory.

    Creates:
    output_dir/
    ├── README.md              — summary with reproduction steps
    ├── requests/
    │   ├── 001_request.http   — HTTP request/response pairs
    │   └── ...
    └── evidence.json          — structured evidence array
    """
    out = Path(output_dir)
    requests_dir = out / "requests"
    requests_dir.mkdir(parents=True, exist_ok=True)

    package = PoCPackage(
        finding_id=finding_id,
        chain_id=chain_id,
        output_dir=str(out),
    )

    # Gather evidence and request IDs
    evidence: list[dict[str, Any]] = []
    request_ids: list[int] = []
    title = "Vulnerability PoC"
    steps: list[str] = []

    if finding_id:
        finding = context.get_finding_by_id(finding_id)
        if finding:
            title = finding.get("title", title)
            ev = finding.get("evidence")
            if isinstance(ev, list):
                evidence.extend(ev)
            rids = finding.get("request_ids", [])
            if isinstance(rids, list):
                request_ids.extend(rids)
            desc = finding.get("description", "")
            if desc:
                steps.append(desc)

    if chain_id:
        chain = context.get_chain(chain_id)
        if chain:
            title = chain.get("title", title)
            for fid in chain.get("finding_ids", []):
                finding = context.get_finding_by_id(fid)
                if finding:
                    ev = finding.get("evidence")
                    if isinstance(ev, list):
                        evidence.extend(ev)
                    rids = finding.get("request_ids", [])
                    if isinstance(rids, list):
                        request_ids.extend(rids)

    # Write HTTP dumps
    for i, rid in enumerate(request_ids, 1):
        record = context.get_http_record(rid)
        if record:
            http_text = _format_http_dump(record)
            dump_path = requests_dir / f"{i:03d}_request.http"
            try:
                dump_path.write_text(http_text, encoding="utf-8")
            except OSError as exc:
                logger.warning("Failed to write HTTP dump %s: %s", dump_path, exc)
                continue
            package.http_dumps.append({
                "request_id": rid,
                "file": str(dump_path),
                "method": record.get("method"),
                "url": record.get("url"),
                "status_code": record.get("status_code"),
            })

    # Write evidence.json
    evidence_path = out / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    # Write README.md
    readme_path = out / "README.md"
    readme_lines = [
        f"# {title}",
        "",
        "## Evidence",
        "",
        f"- {len(evidence)} evidence item(s)",
        f"- {len(package.http_dumps)} HTTP request/response pair(s)",
        "",
    ]
    if steps:
        readme_lines.append("## Reproduction Steps")
        readme_lines.append("")
        for step in steps:
            readme_lines.append(f"- {step}")
        readme_lines.append("")

    if package.http_dumps:
        readme_lines.append("## HTTP Dumps")
        readme_lines.append("")
        for dump in package.http_dumps:
            readme_lines.append(
                f"- `{dump['file']}` — {dump['method']} {dump['url']} → {dump['status_code']}"
            )
        readme_lines.append("")

    readme_path.write_text("\n".join(readme_lines), encoding="utf-8")

    return package


def _format_http_dump(record: dict[str, Any]) -> str:
    """Format an HTTP history record as a .http file (RFC 7230 style)."""
    lines: list[str] = []

    # Request
    method = record.get("method", "GET")
    url = record.get("url", "/")
    host = record.get("host", "")
    lines.append(f"{method} {url} HTTP/1.1")
    lines.append(f"Host: {host}")

    req_headers = record.get("request_headers", {})
    if isinstance(req_headers, dict):
        for k, v in req_headers.items():
            if k.lower() != "host":
                lines.append(f"{k}: {v}")

    req_body = record.get("request_body")
    if req_body:
        lines.append("")
        lines.append(str(req_body))

    lines.append("")
    lines.append("###")
    lines.append("")

    # Response
    status = record.get("status_code", 0)
    _REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
                302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
                403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
                500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable"}
    reason = _REASONS.get(status, "")
    lines.append(f"HTTP/1.1 {status} {reason}".rstrip())

    resp_headers = record.get("response_headers", {})
    if isinstance(resp_headers, dict):
        for k, v in resp_headers.items():
            lines.append(f"{k}: {v}")

    resp_body = record.get("response_body")
    if resp_body:
        lines.append("")
        # Truncate large bodies
        body_str = str(resp_body)
        if len(body_str) > 2000:
            body_str = body_str[:2000] + "\n... [truncated]"
        lines.append(body_str)

    return "\n".join(lines)
