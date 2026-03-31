# Boba V2 Implementation Plan — Interaction: Browser, HTTP & Vulnerability Testing

## 1. Overview

V2 gives agents the ability to **interact with web applications and test for vulnerabilities**. This is the critical phase that bridges passive reconnaissance (V1) with active security testing — replacing what a human does with Burp Suite + a browser.

### What V2 Delivers

| Capability | Description |
|---|---|
| Playwright browser adapter | Navigate web apps, intercept all traffic, take screenshots, extract DOM |
| HTTP request tool | Send crafted requests (Repeater), replay from history, compare responses, fuzz parameters (Intruder) |
| Session management | Login to targets, persist cookies/tokens, support multiple concurrent sessions for IDOR testing |
| OOB listener | Interactsh integration for detecting blind SSRF, blind XSS, blind command injection |
| Vulnerability testing | `test.idor`, `test.ssrf`, `test.xss`, `test.sqli`, `test.auth` |
| Nuclei adapter | Template-based scanning with custom + community templates |
| HTTP history | Full request/response persistence in SQLite for querying |
| Findings table | Structured vulnerability findings with evidence and severity |

### What an Agent Can Do After V2

```
# Login to target
boba session create <hunt-id> --name "user_a" --target https://app.acme.com
boba session login <hunt-id> user_a --url https://app.acme.com/login \
    --username alice --password secret123

# Navigate and intercept
boba browser navigate <hunt-id> --url https://app.acme.com/dashboard
boba browser extract <hunt-id>
boba browser screenshot <hunt-id> --path evidence/dashboard.png

# Send crafted requests
boba http request <hunt-id> --method GET --url https://app.acme.com/api/users/123
boba http replay <hunt-id> --request-id 42 --modify-header "Cookie: session=attacker"
boba http compare <hunt-id> --id-a 42 --id-b 43
boba http fuzz <hunt-id> --url "https://app.acme.com/api/users/FUZZ" \
    --payloads 1,2,3,100,999

# Test for vulnerabilities
boba test idor <hunt-id> --endpoint /api/users/123 --session-a user_a --session-b user_b
boba test ssrf <hunt-id> --url https://app.acme.com/proxy --param url
boba test xss <hunt-id> --url https://app.acme.com/search --param q

# Scan with Nuclei
boba scan nuclei <hunt-id> --severity high,critical

# Query everything
boba context http-history <hunt-id> --host app.acme.com --format json
boba context findings <hunt-id> --format json
```

### Architectural Shift from V1

V1 adapters are **stateless** — run a subprocess, parse output, done. V2 introduces **stateful resources** that persist across multiple tool calls:

- A **BrowserManager** owns a Playwright instance and named browser contexts
- A **SessionManager** maintains authentication state across browser and HTTP client
- An **OOBManager** keeps Interactsh listeners alive for async callback detection

These live in a new `interaction/` package — they're Python-native objects with persistent state, not CLI tool wrappers.

```
V1 Pattern:  adapter.run(targets) → ToolResult (stateless)
V2 Pattern:  manager.navigate(url) → PageInfo   (stateful, persists traffic)
```

---

## 2. Project Structure Changes

### New Files

```
src/boba/
├── interaction/                     # NEW — stateful interaction primitives
│   ├── __init__.py
│   ├── browser.py                   # BrowserManager — Playwright lifecycle
│   ├── http.py                      # HttpClient — raw HTTP requests (Repeater/Intruder)
│   ├── session.py                   # SessionManager — auth state persistence
│   ├── oob.py                       # OOBManager — Interactsh integration
│   └── history.py                   # HttpHistorySink — persistence bridge
├── adapters/
│   ├── nuclei.py                    # NEW — Nuclei BaseAdapter subclass
│   └── sqlmap.py                    # NEW — SQLmap BaseAdapter subclass
├── tools/
│   ├── vuln.py                      # NEW — test_idor, test_ssrf, test_xss, test_sqli, test_auth
│   └── scan.py                      # NEW — nuclei_scan high-level tool
└── payloads/                        # NEW — built-in payload lists
    ├── __init__.py
    ├── xss.py                       # XSS polyglots and common payloads
    ├── sqli.py                      # SQL injection payloads by DB type
    ├── ssrf.py                      # Internal IP payloads, cloud metadata URLs
    └── auth.py                      # JWT manipulation helpers
```

### Modified Files

```
src/boba/
├── core/
│   ├── context.py                   # ADD: http_history, sessions, findings, oob_listeners tables
│   ├── models.py                    # ADD: new dataclasses and enums
│   ├── errors.py                    # ADD: BrowserError, SessionError, OOBError
│   └── config.py                    # ADD: get_hunt_dir(), body storage paths
├── cli/
│   └── main.py                      # ADD: browser, http, session, scan, test command groups
└── pyproject.toml                   # ADD: playwright, httpx, pyjwt dependencies
```

### New Dependencies

```toml
# Add to pyproject.toml [project] dependencies
dependencies = [
    # ... existing ...
    "playwright>=1.40",       # Browser automation
    "httpx>=0.27",            # Async HTTP client for raw requests
    "pyjwt[crypto]>=2.8",    # JWT manipulation for auth testing
]

[project.optional-dependencies]
# Interactsh is optional — only needed for OOB testing
oob = ["interactsh-py>=0.1"]  # or use binary discovery
```

Post-install hook for Playwright browsers:
```bash
playwright install chromium
```

---

## 3. New SQLite Schema

> Extends `src/boba/core/context.py`

### 3.1 HTTP History Table

This is the V2 equivalent of Burp Suite's HTTP History tab — every request/response exchanged with any target, from any source (browser, HTTP client, replays, fuzzing).

```sql
CREATE TABLE IF NOT EXISTS http_history (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id               TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    session_name          TEXT,
    tool_run_id           INTEGER REFERENCES tool_runs(id),
    source                TEXT NOT NULL DEFAULT 'manual',

    -- Request
    method                TEXT NOT NULL,
    url                   TEXT NOT NULL,
    host                  TEXT NOT NULL,
    path                  TEXT NOT NULL DEFAULT '/',
    query                 TEXT,
    request_headers       TEXT NOT NULL DEFAULT '{}',
    request_body          TEXT,
    request_body_ref      TEXT,
    content_type          TEXT,

    -- Response
    status_code           INTEGER,
    response_headers      TEXT DEFAULT '{}',
    response_body         TEXT,
    response_body_ref     TEXT,
    response_length       INTEGER,
    response_content_type TEXT,

    -- Metadata
    elapsed_ms            REAL,
    tls_version           TEXT,
    ip_address            TEXT,
    resource_type         TEXT,
    is_redirect           INTEGER DEFAULT 0,
    redirect_url          TEXT,

    -- Correlation
    parent_request_id     INTEGER REFERENCES http_history(id),
    tags                  TEXT DEFAULT '[]',
    notes                 TEXT,

    timestamp             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_hist_hunt       ON http_history(hunt_id);
CREATE INDEX IF NOT EXISTS idx_http_hist_host       ON http_history(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_http_hist_status     ON http_history(hunt_id, status_code);
CREATE INDEX IF NOT EXISTS idx_http_hist_session    ON http_history(hunt_id, session_name);
CREATE INDEX IF NOT EXISTS idx_http_hist_source     ON http_history(hunt_id, source);
CREATE INDEX IF NOT EXISTS idx_http_hist_method_url ON http_history(hunt_id, method, url);
CREATE INDEX IF NOT EXISTS idx_http_hist_timestamp  ON http_history(hunt_id, timestamp);
```

**Source values:** `browser`, `http_client`, `replay`, `fuzz`, `test_idor`, `test_ssrf`, `test_xss`, `test_sqli`, `test_auth`, `nuclei`

**Large body handling:** Bodies under 64KB are stored inline in `response_body`/`request_body`. Bodies over 64KB are written to `~/.boba/hunts/<hunt_id>/bodies/<request_id>.bin` and referenced via `*_body_ref`. The inline field stores a truncated preview (first 4KB) for quick agent queries without file I/O.

### 3.2 Sessions Table

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    target_url       TEXT NOT NULL,
    auth_method      TEXT NOT NULL DEFAULT 'form',
    cookies_json     TEXT NOT NULL DEFAULT '{}',
    headers_json     TEXT NOT NULL DEFAULT '{}',
    tokens_json      TEXT NOT NULL DEFAULT '{}',
    storage_state    TEXT,
    is_valid         INTEGER DEFAULT 1,
    created_at       TEXT NOT NULL,
    last_used_at     TEXT NOT NULL,
    UNIQUE(hunt_id, name)
);
```

### 3.3 Findings Table

```sql
CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    finding_type     TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'info',
    title            TEXT NOT NULL,
    description      TEXT,
    url              TEXT,
    endpoint         TEXT,
    parameter        TEXT,
    evidence         TEXT,
    request_ids      TEXT DEFAULT '[]',
    tool_run_id      INTEGER REFERENCES tool_runs(id),
    confirmed        INTEGER DEFAULT 0,
    false_positive   INTEGER DEFAULT 0,
    reported         INTEGER DEFAULT 0,
    template_id      TEXT,
    tags             TEXT DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE(hunt_id, finding_type, url, COALESCE(parameter, ''))
);

CREATE INDEX IF NOT EXISTS idx_findings_hunt     ON findings(hunt_id);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(hunt_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(hunt_id, severity);
```

**Note:** Based on V1 learnings, the UNIQUE constraint with COALESCE will need to use `NOT NULL DEFAULT ''` instead. Fix during implementation.

### 3.4 OOB Listeners Table

```sql
CREATE TABLE IF NOT EXISTS oob_listeners (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    listener_id      TEXT NOT NULL,
    callback_domain  TEXT NOT NULL,
    purpose          TEXT,
    test_payload     TEXT,
    target_url       TEXT,
    parameter        TEXT,
    interactions     TEXT DEFAULT '[]',
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    UNIQUE(hunt_id, listener_id)
);
```

---

## 4. HttpHistorySink — The Persistence Bridge

> File: `src/boba/interaction/history.py`

Both the BrowserManager and HttpClient write through this single interface. It handles inline vs. file-referenced body storage, and provides query methods for the CLI and vuln testing tools.

```python
class HttpHistorySink:
    """Writes HTTP exchanges to the http_history table."""

    def __init__(self, hunt_context: HuntContext, hunt_id: str):
        self._context = hunt_context
        self._hunt_id = hunt_id
        self._body_dir = get_hunt_dir(hunt_id) / "bodies"

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
        # If body > 64KB: write to file, store path in *_body_ref, truncate inline
        ...

    # ── Read ─���

    def get(self, request_id: int) -> dict[str, Any]:
        """Get a single HTTP exchange by ID, including full body."""
        ...

    def get_full_body(self, request_id: int, which: str = "response") -> bytes | None:
        """Read full body, from inline or file reference."""
        ...

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
        ...

    # ── Annotate ──

    def tag(self, request_id: int, tags: list[str]) -> None:
        """Add tags to a request (e.g., 'interesting', 'auth', 'idor-evidence')."""
        ...

    def annotate(self, request_id: int, notes: str) -> None:
        """Add notes to a request."""
        ...
```

---

## 5. BrowserManager — Playwright Adapter

> File: `src/boba/interaction/browser.py`

This is the most complex piece in V2. It replaces what a human does with Chrome + Burp Proxy — browse a web app, intercept all traffic, interact with pages, capture evidence.

### 5.1 Architecture: Persistent Contexts via Manager

The agent calls `navigate()`, then `extract()`, then `screenshot()` — all must share the same browser session. The `BrowserManager` owns the Playwright lifecycle and vends **named browser contexts** (one per session or a default).

```
BrowserManager
├── Playwright instance (one)
├── Browser instance (one Chromium)
├── Named BrowserContexts
│   ├── "default"  — unauthenticated browsing
│   ├── "user_a"   — session for User A (cookies injected)
│   └── "user_b"   — session for User B (IDOR testing)
└── HttpHistorySink (captures ALL traffic from all contexts)
```

### 5.2 Traffic Interception

**Strategy:** Use Playwright's `page.route("**/*", handler)` for request interception combined with `page.on("response", handler)` for response capture. This gives us the full request/response pair including headers, body, and timing.

```python
async def _setup_interception(self, page: Page, context_name: str) -> None:
    """Register route handler to capture all traffic."""

    async def _on_route(route):
        request = route.request
        # Capture request details
        req_data = {
            "method": request.method,
            "url": request.url,
            "headers": await request.all_headers(),
            "body": request.post_data,
            "resource_type": request.resource_type,
        }
        # Continue the request (don't block it)
        await route.continue_()

    async def _on_response(response):
        # Capture response details
        try:
            body = await response.body()
        except Exception:
            body = None
        self._sink.record(
            method=response.request.method,
            url=response.url,
            request_headers=await response.request.all_headers(),
            request_body=response.request.post_data,
            status_code=response.status,
            response_headers=await response.all_headers(),
            response_body=body,
            elapsed_ms=response.request.timing.get("responseEnd", 0),
            source="browser",
            session_name=context_name if context_name != "default" else None,
            resource_type=response.request.resource_type,
        )

    await page.route("**/*", _on_route)
    page.on("response", _on_response)
```

**Why route interception, not HAR:** HAR is a post-hoc file format — you get it after the session ends. Route interception gives real-time persistence (each request is written to SQLite as it happens), per-request correlation with test payloads, and the ability to modify requests in-flight (needed for V3 advanced testing).

### 5.3 Return Types

```python
@dataclass
class PageInfo:
    """Returned by navigate() — summary the agent reasons over."""
    url: str
    final_url: str           # After redirects
    status_code: int
    title: str
    content_type: str
    headers: dict[str, str]
    cookies: list[dict[str, Any]]
    timing_ms: float
    requests_captured: int   # How many HTTP exchanges were intercepted

@dataclass
class DOMExtraction:
    """Returned by extract() — structured DOM data for the agent."""
    url: str
    title: str
    forms: list[dict[str, Any]]        # {action, method, inputs: [{name, type, value}]}
    links: list[dict[str, str]]         # {href, text}
    scripts: list[dict[str, str]]       # {src} for external, {hash} for inline
    meta: dict[str, str]                # Meta tags
    comments: list[str]                 # HTML comments (often leak info)
    inputs: list[dict[str, Any]]        # All input/textarea/select elements
    text_content: str                    # Truncated innerText
```

### 5.4 Interface

```python
class BrowserManager:

    def __init__(self, config: BrowserConfig, sink: HttpHistorySink): ...

    async def start(self) -> None:
        """Launch Playwright + Chromium."""

    async def stop(self) -> None:
        """Close all contexts, browser, Playwright."""

    async def get_or_create_context(
        self, name: str = "default",
        cookies: list[dict] | None = None,
        storage_state: dict | None = None,
    ) -> BrowserContext:
        """Get existing or create new named browser context."""

    async def navigate(
        self, url: str,
        context_name: str = "default",
        wait_until: str = "networkidle",
    ) -> PageInfo:
        """Navigate to URL, wait for load, return page info."""

    async def screenshot(
        self, path: str | Path,
        context_name: str = "default",
        full_page: bool = True,
    ) -> Path:
        """Capture screenshot for evidence/PoC."""

    async def extract(
        self, context_name: str = "default",
    ) -> DOMExtraction:
        """Extract structured DOM data from current page."""

    async def execute_js(
        self, script: str,
        context_name: str = "default",
    ) -> Any:
        """Execute JavaScript in page context (for XSS verification, etc.)."""

    async def fill_form(
        self, selector: str, values: dict[str, str],
        context_name: str = "default",
        submit: bool = False,
    ) -> None:
        """Fill form fields and optionally submit (for login flows)."""

    async def click(
        self, selector: str,
        context_name: str = "default",
    ) -> None:
        """Click an element."""

    async def get_cookies(self, context_name: str = "default") -> list[dict]: ...
    async def set_cookies(self, cookies: list[dict], context_name: str = "default") -> None: ...
    async def get_storage_state(self, context_name: str = "default") -> dict: ...
```

### 5.5 Configuration

```python
@dataclass
class BrowserConfig:
    headless: bool = True
    proxy: str | None = None            # "http://127.0.0.1:8080" for Burp chaining
    user_agent: str | None = None
    viewport: dict[str, int] = field(
        default_factory=lambda: {"width": 1280, "height": 720}
    )
    ignore_https_errors: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)
    slow_mo: int = 0                     # ms delay between actions (debugging)
```

**Stealth note:** Headless Chromium is detectable. For V2, `ignore_https_errors=True` and a real-looking user agent are sufficient. V4 can add stealth plugins (`playwright-extra` + `stealth` plugin) if WAF evasion becomes necessary.

---

## 6. HttpClient — Raw HTTP Requests

> File: `src/boba/interaction/http.py`

This is the Burp Repeater/Intruder equivalent — send arbitrary HTTP requests independent of the browser. Uses Python's `httpx` library for async HTTP with full TLS/header/redirect control.

### 6.1 Why Not Playwright's Request API?

Playwright's `page.request` ties you to a browser context and adds overhead. For security testing, you need:
- Custom `Host` headers (for virtual host testing)
- Malformed headers (for HTTP smuggling)
- No automatic cookie handling (for testing what happens without auth)
- Connection-level control (TLS version, timeouts)
- No overhead per request (fuzzing sends thousands)

Python `httpx` provides all of this while being async-native.

### 6.2 Core Interface

```python
class HttpClient:
    """
    Stateless HTTP client for crafted requests.
    Every request/response is persisted to http_history via the sink.
    """

    def __init__(self, sink: HttpHistorySink): ...

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        cookies: dict[str, str] | None = None,
        follow_redirects: bool = True,
        timeout_seconds: float = 30.0,
        verify_ssl: bool = False,
        proxy: str | None = None,
    ) -> HttpResponse: ...

    async def replay(
        self,
        request_id: int,
        modifications: dict[str, Any] | None = None,
    ) -> HttpResponse:
        """
        Replay a request from HTTP history.
        modifications can override: method, url, headers, body, cookies.
        Persists the replayed request with parent_request_id set.
        """

    async def compare(
        self,
        response_id_a: int,
        response_id_b: int,
    ) -> CompareResult:
        """
        Diff two responses: status, headers, body.
        Returns structured diff the agent can reason over.
        """

    async def fuzz(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        positions: list[str],
        payloads: dict[str, list[str]],
        attack_type: str = "sniper",
        rate_limit: int = 10,
        cookies: dict[str, str] | None = None,
    ) -> FuzzResult:
        """
        Systematic parameter fuzzing (Burp Intruder equivalent).
        Persists every request/response to http_history.
        Detects anomalies by comparing against baseline.
        """
```

### 6.3 Fuzz Attack Types

Matching Burp Intruder semantics:

| Attack Type | Behavior | Use Case |
|---|---|---|
| `sniper` | One position at a time, cycle payloads | Test each param individually |
| `battering_ram` | All positions get same payload | Same value in multiple places |
| `pitchfork` | Positions paired by index | Username/password pairs |
| `cluster_bomb` | Cartesian product | All combinations |

### 6.4 Return Types

```python
@dataclass
class HttpResponse:
    request_id: int             # ID in http_history
    status_code: int
    headers: dict[str, str]
    body: bytes
    body_text: str              # Decoded, truncated for agent display
    elapsed_ms: float
    redirect_chain: list[str]

@dataclass
class CompareResult:
    status_match: bool
    status_a: int
    status_b: int
    header_diffs: list[dict[str, Any]]
    body_diff_summary: str      # "identical" | "X lines differ" | excerpt
    body_length_a: int
    body_length_b: int
    timing_diff_ms: float

@dataclass
class FuzzResult:
    total_requests: int
    results: list[dict[str, Any]]   # per-payload: status, length, time
    anomalies: list[dict[str, Any]] # entries deviating from baseline
    baseline_status: int
    baseline_length: int
```

---

## 7. Session Management

> File: `src/boba/interaction/session.py`

### 7.1 Design Principle: Sessions Are Data, Not Connections

A `SessionState` is a serializable blob of auth state (cookies, headers, tokens, browser storage). It can be applied to either a browser context or an HTTP client. This enables the critical IDOR workflow:

```
1. Create session_a (victim) and session_b (attacker)
2. Login both via browser (captures cookies, CSRF tokens)
3. Apply session_a to an HTTP request → get response_a
4. Replay same request with session_b → get response_b
5. Compare: if response_b ≈ response_a → IDOR confirmed
```

### 7.2 Auth Methods

```python
class AuthMethod(str, Enum):
    FORM = "form"             # POST login form (browser-based)
    COOKIE = "cookie"         # Inject raw cookies
    BEARER = "bearer"         # Authorization: Bearer <token>
    BASIC = "basic"           # HTTP Basic Auth
    CUSTOM_HEADER = "header"  # Arbitrary header injection
    OAUTH2 = "oauth2"         # Full OAuth2 flow (browser-based)
```

### 7.3 Interface

```python
class SessionManager:

    def __init__(self, hunt_context: HuntContext, hunt_id: str): ...

    # ── Create & Authenticate ──

    async def create(
        self, name: str, target_url: str,
        auth_method: AuthMethod = AuthMethod.FORM,
    ) -> SessionState: ...

    async def login_form(
        self, session_name: str,
        login_url: str,
        credentials: dict[str, str],
        browser: BrowserManager,
    ) -> SessionState:
        """
        Browser-based form login:
        1. Navigate to login_url
        2. Fill form fields from credentials dict
        3. Submit form
        4. Capture resulting cookies + storage state
        5. Persist to sessions table
        """

    async def login_bearer(self, session_name: str, token: str) -> SessionState: ...
    async def login_cookies(self, session_name: str, cookies: dict[str, str]) -> SessionState: ...

    async def login_oauth2(
        self, session_name: str,
        auth_url: str, token_url: str,
        client_id: str, client_secret: str,
        browser: BrowserManager,
    ) -> SessionState: ...

    # ── Apply ──

    def apply_to_headers(self, session_name: str) -> dict[str, str]:
        """Return headers dict with auth for HttpClient."""

    def apply_to_cookies(self, session_name: str) -> dict[str, str]:
        """Return cookies dict for HttpClient."""

    async def apply_to_browser(
        self, session_name: str, browser: BrowserManager,
    ) -> None:
        """Inject cookies + storage state into browser context named after session."""

    # ── Manage ──

    def get(self, session_name: str) -> SessionState: ...
    def list_sessions(self) -> list[SessionState]: ...
    def delete(self, session_name: str) -> None: ...
    async def validate(self, session_name: str, http_client: HttpClient) -> bool: ...
```

### 7.4 Session State Persistence

```python
@dataclass
class SessionState:
    name: str
    target_url: str
    auth_method: AuthMethod
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] | None = None  # localStorage/sessionStorage
    is_valid: bool = True
    created_at: str = ""
    last_used_at: str = ""
```

Serialized to/from SQLite `sessions` table. Updated on every use (`last_used_at`). Validated by sending a test request to a known authenticated endpoint.

---

## 8. OOB Listener — Interactsh Integration

> File: `src/boba/interaction/oob.py`

### 8.1 What It Does

Out-of-band testing detects **blind vulnerabilities** — the server processes your payload but the response doesn't reveal anything. Instead, the payload triggers a callback to an external listener. Examples:

- **Blind SSRF:** Inject `http://your-listener.oast.fun` → the server fetches it → you see the DNS/HTTP callback
- **Blind XSS:** Inject `<img src=http://your-listener.oast.fun>` → stored, rendered for admin → callback
- **Blind command injection:** Inject `; curl your-listener.oast.fun` → callback

### 8.2 Correlation Strategy

Each listener gets a **unique subdomain** from Interactsh. The `purpose`, `test_payload`, `target_url`, and `parameter` fields in `oob_listeners` link a callback back to the exact injection point.

```
Inject payload:  http://abc123.oast.fun  →  into param "url" at /api/proxy
Callback arrives: DNS lookup for abc123.oast.fun from 10.0.0.5
Correlation:      listener abc123 → SSRF in /api/proxy param "url"
```

### 8.3 Interface

```python
class OOBManager:

    def __init__(self, hunt_context: HuntContext, hunt_id: str): ...

    async def start(self) -> None:
        """Initialize Interactsh client, register with server."""

    async def stop(self) -> None:
        """Deregister and cleanup."""

    async def create_listener(
        self,
        purpose: str,
        target_url: str | None = None,
        parameter: str | None = None,
        test_payload: str | None = None,
    ) -> str:
        """Get unique callback domain. Returns e.g., 'abc123.oast.fun'."""

    def get_payload_url(self, listener_id: str, protocol: str = "http") -> str:
        """Return full URL for injection: http://abc123.oast.fun"""

    async def poll(
        self,
        listener_id: str | None = None,
        timeout_seconds: int = 30,
        poll_interval: float = 2.0,
    ) -> list[dict[str, Any]]:
        """
        Poll for interactions.
        Returns: [{type: 'dns'|'http'|'smtp', timestamp, remote_address, details}]
        """

    async def check_all(self) -> dict[str, list[dict]]:
        """Poll all active listeners."""
```

### 8.4 Implementation Options

| Option | Approach | Tradeoff |
|---|---|---|
| Binary adapter | Run `interactsh-client` as subprocess, parse JSON output | Follows V1 pattern, Go binary needed |
| Python library | Use `interactsh-py` package directly | No binary dependency, but less mature |
| Self-hosted | Run own Interactsh server | Full control, but operational overhead |

**Recommendation for V2:** Start with the Python library (`interactsh-py`) for simplicity. Fall back to binary adapter if the library is unreliable. Self-hosted is a V4 concern.

---

## 9. Nuclei Adapter

> File: `src/boba/adapters/nuclei.py`

Follows the V1 `BaseAdapter` pattern exactly — this is a straightforward CLI tool wrapper.

### 9.1 Adapter Metadata

| Property | Value |
|---|---|
| TOOL_NAME | `"nuclei"` |
| BINARY_NAMES | `["nuclei"]` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"finding"` |
| SCOPE_MODE | `"pre"` |
| Install | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

### 9.2 JSON Output Per Line

```json
{
  "template-id": "exposed-env-file",
  "info": {
    "name": "Exposed .env File",
    "severity": "medium",
    "description": "...",
    "reference": ["https://..."],
    "tags": ["exposure", "config"]
  },
  "type": "http",
  "host": "https://app.example.com",
  "matched-at": "https://app.example.com/.env",
  "extracted-results": ["DB_PASSWORD=secret"],
  "curl-command": "curl -X GET https://app.example.com/.env",
  "matcher-name": "env-keywords"
}
```

### 9.3 Canonical Mapping

```python
def parse_record(self, raw: dict) -> dict:
    return {
        "template_id": raw.get("template-id", ""),
        "template_name": raw.get("info", {}).get("name", ""),
        "severity": raw.get("info", {}).get("severity", "info"),
        "finding_type": raw.get("type", ""),
        "host": raw.get("host", ""),
        "url": raw.get("matched-at", ""),
        "extracted_results": raw.get("extracted-results", []),
        "curl_command": raw.get("curl-command", ""),
        "description": raw.get("info", {}).get("description", ""),
        "reference": raw.get("info", {}).get("reference", []),
        "tags": raw.get("info", {}).get("tags", []),
        "matcher_name": raw.get("matcher-name", ""),
    }
```

### 9.4 Template Management

Custom Nuclei templates stored per-hunt:

```
~/.boba/hunts/<hunt_id>/templates/
├── exposed-env-custom.yaml
├── api-key-leak.yaml
└── ...
```

The high-level `scan.nuclei_scan()` tool can run with:
- Community templates (default Nuclei templates)
- Custom templates (from hunt directory)
- Specific severity filter (`--severity high,critical`)
- Tag filter (`--tags cve,exposure`)

---

## 10. Vulnerability Testing Tools

> File: `src/boba/tools/vuln.py`

These are the highest-value tools in V2 — they compose browser + HTTP client + sessions + OOB into automated vulnerability checks. Each follows the same meta-pattern:

```
Setup → Execute → Analyze → Report
```

### 10.1 Common Return Type

```python
@dataclass
class VulnTestResult:
    test_type: str                       # 'idor', 'ssrf', 'xss', etc.
    vulnerable: bool
    confidence: str                      # 'confirmed', 'likely', 'possible'
    title: str
    description: str
    severity: str                        # 'critical', 'high', 'medium', 'low', 'info'
    evidence: list[dict[str, Any]]       # Request/response IDs, diffs, OOB callbacks
    request_ids: list[int]               # All related http_history IDs
    recommendations: list[str]
```

### 10.2 test.idor

```python
async def test_idor(
    http_client: HttpClient,
    session_a: SessionState,    # Owner/victim
    session_b: SessionState,    # Attacker
    endpoint: str,
    method: str = "GET",
    body: str | None = None,
    object_ids: list[str] | None = None,
) -> VulnTestResult:
    """
    1. Request endpoint as User A → response_a
    2. Request same endpoint as User B → response_b
    3. Request with no auth → response_unauth
    4. Compare:
       - If response_b ≈ response_a AND response_b ≠ response_unauth → IDOR confirmed
       - If response_b = 200 and response_unauth = 401/403 → IDOR confirmed
    5. If object_ids provided: test each ID with both sessions
    """
```

### 10.3 test.ssrf

```python
async def test_ssrf(
    http_client: HttpClient,
    oob_manager: OOBManager,
    url: str,
    method: str = "GET",
    injection_points: list[dict] | None = None,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    poll_timeout_seconds: int = 30,
) -> VulnTestResult:
    """
    1. Create OOB listener for each injection point
    2. Inject payloads:
       - OOB callback URL (blind detection)
       - http://127.0.0.1 (internal access)
       - http://169.254.169.254/latest/meta-data/ (cloud metadata)
       - http://[::1] (IPv6 localhost)
    3. Send requests
    4. Check responses for internal content
    5. Poll OOB for callbacks
    6. Correlate callbacks to injection points
    """
```

### 10.4 test.xss

```python
async def test_xss(
    http_client: HttpClient,
    browser: BrowserManager,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    payloads: list[str] | None = None,
    session: SessionState | None = None,
    check_dom: bool = True,
    oob_manager: OOBManager | None = None,
) -> VulnTestResult:
    """
    1. Reflected: inject payloads, check if they appear unescaped in response
    2. DOM-based: render in browser, inject canary (window.__xss_fired = true),
       check if it executes
    3. Blind: inject <img src=oob_url> payloads, poll for callbacks
    """
```

### 10.5 test.sqli

```python
async def test_sqli(
    http_client: HttpClient,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    session: SessionState | None = None,
    payloads: list[str] | None = None,
) -> VulnTestResult:
    """
    1. Baseline: normal request → record response
    2. Error-based: inject ' " ) → check for SQL error strings in response
    3. Boolean-based: ' AND 1=1-- vs ' AND 1=2-- → compare response lengths
    4. Time-based: ' AND SLEEP(5)-- → check response time delta
    """
```

### 10.6 test.auth

```python
async def test_auth(
    http_client: HttpClient,
    endpoint: str,
    session: SessionState | None = None,
    jwt_token: str | None = None,
) -> VulnTestResult:
    """
    1. No-auth: request without credentials → should be 401/403
    2. JWT none algorithm: re-sign with alg=none
    3. JWT algorithm confusion: RS256 → HS256 with public key as secret
    4. Expired token: modify exp claim to past date
    5. Role escalation: modify role/isAdmin claims
    """
```

---

## 11. Built-in Payloads

> Package: `src/boba/payloads/`

Curated payload lists that vulnerability testing tools use by default.

| Module | Contents |
|---|---|
| `xss.py` | Polyglots, event handlers, encoding bypasses, blind XSS callbacks |
| `sqli.py` | Error-based, boolean-based, time-based payloads by DB type (MySQL, PostgreSQL, MSSQL, SQLite) |
| `ssrf.py` | Internal IPs (127.0.0.1, 169.254.169.254, [::1]), cloud metadata URLs (AWS, GCP, Azure), DNS rebinding |
| `auth.py` | JWT manipulation helpers (none algorithm, algorithm confusion, claim tampering) |

These are Python modules exporting `list[str]` constants, not external files. Agents can also pass custom payloads via the `payloads` parameter on any test function.

---

## 12. CLI Extensions

### New Command Groups

```
boba browser
├── navigate    HUNT_ID --url URL [--context NAME] [--wait-until load|networkidle]
├── screenshot  HUNT_ID --path PATH [--context NAME] [--full-page]
├── extract     HUNT_ID [--context NAME]
└── cookies     HUNT_ID [--context NAME]

boba http
├── request     HUNT_ID --method METHOD --url URL [--header KEY:VALUE] [--body BODY]
├── replay      HUNT_ID --request-id ID [--modify-header KEY:VALUE] [--modify-body BODY]
├── compare     HUNT_ID --id-a ID --id-b ID
└── fuzz        HUNT_ID --url URL --positions POS --payloads FILE [--attack-type sniper]

boba session
├── create      HUNT_ID --name NAME --target URL [--method form|cookie|bearer]
├── login       HUNT_ID NAME --url LOGIN_URL --username USER --password PASS
├── login-token HUNT_ID NAME --token TOKEN
├── list        HUNT_ID
├── validate    HUNT_ID NAME
└── delete      HUNT_ID NAME

boba scan
└── nuclei      HUNT_ID [--severity LEVEL] [--tags TAGS] [--templates PATH]

boba test
├── idor        HUNT_ID --endpoint URL --session-a NAME --session-b NAME
├── ssrf        HUNT_ID --url URL --param PARAM
├── xss         HUNT_ID --url URL --param PARAM [--check-dom] [--blind]
├── sqli        HUNT_ID --url URL --param PARAM
└── auth        HUNT_ID --endpoint URL [--jwt TOKEN]

boba context    (EXTEND existing)
├── http-history HUNT_ID [--host HOST] [--method METHOD] [--status CODE] [--source SOURCE]
├── findings    HUNT_ID [--type TYPE] [--severity LEVEL]
├── sessions    HUNT_ID
└── oob         HUNT_ID
```

---

## 13. Implementation Milestones

Ordered by dependency. Each milestone is independently testable.

### M1: Schema Extensions & Models (~200 lines)
**Dependencies:** V1 complete
**Files:** `core/context.py` (extend), `core/models.py` (extend), `core/errors.py` (extend), `core/config.py` (extend)
**Deliverable:** 4 new tables (http_history, sessions, findings, oob_listeners), new dataclasses, new error types, `get_hunt_dir()`.
**Tests:** Upsert/query tests for all new tables.

### M2: HttpHistorySink (~150 lines)
**Dependencies:** M1
**Files:** `interaction/__init__.py`, `interaction/history.py`
**Deliverable:** Persistence bridge for HTTP exchanges, large body file storage, query methods.
**Tests:** Record/query exchanges, large body file handling.

### M3: HttpClient (~300 lines)
**Dependencies:** M2
**Files:** `interaction/http.py`
**Deliverable:** `request()`, `replay()`, `compare()`, `fuzz()`. All traffic persisted via sink.
**Tests:** Request with mocked httpx, replay from history, response comparison, fuzz with sniper/pitchfork attacks.

### M4: Session Management (~250 lines)
**Dependencies:** M1, M2
**Files:** `interaction/session.py`
**Deliverable:** `SessionManager` with create, login_bearer, login_cookies, apply_to_headers/cookies. Browser-based login deferred to M5.
**Tests:** Create sessions, apply to headers/cookies, persist/load from SQLite.

### M5: BrowserManager (~400 lines)
**Dependencies:** M2, M4
**Files:** `interaction/browser.py`
**Deliverable:** Playwright lifecycle, `navigate()`, `screenshot()`, `extract()`, `execute_js()`, `fill_form()`, traffic interception, session injection. Add `login_form()` to SessionManager.
**Tests:** Navigate with mocked Playwright (or headless integration test), DOM extraction, screenshot capture.

### M6: OOB Manager (~200 lines)
**Dependencies:** M1
**Files:** `interaction/oob.py`
**Deliverable:** Interactsh integration, listener creation, polling, correlation.
**Tests:** Mock Interactsh client, test listener creation and callback matching.

### M7: Nuclei Adapter (~100 lines)
**Dependencies:** V1 BaseAdapter (already exists)
**Files:** `adapters/nuclei.py`, `tools/scan.py`
**Deliverable:** Nuclei BaseAdapter subclass + `nuclei_scan()` high-level tool. Results persisted to findings table.
**Tests:** Parse sample Nuclei JSON output, scope filtering.

### M8: Built-in Payloads (~200 lines)
**Dependencies:** None
**Files:** `payloads/__init__.py`, `payloads/xss.py`, `payloads/sqli.py`, `payloads/ssrf.py`, `payloads/auth.py`
**Deliverable:** Curated payload lists for each vulnerability class.

### M9: Vulnerability Testing Tools (~500 lines)
**Dependencies:** M3, M4, M5, M6, M8
**Files:** `tools/vuln.py`
**Deliverable:** `test_idor()`, `test_ssrf()`, `test_xss()`, `test_sqli()`, `test_auth()`. Results persisted to findings table.
**Tests:** Each test function with mocked HTTP client and browser, verifying detection logic.

### M10: CLI Extensions (~400 lines)
**Dependencies:** M3, M4, M5, M6, M7, M9
**Files:** `cli/main.py` (extend)
**Deliverable:** All new command groups: browser, http, session, scan, test, context extensions.

### Dependency Graph

```
M1 (Schema + Models)
├── M2 (HttpHistorySink)
│   ├── M3 (HttpClient)
│   │   └── M9 (Vuln Tools) ── requires M4, M5, M6, M8
│   │       └── M10 (CLI)
│   ├── M4 (SessionManager)
│   │   └── M5 (BrowserManager) ── adds login_form to M4
│   └── M6 (OOBManager) ── independent of M3/M4/M5
├── M7 (Nuclei Adapter) ── independent
└── M8 (Payloads) ── independent

Parallelizable:
- M3, M4, M6, M7, M8 can all start once M1+M2 are done
- M5 starts once M2+M4 are done
- M9 waits for M3, M4, M5, M6, M8
- M10 waits for everything
```

---

## 14. Testing Strategy

### Unit Tests (no browser/network required)

| Component | Mocking |
|---|---|
| HttpHistorySink | In-memory SQLite, temp dir for body files |
| HttpClient | Mock `httpx.AsyncClient` |
| SessionManager | In-memory SQLite |
| BrowserManager | Mock Playwright (or `pytest-playwright` for integration) |
| OOBManager | Mock Interactsh client |
| NucleiAdapter | Mock subprocess (same pattern as V1) |
| Vuln tools | Mock HttpClient, BrowserManager, OOBManager |

### Integration Tests (require Playwright/network)

Marked `@pytest.mark.integration`:
- Navigate a local test server, verify traffic captured
- Fill and submit a login form, verify session cookies persisted
- Screenshot a page, verify PNG file created

### Playwright Test Fixture

```python
@pytest.fixture
async def browser_manager(tmp_path, context):
    sink = HttpHistorySink(context, "test-hunt")
    config = BrowserConfig(headless=True)
    mgr = BrowserManager(config, sink)
    await mgr.start()
    yield mgr
    await mgr.stop()
```

---

## 15. Open Design Decisions

| Decision | Options | Recommendation |
|---|---|---|
| **Playwright browser type** | Chromium vs Firefox vs WebKit | Chromium — best tooling support, most targets test against Chrome |
| **Interactsh client** | Python lib vs Go binary vs self-hosted | Python lib for V2, binary fallback if needed |
| **SQLmap integration** | Adapter (subprocess) vs pure Python payloads | Both — quick detection via built-in payloads, thorough exploitation via sqlmap adapter |
| **Body storage threshold** | 64KB inline vs file | 64KB is a good default; make configurable later |
| **Browser lifecycle** | Start/stop per command vs long-running | Long-running within a hunt session; CLI starts on first browser command, stops on hunt close |
| **Concurrent sessions limit** | Unlimited vs capped | Cap at 10 named sessions per hunt for V2 |
| **Fuzz rate limiting** | Fixed rate vs adaptive | Fixed rate for V2 (user-specified); adaptive throttling in V4 |
