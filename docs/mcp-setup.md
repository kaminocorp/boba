# Boba MCP Server — Setup Guide

Boba's MCP server exposes all 65 tools as native MCP tool calls. Any MCP-compatible agent (Claude Code, Claude Desktop, Hermes, or custom agents) can operate Boba without knowing it's a CLI tool underneath.

---

## Installation

```bash
# Install Boba with MCP support
pip install 'boba-hunter[mcp]'

# Or from source (editable)
pip install -e ".[dev]"
```

The `mcp` optional dependency pulls in the MCP Python SDK (FastMCP). Users who only want the CLI don't need it — plain `pip install boba-hunter` skips the MCP SDK entirely. (The distribution name on PyPI is `boba-hunter`; the import name and CLI command remain `boba`.)

---

## Running the Server

### STDIO (local agents — Claude Code, Claude Desktop)

```bash
boba-mcp
```

This starts the MCP server on STDIO, which is the default transport for local agent connections.

### Streamable HTTP (remote/networked agents)

```bash
BOBA_MCP_TRANSPORT=streamable-http BOBA_MCP_PORT=3000 boba-mcp
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BOBA_DATA_DIR` | `.` (current directory) | Where SQLite databases are stored |
| `BOBA_MCP_TRANSPORT` | `stdio` | Transport: `stdio` or `streamable-http` |
| `BOBA_MCP_PORT` | `3000` | Port for streamable-http transport |

---

## Agent Configuration

### Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "boba": {
      "command": "boba-mcp",
      "env": {
        "BOBA_DATA_DIR": "/path/to/hunts"
      }
    }
  }
}
```

### Claude Code

Add to your project's `.mcp.json` or global MCP settings:

```json
{
  "mcpServers": {
    "boba": {
      "command": "boba-mcp",
      "env": {
        "BOBA_DATA_DIR": "."
      }
    }
  }
}
```

### Custom Agents (Streamable HTTP)

```bash
# Start server
BOBA_DATA_DIR=/data BOBA_MCP_TRANSPORT=streamable-http BOBA_MCP_PORT=3000 boba-mcp

# Connect from any MCP client at http://localhost:3000/mcp
```

For production deployments, put the server behind nginx/Caddy with TLS and auth — the MCP server itself has no authentication layer.

---

## Tool Reference (65 tools)

### Hunt Management (6)

| Tool | Description |
|---|---|
| `hunt_create` | Create a new hunt with optional scope YAML |
| `hunt_status` | Get hunt details and discovery statistics |
| `hunt_list` | List all hunts |
| `hunt_pause` | Pause an active hunt |
| `hunt_resume` | Resume a paused hunt |
| `hunt_close` | Close a hunt (mark completed) |

### Reconnaissance (5)

| Tool | Description |
|---|---|
| `recon_subdomains` | Discover subdomains via subfinder |
| `recon_hosts` | Check which hosts are alive via httpx |
| `recon_ports` | Port scan via naabu |
| `recon_urls` | Discover historical URLs via gau + waybackurls |
| `recon_tech` | Fingerprint technology stacks via whatweb |

### Enumeration (2)

| Tool | Description |
|---|---|
| `enum_directories` | Fuzz for directories/files via ffuf |
| `enum_crawl` | Crawl web applications via katana |

### Scanning (1)

| Tool | Description |
|---|---|
| `scan_nuclei` | Run Nuclei vulnerability scanner |

### Context Queries (11)

| Tool | Description |
|---|---|
| `context_subdomains` | List discovered subdomains |
| `context_hosts` | List discovered hosts (optionally alive only) |
| `context_ports` | List discovered ports |
| `context_urls` | List discovered URLs |
| `context_tech` | List detected technologies |
| `context_directories` | List discovered directories |
| `context_findings` | List vulnerability findings |
| `context_sessions` | List auth sessions |
| `context_http_history` | Query HTTP request/response history |
| `context_tool_runs` | List tool execution history |
| `context_stats` | Get aggregate discovery statistics |

### Session Management (7)

| Tool | Description |
|---|---|
| `session_create` | Create a new auth session |
| `session_login_token` | Authenticate with Bearer token |
| `session_login_basic` | Authenticate with HTTP Basic |
| `session_login_cookies` | Authenticate with raw cookies |
| `session_login_header` | Authenticate with custom header |
| `session_list` | List all sessions |
| `session_delete` | Delete a session |

### HTTP Client (4)

| Tool | Description |
|---|---|
| `http_request` | Send an HTTP request (session-aware) |
| `http_replay` | Replay a request from history with modifications |
| `http_compare` | Compare two HTTP responses |
| `http_fuzz` | Fuzz parameters (Burp Intruder equivalent) |

### Browser (3)

| Tool | Description |
|---|---|
| `browser_navigate` | Navigate headless browser to URL |
| `browser_screenshot` | Take a screenshot |
| `browser_extract` | Extract DOM data (forms, links, scripts) |

### OOB Listeners (3)

| Tool | Description |
|---|---|
| `oob_create_listener` | Create callback listener for blind testing |
| `oob_get_payload` | Get injectable payload URL |
| `oob_poll` | Poll for out-of-band callbacks |

### Vulnerability Testing (12)

| Tool | Description |
|---|---|
| `test_idor` | Test for Insecure Direct Object Reference |
| `test_ssrf` | Test for Server-Side Request Forgery |
| `test_sqli` | Test for SQL Injection |
| `test_xss` | Test for Cross-Site Scripting |
| `test_auth` | Test for auth bypass / JWT manipulation |
| `test_race` | Test for race conditions |
| `test_redirect` | Test for open redirect |
| `test_csrf` | Test for CSRF |
| `test_mass_assign` | Test for mass assignment |
| `test_reset` | Test password reset flow |
| `test_ai` | Test AI/LLM for prompt injection |
| `test_ai_conversation` | Test AI chatbot via multi-turn conversation |

### Analysis (6)

| Tool | Description |
|---|---|
| `analyze_coverage` | Coverage summary (tested vs untested) |
| `analyze_coverage_gaps` | Identify untested endpoints |
| `analyze_dedupe` | Deduplicate findings |
| `analyze_severity` | CVSS scoring + payout estimates |
| `analyze_chain` | Detect attack chains |
| `analyze_prioritize` | Prioritize endpoints by vuln likelihood |

### Reporting (5)

| Tool | Description |
|---|---|
| `report_draft` | Draft report from finding or chain |
| `report_format` | Format for HackerOne/Bugcrowd/Markdown |
| `report_poc` | Package PoC evidence |
| `report_list` | List all reports |
| `report_show` | Get single report |

---

## Complete Hunt Walkthrough

Here's a full hunt workflow using MCP tool calls:

```
# 1. Create a scoped hunt
hunt_create(name="Acme Corp", scope_yaml="/path/to/scope.yaml")
→ {"hunt_id": "a1b2c3d4e5f6", "status": "active"}

# 2. Reconnaissance
recon_subdomains(hunt_id, domains=["acme.com"])
recon_hosts(hunt_id)                    # auto-uses discovered subdomains
recon_ports(hunt_id)                    # auto-uses alive hosts
recon_urls(hunt_id, domains=["acme.com"])
recon_tech(hunt_id)                     # auto-uses alive hosts

# 3. Enumeration
enum_directories(hunt_id, url="https://acme.com")
enum_crawl(hunt_id)                     # auto-uses alive hosts
scan_nuclei(hunt_id, severity="critical,high")

# 4. Check what we found
context_stats(hunt_id)
analyze_prioritize(hunt_id, top=10)

# 5. Set up sessions for authenticated testing
session_create(hunt_id, name="user_a", target_url="https://acme.com")
session_login_token(hunt_id, "user_a", token="...")
session_create(hunt_id, name="user_b", target_url="https://acme.com")
session_login_token(hunt_id, "user_b", token="...")

# 6. Vulnerability testing
test_idor(hunt_id, endpoint="/api/user/123", session_a="user_a", session_b="user_b")
test_sqli(hunt_id, url="https://acme.com/search", param="q", session_name="user_a")
test_xss(hunt_id, url="https://acme.com/search", param="q")
test_ssrf(hunt_id, url="https://acme.com/fetch", param="url")

# 7. Analysis
analyze_coverage(hunt_id)
analyze_chain(hunt_id)
analyze_severity(hunt_id, platform="hackerone")
analyze_dedupe(hunt_id)

# 8. Reporting
context_findings(hunt_id)               # review findings
report_draft(hunt_id, finding_id=1)     # draft report
report_format(hunt_id, report_id=1, platform="hackerone")
report_poc(hunt_id, finding_id=1)       # package evidence
```

Every recon/enum step persists results to SQLite. Subsequent tools auto-consume prior results. Context tools let the agent inspect state at any point without re-running tools.
