# Boba V4 Implementation Plan — Recon Breadth: Closing the Toolkit Gaps

## 1. Overview

V1 built recon (discover assets). V2 built interaction (test for vulnerabilities). V3 built intelligence (analyze, chain, report). V4 closes the **recon breadth gap** — the missing discovery capabilities that prevent an agent from finding the attack surface that human hunters routinely find.

The product vision's capability map has 14 recon/enumeration capabilities. V1 delivered 7 of them. The remaining 7 represent techniques that elite hunters use to find assets and inputs that surface-level recon misses — hidden parameters, API endpoints, GraphQL schemas, leaked secrets, cloud buckets, and IP ranges not linked from the main domain.

**Scoping decision:** This plan covers the toolkit gaps only. Program selection (`program.*`), infrastructure management (`infra.*`), continuous monitoring (`monitor.*`), and platform API submission (`report.submit`) are intentionally deferred — Boba remains a toolkit that agents compose, not an autonomous hunting platform.

### What V4 Delivers

| Capability | Description | Priority |
|---|---|---|
| Parameter discovery | Find hidden query/body/header parameters on known endpoints | **CRITICAL** |
| GitHub secret scanning | Detect leaked credentials, API keys, internal URLs in public repos | HIGH |
| API surface mapping | Discover API endpoints invisible to crawlers | HIGH |
| GraphQL introspection | Dump GraphQL schemas, enumerate types/queries/mutations | MEDIUM |
| ASN/IP range enumeration | Find all IP ranges owned by a target organization | MEDIUM |
| Cloud bucket discovery | Detect misconfigured S3/GCS/Azure storage buckets | MEDIUM |

**Not in scope:** Continuous monitoring (`monitor.assets`) — this is an operational/scheduling concern that fits a future autonomy phase, not a toolkit gap.

### What an Agent Can Do After V4

```bash
# Discover hidden parameters on an endpoint
boba enum parameters --hunt-id abc123 --url https://app.acme.com/api/search --method GET
boba enum parameters --hunt-id abc123 --url https://app.acme.com/api/profile --method POST --body-type json

# Scan GitHub repos for leaked secrets
boba recon secrets --hunt-id abc123 --target acme-corp
boba recon secrets --hunt-id abc123 --repo https://github.com/acme-corp/webapp

# Discover API endpoints
boba enum api --hunt-id abc123 --url https://app.acme.com
boba enum api --hunt-id abc123 --targets-from-context

# Dump GraphQL schema
boba enum graphql --hunt-id abc123 --url https://app.acme.com/graphql

# Enumerate ASN and IP ranges
boba recon asn --hunt-id abc123 --org "Acme Corporation"
boba recon asn --hunt-id abc123 --domain acme.com

# Discover cloud storage buckets
boba recon cloud --hunt-id abc123 --keyword acme
boba recon cloud --hunt-id abc123 --domain acme.com
```

### Architectural Approach

V4 follows the exact same patterns established in V1:

```
V1 Pattern:  adapter.run(targets) → ToolResult → context.upsert_records()
V4 Pattern:  adapter.run(targets) → ToolResult → context.upsert_records()
```

No new architectural concepts. Every capability is: adapter + tool function + CLI command + persistence + tests. The adapter pattern, scope enforcement, and context persistence work identically to existing tools.

**Two exceptions** where we don't wrap an external CLI tool:
- **GraphQL introspection** — a single HTTP POST, not worth a subprocess. Implemented as a Python function using the existing `HttpClient`.
- **Cloud bucket discovery** — uses HTTP HEAD requests against known patterns. Implemented as a Python function, no external binary.

---

## 2. Project Structure Changes

### New Files

```
src/boba/
├── adapters/
│   ├── arjun.py                     # NEW — parameter discovery adapter
│   ├── gitleaks.py                  # NEW — secret scanning adapter
│   └── kiterunner.py                # NEW — API endpoint discovery adapter
├── tools/
│   └── recon.py                     # EXTEND — add secrets(), asn(), cloud()
│   └── enum.py                      # EXTEND — add parameters(), api(), graphql()

tests/
├── adapters/
│   ├── test_arjun.py                # NEW — Arjun adapter tests
│   ├── test_gitleaks.py             # NEW — gitleaks adapter tests
│   └── test_kiterunner.py           # NEW — Kiterunner adapter tests
├── tools/
│   ├── test_recon.py                # EXTEND — secrets, asn, cloud tests
│   └── test_enum.py                 # EXTEND — parameters, api, graphql tests
```

### Modified Files

```
src/boba/
├── core/
│   ├── context.py                   # ADD: parameters table, secrets table,
│   │                                #      api_endpoints table, graphql_schemas table,
│   │                                #      ip_ranges table, cloud_buckets table,
│   │                                #      upsert/get methods for each
│   └── models.py                    # ADD: new PRODUCES values in adapter base
├── cli/
│   └── main.py                      # ADD: new recon/enum subcommands,
│   │                                #      new context query subcommands
│   └── formatters.py               # ADD: table formatters for new entity types
```

### New Dependencies

```toml
# No new required dependencies.
# Arjun, gitleaks, and Kiterunner are external Go/Python binaries
# discovered at runtime via find_binary() — same as subfinder, httpx, etc.
#
# GraphQL introspection and cloud bucket checks use the existing
# httpx-based HttpClient — no new Python packages needed.
```

---

## 3. New SQLite Schema

> Extends `src/boba/core/context.py`

### 3.1 Parameters Table

Discovered parameters on known endpoints. This is the bridge between recon and vuln testing — every row here is a candidate for IDOR, SQLi, XSS, and SSRF testing.

```sql
CREATE TABLE IF NOT EXISTS parameters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    name            TEXT NOT NULL,
    param_type      TEXT NOT NULL DEFAULT 'query',  -- query | body | header | cookie
    sources         TEXT NOT NULL DEFAULT '[]',       -- JSON array
    confirmed       INTEGER NOT NULL DEFAULT 0,       -- 1 if param elicited different response
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url, method, name, param_type)
);
CREATE INDEX IF NOT EXISTS idx_params_hunt ON parameters(hunt_id);
CREATE INDEX IF NOT EXISTS idx_params_url ON parameters(hunt_id, url);
```

### 3.2 Secrets Table

Leaked credentials and sensitive strings found in source code repositories.

```sql
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,           -- gitleaks rule that matched (e.g., "aws-access-key")
    secret_type     TEXT NOT NULL,           -- key | token | password | certificate | other
    file_path       TEXT NOT NULL,           -- repo-relative file path
    repo            TEXT NOT NULL DEFAULT '',-- repository URL or name
    line_number     INTEGER,
    match_preview   TEXT NOT NULL DEFAULT '',-- redacted preview (first/last 4 chars)
    commit          TEXT NOT NULL DEFAULT '',-- commit SHA
    author          TEXT NOT NULL DEFAULT '',
    date            TEXT NOT NULL DEFAULT '',
    entropy         REAL,                    -- Shannon entropy of match
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, repo, file_path, rule_id, line_number)
);
CREATE INDEX IF NOT EXISTS idx_secrets_hunt ON secrets(hunt_id);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(hunt_id, secret_type);
```

### 3.3 API Endpoints Table

API endpoints discovered by Kiterunner or other API-aware tools, distinct from URLs found by crawlers.

```sql
CREATE TABLE IF NOT EXISTS api_endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    status_code     INTEGER,
    content_type    TEXT NOT NULL DEFAULT '',
    content_length  INTEGER,
    host            TEXT NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',
    framework       TEXT NOT NULL DEFAULT '', -- detected API framework (express, django, etc.)
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url, method)
);
CREATE INDEX IF NOT EXISTS idx_api_hunt ON api_endpoints(hunt_id);
CREATE INDEX IF NOT EXISTS idx_api_host ON api_endpoints(hunt_id, host);
```

### 3.4 GraphQL Schemas Table

Introspection results stored per-endpoint. A successful introspection dumps the full schema — types, queries, mutations, subscriptions.

```sql
CREATE TABLE IF NOT EXISTS graphql_schemas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    introspection   INTEGER NOT NULL DEFAULT 0, -- 1 if introspection is enabled
    types           TEXT NOT NULL DEFAULT '[]',  -- JSON array of type names
    queries         TEXT NOT NULL DEFAULT '[]',  -- JSON array of query fields
    mutations       TEXT NOT NULL DEFAULT '[]',  -- JSON array of mutation fields
    subscriptions   TEXT NOT NULL DEFAULT '[]',  -- JSON array of subscription fields
    raw_schema      TEXT NOT NULL DEFAULT '{}',  -- full __schema JSON (compressed if large)
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url)
);
CREATE INDEX IF NOT EXISTS idx_graphql_hunt ON graphql_schemas(hunt_id);
```

### 3.5 IP Ranges Table

ASN-derived IP ranges owned by the target organization.

```sql
CREATE TABLE IF NOT EXISTS ip_ranges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    cidr            TEXT NOT NULL,
    asn             TEXT NOT NULL DEFAULT '',
    org_name        TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    rir             TEXT NOT NULL DEFAULT '', -- ARIN, RIPE, APNIC, etc.
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_ipranges_hunt ON ip_ranges(hunt_id);
CREATE INDEX IF NOT EXISTS idx_ipranges_asn ON ip_ranges(hunt_id, asn);
```

### 3.6 Cloud Buckets Table

Discovered cloud storage buckets and their access status.

```sql
CREATE TABLE IF NOT EXISTS cloud_buckets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,            -- aws | gcp | azure
    bucket_name     TEXT NOT NULL,
    url             TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'unknown', -- exists | listable | writable | not_found
    region          TEXT NOT NULL DEFAULT '',
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, provider, bucket_name)
);
CREATE INDEX IF NOT EXISTS idx_buckets_hunt ON cloud_buckets(hunt_id);
CREATE INDEX IF NOT EXISTS idx_buckets_status ON cloud_buckets(hunt_id, status);
```

---

## 4. Implementation Phases

V4 is split into 3 phases, ordered by impact on the agent's ability to find bugs.

### Phase 1 — Parameter Discovery (CRITICAL)

This is the highest-impact gap. Every vuln test tool (IDOR, SQLi, XSS, SSRF, mass assignment) requires knowing which parameters exist. Without parameter discovery, the agent can only test parameters it finds in HTML forms or JS — missing the hidden ones where bugs live.

**Tool: Arjun** — the standard parameter discovery tool. Sends requests with candidate parameter names and detects which ones elicit a different response (by status code, content length, or body content).

#### 4.1.1 Arjun Adapter

> `src/boba/adapters/arjun.py`

```python
class ArjunAdapter(BaseAdapter):
    TOOL_NAME = "arjun"
    BINARY_NAMES = ["arjun"]
    OUTPUT_FORMAT = OutputFormat.JSON_OBJECT
    PRODUCES = "parameter"
    SCOPE_MODE = "pre"  # URL is the input — scope-check before sending requests
```

**`build_command`** constructs:
```bash
arjun -u <url> -m <method> -oJ /tmp/arjun_out.json [--stable] [-t <threads>]
```

Key flags:
- `-m GET|POST|JSON` — HTTP method and body type
- `-oJ` — JSON output (adapter reads from file, not stdout)
- `--stable` — slower but more reliable detection
- `-t` — thread count (maps to `config.rate_limit`)

**`parse_record`** maps Arjun's output to:
```python
{
    "url": "<target_url>",
    "method": "GET",
    "name": "<param_name>",
    "param_type": "query",  # or "body", "json"
    "confirmed": True,
}
```

Arjun outputs `{"url": "...", "params": ["id", "page", "debug"]}` — each param becomes a separate record.

**`extract_scope_target`** returns the URL (scope checks the target, not the parameter name).

#### 4.1.2 Tool Function

> `src/boba/tools/enum.py` — add `parameters()`

```python
async def parameters(
    context: HuntContext,
    hunt: Hunt,
    url: str,
    method: str = "GET",
    body_type: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
```

- Scope-checks the URL before running
- Runs `ArjunAdapter` with method and body_type config
- Persists each discovered parameter via `context.upsert_parameter()`
- Logs tool run

#### 4.1.3 CLI Command

> `src/boba/cli/main.py` — add to `enum_app`

```bash
boba enum parameters <hunt-id> --url <url> [--method GET|POST] [--body-type json|form]
```

#### 4.1.4 Context Methods

> `src/boba/core/context.py`

- `upsert_parameter(hunt_id, record)` — INSERT ON CONFLICT merges sources
- `get_parameters(hunt_id, url=None, method=None)` — query with optional filters
- `context` subcommand: `boba context parameters <hunt-id> [--url <filter>]`

#### 4.1.5 Tests

- Adapter: parse Arjun JSON output, build command with method variants, scope filtering
- Tool: mock adapter, verify persistence and tool run logging
- CLI: JSON and table output

---

### Phase 2 — Secret Scanning & API Discovery (HIGH)

Two capabilities that find entirely different classes of attack surface: leaked credentials (passive, no target interaction) and hidden API endpoints (active, probes target).

#### 4.2.1 Gitleaks Adapter

> `src/boba/adapters/gitleaks.py`

**Tool: gitleaks** — scans git repos for secrets using regex + entropy rules. Preferred over trufflehog because it outputs clean JSON and has a single binary with no dependencies.

```python
class GitleaksAdapter(BaseAdapter):
    TOOL_NAME = "gitleaks"
    BINARY_NAMES = ["gitleaks"]
    OUTPUT_FORMAT = OutputFormat.JSON_ARRAY
    PRODUCES = "secret"
    SCOPE_MODE = "post"  # Can't scope-filter before scanning a repo
```

**`build_command`** constructs:
```bash
gitleaks detect --source <repo_path_or_url> --report-format json --report-path /tmp/gitleaks_out.json --no-banner
```

For remote repos: `--source` accepts a clone URL. Gitleaks clones to a temp dir internally.
For org scanning: the tool function handles GitHub API enumeration of repos.

**`parse_record`** maps gitleaks output to:
```python
{
    "rule_id": "aws-access-key-id",
    "secret_type": "key",
    "file_path": "config/deploy.env",
    "repo": "https://github.com/acme-corp/webapp",
    "line_number": 42,
    "match_preview": "AKIA****XMPL",  # redacted in adapter
    "commit": "a1b2c3d",
    "author": "dev@acme.com",
    "date": "2025-11-03",
    "entropy": 4.2,
}
```

**Security**: the adapter redacts secrets to first 4 + last 4 characters before persisting. Full matches are never stored in the database.

**`extract_scope_target`** returns the repo URL or org name for scope checking.

#### 4.2.2 Kiterunner Adapter

> `src/boba/adapters/kiterunner.py`

**Tool: Kiterunner** — API endpoint discovery via wordlist-driven probing. Unlike directory brute-forcing (ffuf), Kiterunner understands REST patterns and tests multiple HTTP methods per path.

```python
class KiterunnerAdapter(BaseAdapter):
    TOOL_NAME = "kiterunner"
    BINARY_NAMES = ["kr"]
    OUTPUT_FORMAT = OutputFormat.PLAIN_LINES
    PRODUCES = "api_endpoint"
    SCOPE_MODE = "pre"
```

**`build_command`** constructs:
```bash
kr scan <url> -w <wordlist> -x <max_connections> --fail-status-codes 404,400 -oJ
```

Default wordlist: `routes-large.kite` (ships with Kiterunner).

**`parse_record`** maps output to:
```python
{
    "url": "https://app.acme.com/api/v2/users",
    "method": "GET",
    "status_code": 200,
    "content_type": "application/json",
    "content_length": 4521,
    "host": "app.acme.com",
    "path": "/api/v2/users",
}
```

#### 4.2.3 Tool Functions

> `src/boba/tools/recon.py` — add `secrets()`

```python
async def secrets(
    context: HuntContext,
    hunt: Hunt,
    target: str,              # GitHub org, user, or repo URL
    repo: str | None = None,  # specific repo URL (overrides target)
    config: AdapterConfig | None = None,
) -> ToolResult:
```

> `src/boba/tools/enum.py` — add `api()`

```python
async def api(
    context: HuntContext,
    hunt: Hunt,
    url: str | None = None,
    targets: list[str] | None = None,  # pulls from context if None
    wordlist: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
```

#### 4.2.4 CLI Commands

```bash
boba recon secrets <hunt-id> --target <github-org-or-user> [--repo <url>]
boba enum api <hunt-id> --url <url> [--wordlist <path>]
boba context secrets <hunt-id> [--type key|token|password]
boba context api-endpoints <hunt-id> [--host <filter>]
```

#### 4.2.5 Tests

- Gitleaks adapter: parse JSON array output, verify secret redaction, scope filtering
- Kiterunner adapter: parse plain-line output, verify method/status extraction
- Tool functions: mock adapters, verify persistence
- CLI: JSON and table output for both

---

### Phase 3 — GraphQL, ASN, Cloud Buckets (MEDIUM)

Three capabilities that round out the toolkit. Each addresses a specific target profile: GraphQL APIs, large organizations with IP ranges, and cloud-native infrastructure.

#### 4.3.1 GraphQL Introspection

> `src/boba/tools/enum.py` — add `graphql()`

**No adapter needed.** GraphQL introspection is a single HTTP POST with a well-known query. Using the existing `HttpClient` is simpler and faster than wrapping an external tool.

```python
async def graphql(
    context: HuntContext,
    hunt: Hunt,
    url: str,
    session_name: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
```

Implementation:
1. Send introspection query via `HttpClient.request()`:
   ```json
   {"query": "{__schema{types{name kind fields{name type{name kind ofType{name}}}} queryType{fields{name args{name type{name}}}} mutationType{fields{name args{name type{name}}}} subscriptionType{fields{name}}}}"}
   ```
2. If introspection disabled (error response), try field suggestion enumeration via `{__type(name:"Query"){fields{name}}}` with common type names
3. Parse response: extract type names, query fields, mutation fields, subscription fields
4. Persist to `graphql_schemas` table
5. Also persist discovered query/mutation fields as `api_endpoint` records for downstream testing

**Why not Clairvoyance?** Clairvoyance is useful when introspection is disabled, but it's a slow brute-force tool that sends thousands of requests. For a toolkit, we start with introspection (instant if enabled) and can add Clairvoyance as a future adapter if needed.

#### 4.3.2 ASN / IP Range Enumeration

> `src/boba/tools/recon.py` — add `asn()`

**No adapter needed.** ASN lookups use public APIs (no binary required). Two data sources:

1. **BGP.tools API** — `https://bgp.tools/search?q=<org>` for org-to-ASN lookup
2. **RIPEstat API** — `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<num>` for ASN-to-CIDR

```python
async def asn(
    context: HuntContext,
    hunt: Hunt,
    org: str | None = None,
    domain: str | None = None,
    asn_number: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
```

Implementation:
1. If `domain` given: DNS lookup → IP → whois-style ASN lookup via public APIs
2. If `org` given: search BGP.tools for matching ASN numbers
3. If `asn_number` given: directly query prefix announcements
4. For each ASN: fetch all announced prefixes (CIDR ranges)
5. Persist to `ip_ranges` table
6. Optionally: add discovered CIDRs to scope as inclusion rules (with agent confirmation)

Uses `HttpClient` for API calls. No external binary.

#### 4.3.3 Cloud Bucket Discovery

> `src/boba/tools/recon.py` — add `cloud()`

**No adapter needed.** Bucket discovery checks predictable naming patterns against known cloud storage URLs.

```python
async def cloud(
    context: HuntContext,
    hunt: Hunt,
    keyword: str | None = None,
    domain: str | None = None,
    wordlist: list[str] | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
```

Implementation:
1. Generate candidate bucket names from keyword/domain: `acme`, `acme-backup`, `acme-dev`, `acme-staging`, `acme-prod`, `acme.com`, `acme-assets`, etc.
2. For each candidate, check existence:
   - **AWS S3**: HEAD `https://<bucket>.s3.amazonaws.com/`
   - **GCP**: HEAD `https://storage.googleapis.com/<bucket>`
   - **Azure**: HEAD `https://<bucket>.blob.core.windows.net/`
3. Classify response:
   - 200 → `listable` (publicly accessible — HIGH severity finding)
   - 403 → `exists` (bucket exists but access denied — useful for further testing)
   - 404 → `not_found` (skip)
4. Persist to `cloud_buckets` table

Uses `HttpClient` for requests. Rate-limited (max 5 concurrent) to avoid WAF triggers.

#### 4.3.4 CLI Commands

```bash
boba enum graphql <hunt-id> --url <endpoint> [--session <name>]
boba recon asn <hunt-id> [--org <name>] [--domain <domain>] [--asn <number>]
boba recon cloud <hunt-id> [--keyword <word>] [--domain <domain>]
boba context graphql <hunt-id>
boba context ip-ranges <hunt-id> [--asn <filter>]
boba context cloud-buckets <hunt-id> [--status exists|listable]
```

#### 4.3.5 Tests

- GraphQL: mock HTTP response with introspection JSON, verify type/query/mutation extraction, test disabled-introspection fallback
- ASN: mock API responses, verify CIDR parsing, test domain→IP→ASN resolution chain
- Cloud: mock HEAD responses with various status codes, verify bucket name generation patterns, verify rate limiting

---

## 5. Integration Points

### 5.1 Feeding Vuln Tests

The primary value of V4 is feeding the existing V2/V3 testing pipeline. Here's how new data flows into existing tools:

```
parameters table  ──►  test_idor (now has params to test)
                  ──►  test_sqli (inject into discovered params)
                  ──►  test_xss (reflect through discovered params)
                  ──►  test_ssrf (URL-type params → SSRF candidates)

secrets table     ──►  Agent reasoning (leaked API keys → direct access)
                  ──►  test_auth (try leaked credentials)

api_endpoints     ──►  test_idor (API endpoints are prime IDOR targets)
                  ──►  test_auth (test API auth)
                  ──►  enum.parameters (discover params on API endpoints)

graphql_schemas   ──►  Agent reasoning (mutations → test auth, queries → test data access)
                  ──►  test_idor (GraphQL queries with ID arguments)

ip_ranges         ──►  recon.hosts (scan discovered IP ranges for live hosts)
                  ──►  recon.ports (port scan new infrastructure)

cloud_buckets     ──►  Agent reasoning (listable bucket = immediate finding)
```

### 5.2 Prioritize Integration

> `src/boba/analysis/prioritize.py`

Extend `prioritize_endpoints()` to also consider:
- Parameters with `confirmed=True` get higher scores
- API endpoints (from Kiterunner) get higher scores than crawler-discovered URLs
- GraphQL mutations get highest priority (state-changing operations)

### 5.3 Coverage Integration

> `src/boba/analysis/coverage.py`

Extend coverage tracking to include:
- Parameter-level coverage: "has param `id` on `/api/user` been tested for IDOR?"
- API endpoint coverage: "has `POST /api/v2/transfer` been tested for auth?"

### 5.4 Hunt Stats

> `src/boba/core/context.py` — extend `get_hunt_stats()`

Add counts for: `parameters`, `secrets`, `api_endpoints`, `graphql_schemas`, `ip_ranges`, `cloud_buckets`.

---

## 6. Phase Ordering & Dependencies

```
Phase 1: Parameter Discovery
├── ArjunAdapter (new adapter)
├── parameters table (new schema)
├── enum.parameters() tool function
├── CLI: boba enum parameters
├── CLI: boba context parameters
└── Tests (~25 new)

Phase 2: Secrets & API Discovery
├── GitleaksAdapter (new adapter)
├── KiterunnerAdapter (new adapter)
├── secrets table (new schema)
├── api_endpoints table (new schema)
├── recon.secrets() tool function
├── enum.api() tool function
├── CLI: boba recon secrets, boba enum api
├── CLI: boba context secrets, boba context api-endpoints
└── Tests (~40 new)

Phase 3: GraphQL, ASN, Cloud
├── enum.graphql() (Python-native, no adapter)
├── recon.asn() (Python-native, no adapter)
├── recon.cloud() (Python-native, no adapter)
├── graphql_schemas table (new schema)
├── ip_ranges table (new schema)
├── cloud_buckets table (new schema)
├── CLI: 6 new commands
├── Integration: prioritize, coverage, hunt_stats
└── Tests (~40 new)
```

Phases are independent and can be built in any order. Phase 1 is recommended first due to its direct impact on the existing vuln testing pipeline.

**Estimated new tests: ~105** (bringing total from 592 to ~697).

---

## 7. Capability Map After V4

Cross-referencing with the product vision's "Human-to-Agent Capability Map":

### Reconnaissance & Enumeration (14/14 → complete)

| Capability | V1 | V4 | Status |
|---|---|---|---|
| Subdomain discovery | subfinder | — | Done |
| Live host detection | httpx | — | Done |
| Port scanning | naabu | — | Done |
| Historical URL mining | gau + waybackurls | — | Done |
| Technology fingerprinting | whatweb | — | Done |
| Directory/endpoint fuzzing | ffuf | — | Done |
| JS crawling | katana | — | Done |
| Parameter discovery | — | Arjun | **V4 Phase 1** |
| API surface mapping | — | Kiterunner | **V4 Phase 2** |
| GitHub secret scanning | — | gitleaks | **V4 Phase 2** |
| GraphQL introspection | — | Python-native | **V4 Phase 3** |
| ASN/IP range enumeration | — | Python-native | **V4 Phase 3** |
| Cloud bucket discovery | — | Python-native | **V4 Phase 3** |
| Continuous monitoring | — | — | Deferred (autonomy) |

### Remaining Vision Gaps (intentionally deferred)

| Category | Capabilities | Reason |
|---|---|---|
| Program Selection | search, analyze, policy, portfolio | Boba stays a toolkit, not a platform |
| Infrastructure | deploy, distribute, schedule, alert | Operational concern, not toolkit |
| Platform Submission | submit, respond, status | Requires API keys and platform accounts |
| OAuth/SSO | session.oauth | Complex per-provider logic; manual token capture works |
| Business Logic Testing | test.logic | Inherently requires agent reasoning, not a tool |
| Continuous Monitoring | monitor.assets | Scheduling concern, deferred |

After V4, the toolkit covers **38 → 44 of 60** vision capabilities (73%), with 100% coverage of the recon/enumeration category that agents need to find attack surface.
