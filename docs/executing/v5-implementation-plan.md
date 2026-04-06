# V5 Implementation Plan — JS Endpoint Mining + GraphQL Testing

**Status:** Planning  
**Prerequisite:** V4 complete (0.6.0 ✅)  
**Goal:** Close the two critical attack-surface gaps identified in the code assessment — JS source mining and GraphQL vulnerability testing.

---

## Motivation

Two capability gaps prevent an agent from fully mapping and testing modern web targets:

1. **JS endpoint mining** — Modern SPAs declare their entire API surface in bundled JavaScript. Katana already follows links *referenced* in JS (`-js-crawl`), but it does not parse JS source to extract route strings, `fetch()` calls, `axios` calls, or internal URL constants. An agent without this sees only the entrypoints the server explicitly links to, missing the majority of the actual API.

2. **GraphQL testing** — If a target exposes a GraphQL endpoint, the agent currently has no way to discover the schema, enumerate resolvers, or test for BOLA/IDOR on queries. The HTTP client can send raw GraphQL requests, but only if the schema is already known. Without automated discovery and introspection, the agent is blind to this entire attack surface.

---

## Architecture Decisions

### JS mining: Python-native, no external binary

The existing adapter pattern wraps external CLI tools. JS mining does not require one — it is pure regex extraction over HTTP-fetched content. Introducing a binary dependency (LinkFinder, etc.) would create an install friction point for every agent environment.

**Decision:** Implement as a `JsMiner` class in `src/boba/tools/js_mine.py` that uses `httpx` (already a dependency) directly. It exposes the same `async run() → ToolResult` interface as adapters, making it composable with the existing tool layer, but is not a `BaseAdapter` subclass.

### GraphQL discovery: Python-native adapter variant

GraphQL endpoint discovery is a structured HTTP probe (check known paths against live hosts). It does not require an external binary. It *does* fit the adapter lifecycle (targets → scope filter → probe → records → scope filter), but overrides `_execute` to use Python httpx rather than subprocess.

**Decision:** `GraphqlDiscoverAdapter` extends `BaseAdapter` and overrides `_execute`. This keeps scope enforcement, logging, and result formatting identical to all other adapters.

### GraphQL schema: new `graphql_schemas` table

Storing a full introspected schema (potentially hundreds of types) in the existing `api_endpoints` table would require an opaque blob column. A dedicated table is cleaner and allows schema-aware querying later.

### GraphQL vuln tests: extend `tools/vuln.py`

Three new test functions follow the exact existing pattern (`test_graphql_idor`, `test_graphql_auth`, `test_graphql_mass_assign`). They live in `vuln.py` today; after the V5.x refactor of `vuln.py` into a package (per code assessment plan), they go into `vuln/graphql.py`.

---

## Phase V5.1 — JS Endpoint Mining

### New files

#### `src/boba/tools/js_mine.py`

Core implementation. No external binary.

```python
class JsMiner:
    """Fetches JS files and extracts endpoint strings using regex patterns."""

    # Patterns derived from LinkFinder's proven regex, tuned for false-positive reduction:
    # - require leading / (absolute paths only, no relative fragments)
    # - require minimum 2 path segments (avoids matching bare words like "/en")  
    # - exclude data URIs, image paths, common static extensions
    PATTERNS: list[re.Pattern] = [...]

    STATIC_EXTENSIONS = frozenset({".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf", ...})

    async def run(
        self,
        js_urls: list[str],
        session_headers: dict[str, str] | None = None,
        timeout_seconds: float = 30.0,
        max_js_size_bytes: int = 5 * 1024 * 1024,  # 5 MB cap
        concurrency: int = 5,
    ) -> ToolResult:
        """
        Fetch each JS URL and extract endpoint strings.

        Returns ToolResult with records of type {"url": str, "source_js": str,
        "host": str, "path": str, "source": "js_mine"}.

        Deduplicates across JS files — if /api/users appears in 3 JS files,
        it produces one record (source_js = first file that referenced it).
        """
```

**Endpoint extraction pipeline (per JS file):**
1. Fetch JS content with httpx (respect `max_js_size_bytes` cap)
2. Apply regex patterns → raw string candidates
3. Filter: must start with `/` or `https?://`, min 2 path segments, not static extension
4. Normalize: strip query strings and fragment identifiers
5. Scope-check against `ScopeEngine` (domain of the JS file's host)
6. Deduplicate across all processed files using a `seen_paths: set[str]` per host

**Regex patterns (4 families):**

| Pattern family | Example match | Regex |
|---|---|---|
| Quoted path literal | `"/api/users"` | `['"](/(?:[a-zA-Z0-9_\-\.{}]+/)+[a-zA-Z0-9_\-\.{}]*)['"]` |
| fetch/axios call | `fetch("/api/data")` | `(?:fetch\|axios\.[a-z]+)\s*\(\s*['"]([^'"]+)['"]` |
| URL assignment | `url = "/v1/endpoint"` | `(?:url\|path\|endpoint\|href\|api)\s*[=:]\s*['"]([^'"]+)['"]` |
| Template literal path | `` `/api/${id}/profile` `` | `` [`](/[a-zA-Z0-9_/\-\.{}`$]+)[`] `` |

#### `src/boba/tools/enum.py` — new `js_endpoints()` function

```python
async def js_endpoints(
    context: HuntContext,
    hunt: Hunt,
    js_urls: list[str] | None = None,
    session: SessionState | None = None,
    concurrency: int = 5,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Extract API endpoint strings from JavaScript source files.

    If js_urls is None, auto-discovers JS files from context:
    - All urls where path ends in .js
    - All http_history records with response_content_type containing 'javascript'

    Persists discovered endpoints to api_endpoints table.
    """
```

**Auto-discovery of JS files from context:**
```python
if js_urls is None:
    known_urls = context.get_urls(hunt.id)
    js_urls = [
        u["url"] for u in known_urls
        if u.get("url", "").endswith(".js")
        or "javascript" in (u.get("content_type") or "").lower()
    ]
    # Also pull from http_history (browser/crawler traffic may have captured JS)
    history = context.query_http_history(hunt.id, limit=2000)
    for rec in history:
        if "javascript" in (rec.get("response_content_type") or "").lower():
            js_urls.append(rec["url"])
    js_urls = list(dict.fromkeys(js_urls))  # deduplicate, preserve order
```

Records are persisted to `api_endpoints` with `framework="js_mine"` and `source="js_mine"`.

### Schema changes

None. JS-mined endpoints go into the existing `api_endpoints` table with `framework="js_mine"`.

### CLI additions

```
boba enum js [HUNT_ID] [--url URL] [--targets t1,t2] [--concurrency N]
```

- `--url` / `--targets`: explicit JS URLs (if omitted, auto-discovers from context)
- `--concurrency`: parallel fetch workers (default 5)

### Tests

| Test | What it covers |
|---|---|
| `test_js_mine_fetch_and_extract` | Mocked JS response → correct endpoint extraction |
| `test_js_mine_pattern_families` | Each of the 4 regex families independently |
| `test_js_mine_false_positive_filter` | Static extensions, bare words, data URIs rejected |
| `test_js_mine_scope_filter` | Out-of-scope endpoints excluded |
| `test_js_mine_dedup` | Same path in 3 JS files → 1 record |
| `test_js_mine_size_cap` | JS file > 5 MB skipped, warning logged |
| `test_js_mine_auto_discover` | Pulls JS URLs from context.get_urls correctly |
| `test_enum_js_endpoints_integration` | End-to-end: context → mine → persist |
| `test_cli_enum_js` | CLI command routes to correct function |

**Target: ~18 new tests.**

---

## Phase V5.2 — GraphQL Discovery

### New files

#### `src/boba/adapters/graphql_discover.py`

```python
class GraphqlDiscoverAdapter(BaseAdapter):
    """
    Probe live hosts for GraphQL endpoints.

    Overrides _execute: uses httpx directly instead of subprocess.
    Checks a list of known GraphQL paths against each target host.
    """
    TOOL_NAME = "graphql_discover"
    BINARY_NAMES = []       # no binary required
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "api_endpoint"
    SCOPE_MODE = "pre"

    # Common GraphQL endpoint paths (ordered by frequency in real programs)
    GRAPHQL_PATHS = [
        "/graphql",
        "/api/graphql",
        "/graphql/v1",
        "/v1/graphql",
        "/v2/graphql",
        "/gql",
        "/query",
        "/api/query",
        "/graphql/console",
    ]

    # Minimal introspection query — confirms endpoint is live GraphQL, not just 200
    _PROBE_QUERY = '{"query":"{__typename}"}'

    def find_binary(self) -> Path:
        return Path("graphql_discover")   # stub — never called

    def install_hint(self) -> str:
        return "Built-in — no install required"

    def build_command(self, targets, config):
        return ([], None)   # unused

    async def _execute(self, cmd, config) -> SubprocessResult:
        """Override: probe targets via httpx rather than subprocess."""
        # Populated by run() before _execute is called
        ...

    def parse_record(self, raw):
        ...  # maps probed result to api_endpoint schema

    def extract_scope_target(self, record):
        return record.get("url")
```

**Probe logic per target:**
1. For each host in targets × each path in `GRAPHQL_PATHS`:
   - POST `_PROBE_QUERY` with `Content-Type: application/json`
   - If response is 200 AND body contains `"__typename"` or `"data"` → confirmed GraphQL
   - If response is 400/422 AND body contains `"errors"` → likely GraphQL (returns error for minimal query)
   - Record: `{url, method: "POST", status_code, content_type, framework: "graphql", host, path}`
2. Skip paths that return identical responses to a non-GraphQL probe (WAF false-positive guard)

#### `src/boba/tools/enum.py` — new `graphql_discover()` function

```python
async def graphql_discover(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Probe live hosts for GraphQL endpoints.

    If no targets given, pulls alive host URLs from context.
    Persists confirmed endpoints to api_endpoints with framework='graphql'.
    """
```

### Schema changes: `graphql_schemas` table

```sql
CREATE TABLE IF NOT EXISTS graphql_schemas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    endpoint_url    TEXT NOT NULL,
    schema_json     TEXT NOT NULL DEFAULT '{}',
    type_count      INTEGER NOT NULL DEFAULT 0,
    query_count     INTEGER NOT NULL DEFAULT 0,
    mutation_count  INTEGER NOT NULL DEFAULT 0,
    introspection   INTEGER NOT NULL DEFAULT 1,   -- 1=full, 0=field-guessed
    discovered_at   TEXT NOT NULL,
    UNIQUE(hunt_id, endpoint_url)
);

CREATE INDEX IF NOT EXISTS idx_gql_schemas_hunt ON graphql_schemas(hunt_id);
```

Added to `_SCHEMA_SQL` in `context.py`. New `HuntContext` methods:

```python
def upsert_graphql_schema(self, hunt_id: str, record: dict[str, Any]) -> int: ...
def get_graphql_schemas(self, hunt_id: str) -> list[dict[str, Any]]: ...
```

### CLI additions

```
boba enum graphql [HUNT_ID] [--targets t1,t2]
boba context graphql-schemas [HUNT_ID]
```

### Tests

| Test | What it covers |
|---|---|
| `test_graphql_discover_confirmed` | `{__typename}` → 200 + data → confirmed |
| `test_graphql_discover_error_response` | 400 + errors → still recorded |
| `test_graphql_discover_false_positive_guard` | Non-GraphQL 200 ignored |
| `test_graphql_discover_waf` | WAF 403 on all paths → waf_detected |
| `test_graphql_discover_scope_filter` | Out-of-scope hosts excluded pre-probe |
| `test_graphql_discover_auto_targets` | Pulls from context when targets=None |
| `test_graphql_schema_upsert` | Schema stored + retrieved from DB |
| `test_cli_enum_graphql` | CLI command routes correctly |

**Target: ~12 new tests.**

---

## Phase V5.3 — GraphQL Schema Extraction

### New file: `src/boba/interaction/graphql.py`

```python
class GraphQLClient:
    """
    GraphQL schema extraction and query execution client.

    Built on top of HttpClient. Two schema discovery modes:
    1. Introspection: full schema via __schema query (when enabled)
    2. Field suggestion: Clairvoyance-style enumeration via error messages
       ("Did you mean X?" responses) when introspection is disabled
    """

    def __init__(self, http_client: HttpClient, endpoint_url: str):
        ...

    async def introspect(self, session: SessionState | None = None) -> dict | None:
        """
        Run full introspection query.
        Returns parsed schema dict or None if introspection is disabled.
        Schema dict keys: types, queries, mutations, subscriptions.
        """

    async def enumerate_fields(
        self,
        known_types: list[str] | None = None,
        wordlist: list[str] | None = None,
        session: SessionState | None = None,
        max_rounds: int = 3,
    ) -> dict:
        """
        Field suggestion enumeration (Clairvoyance approach).
        Sends queries with invalid field names, parses 'Did you mean X?' error messages.
        Returns partial schema: {type_name: [field_name, ...], ...}.
        """

    async def execute(
        self,
        query: str,
        variables: dict | None = None,
        session: SessionState | None = None,
    ) -> dict:
        """Execute an arbitrary GraphQL query. Returns parsed response."""

    async def execute_mutation(
        self,
        mutation: str,
        variables: dict | None = None,
        session: SessionState | None = None,
    ) -> dict:
        """Execute a GraphQL mutation."""
```

**Field suggestion algorithm:**
```
For each type in known_types (or start with "Query", "Mutation"):
  1. Send: { typeName { nonexistent_field } }
  2. If response contains "Did you mean": extract suggested fields
  3. Add discovered fields to known set
  4. Repeat until no new fields found (up to max_rounds)
```

#### `src/boba/tools/enum.py` — new `graphql_schema()` function

```python
async def graphql_schema(
    context: HuntContext,
    hunt: Hunt,
    endpoint_url: str,
    session: SessionState | None = None,
    http_client: HttpClient | None = None,
    try_field_enumeration: bool = True,
) -> dict:
    """
    Extract schema from a confirmed GraphQL endpoint.

    Tries full introspection first. Falls back to field suggestion enumeration
    if introspection is disabled and try_field_enumeration=True.
    Persists to graphql_schemas table. Returns schema dict.
    """
```

### CLI additions

```
boba enum graphql-schema [HUNT_ID] --url URL [--session SESSION] [--no-field-enum]
```

### Tests

| Test | What it covers |
|---|---|
| `test_graphql_introspect_success` | Full schema returned and parsed |
| `test_graphql_introspect_disabled` | 200 + error → returns None |
| `test_graphql_field_suggestion_parse` | "Did you mean" → extracted fields |
| `test_graphql_field_enum_rounds` | Multi-round enumeration converges |
| `test_graphql_execute_query` | Query execution with variables |
| `test_graphql_schema_persisted` | Schema stored to graphql_schemas |

**Target: ~10 new tests.**

---

## Phase V5.4 — GraphQL Vulnerability Testing

### New functions in `src/boba/tools/vuln.py` (or `vuln/graphql.py` post-refactor)

#### `test_graphql_idor`

```python
async def test_graphql_idor(
    gql_client: GraphQLClient,
    session_a: SessionState,
    session_b: SessionState,
    query_template: str,        # e.g. "{ user(id: ID_PLACEHOLDER) { email name } }"
    id_placeholder: str = "ID_PLACEHOLDER",
    object_ids: list[str] | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """
    Test for BOLA/IDOR on a GraphQL query.

    1. Execute query as User A (owner) with known object ID
    2. Execute same query as User B (attacker)
    3. Execute without auth
    4. Compare responses using _bodies_similar

    Extends IDOR logic: also tests ID enumeration via sequential/UUID variants
    if object_ids provided.
    """
```

#### `test_graphql_auth`

```python
async def test_graphql_auth(
    gql_client: GraphQLClient,
    query_or_mutation: str,     # full GQL operation
    session: SessionState | None = None,
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """
    Test authorization enforcement on a GraphQL operation.

    1. Execute without auth → should fail with authorization error
    2. Execute with session → baseline
    3. Check for privilege escalation patterns in schema (admin: Boolean fields)

    Also checks for introspection-as-information-disclosure:
    if introspection succeeds, that itself is a finding (INFO severity).
    """
```

#### `test_graphql_mass_assign`

```python
async def test_graphql_mass_assign(
    gql_client: GraphQLClient,
    mutation_template: str,     # mutation with FIELDS_PLACEHOLDER
    session: SessionState,
    extra_fields: dict | None = None,   # e.g. {"isAdmin": True, "role": "superuser"}
    scope_engine: Any | None = None,
    context: HuntContext | None = None,
    hunt_id: str = "",
) -> VulnTestResult:
    """
    Test GraphQL mutations for mass assignment.

    Attempts to inject privileged fields into mutation inputs.
    Checks response for evidence of field acceptance.
    """
```

### CLI additions

```
boba test graphql-idor [HUNT_ID] --url URL --query QUERY --session-a A --session-b B
boba test graphql-auth [HUNT_ID] --url URL --query QUERY [--session SESSION]
boba test graphql-mass-assign [HUNT_ID] --url URL --mutation MUTATION --session SESSION
```

### Tests

| Test | What it covers |
|---|---|
| `test_graphql_idor_detected` | Session B reads Session A's data → vulnerable |
| `test_graphql_idor_body_differ` | Per-user endpoint → not flagged |
| `test_graphql_idor_no_auth` | Unauth access → confirmed |
| `test_graphql_idor_enumeration` | object_ids iteration upgrades confidence |
| `test_graphql_auth_no_auth` | Unprotected operation → finding |
| `test_graphql_auth_introspection` | Enabled introspection → INFO finding |
| `test_graphql_mass_assign_field_accepted` | Injected field in response → vulnerable |
| `test_graphql_mass_assign_field_rejected` | Server ignores field → clean |
| `test_graphql_waf_detection` | WAF blocks all → waf_detected |
| `test_cli_test_graphql_idor` | CLI command routes correctly |
| `test_cli_test_graphql_auth` | CLI command routes correctly |
| `test_cli_test_graphql_mass_assign` | CLI command routes correctly |

**Target: ~18 new tests.**

---

## Rollout Summary

| Phase | Feature | New files | New tests | Est. version |
|---|---|---|---|---|
| V5.1 | JS endpoint mining | `tools/js_mine.py` | ~18 | 0.7.0 |
| V5.2 | GraphQL discovery + schema table | `adapters/graphql_discover.py`, schema migration | ~12 | 0.7.1 |
| V5.3 | GraphQL schema extraction | `interaction/graphql.py` | ~10 | 0.7.2 |
| V5.4 | GraphQL vuln testing | `tools/vuln.py` additions | ~18 | 0.7.3 |

**Total new tests across V5: ~58. Zero regressions expected** (no changes to existing method signatures or table schemas beyond additive migration).

---

## Integration into Agent Workflow

After V5, the full agent recon+enum pipeline becomes:

```
hunt create → subdomains → hosts → ports → urls → tech → secrets
           → crawl → js_endpoints   ← NEW: mines JS source
           → api (kiterunner)
           → graphql_discover       ← NEW: finds GraphQL endpoints
           → graphql_schema         ← NEW: extracts schema
           → parameters (arjun)
           → prioritize
           → test_idor / test_ssrf / test_xss / test_sqli / test_auth
           → test_graphql_idor / test_graphql_auth                ← NEW
           → detect_chains → report
```

JS mining feeds discovered endpoints directly into `api_endpoints`, where `prioritize_endpoints` picks them up automatically — no change to the analysis pipeline needed.

GraphQL findings use the same `findings` table, same `VulnTestResult` model, same chain detection rules (IDOR chain rule fires on `graphql_idor` finding type), and same report formatters. The only new surface for report templates is the GraphQL-specific PoC format (operation string + variables JSON instead of raw HTTP dump), which `reporting/poc.py` will need a small extension for.
