"""Database schema DDL for all hunt tables."""

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hunts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    scope_json  TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id     TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,
    rule_type   TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'include',
    UNIQUE(hunt_id, pattern, rule_type)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    subdomain     TEXT NOT NULL,
    root_domain   TEXT,
    sources       TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, subdomain)
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    ip              TEXT,
    port            INTEGER NOT NULL DEFAULT 0,
    scheme          TEXT NOT NULL DEFAULT '',
    url             TEXT,
    status_code     INTEGER,
    title           TEXT,
    webserver       TEXT,
    content_length  INTEGER,
    content_type    TEXT,
    technologies    TEXT DEFAULT '[]',
    tls_version     TEXT,
    final_url       TEXT,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_checked_at TEXT NOT NULL,
    UNIQUE(hunt_id, host, port, scheme)
);

CREATE TABLE IF NOT EXISTS ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    ip            TEXT,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, port, protocol)
);

CREATE TABLE IF NOT EXISTS urls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    host          TEXT,
    path          TEXT,
    query         TEXT,
    method        TEXT NOT NULL DEFAULT 'GET',
    status_code   INTEGER,
    sources       TEXT NOT NULL DEFAULT '[]',
    found_on      TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, url, method)
);

CREATE TABLE IF NOT EXISTS technologies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT,
    detail        TEXT,
    sources       TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, name)
);

CREATE TABLE IF NOT EXISTS directories (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id           TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url               TEXT NOT NULL,
    input_value       TEXT,
    status_code       INTEGER NOT NULL,
    content_length    INTEGER,
    word_count        INTEGER,
    line_count        INTEGER,
    content_type      TEXT,
    redirect_location TEXT,
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url)
);

CREATE TABLE IF NOT EXISTS parameters (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    method        TEXT NOT NULL DEFAULT 'GET',
    name          TEXT NOT NULL,
    param_type    TEXT NOT NULL DEFAULT 'query',
    sources       TEXT NOT NULL DEFAULT '[]',
    confirmed     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(hunt_id, url, method, name, param_type)
);

CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    secret_type     TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    repo            TEXT NOT NULL DEFAULT '',
    line_number     INTEGER,
    match_preview   TEXT NOT NULL DEFAULT '',
    commit_sha      TEXT NOT NULL DEFAULT '',
    author          TEXT NOT NULL DEFAULT '',
    date            TEXT NOT NULL DEFAULT '',
    entropy         REAL,
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, repo, file_path, rule_id, line_number)
);

CREATE INDEX IF NOT EXISTS idx_secrets_hunt ON secrets(hunt_id);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(hunt_id, secret_type);

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
    framework       TEXT NOT NULL DEFAULT '',
    sources         TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url, method)
);

CREATE INDEX IF NOT EXISTS idx_api_hunt ON api_endpoints(hunt_id);
CREATE INDEX IF NOT EXISTS idx_api_host ON api_endpoints(hunt_id, host);

CREATE TABLE IF NOT EXISTS tool_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    tool_name        TEXT NOT NULL,
    command_json     TEXT NOT NULL,
    status           TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    duration_seconds REAL,
    exit_code        INTEGER,
    records_found    INTEGER,
    records_filtered INTEGER,
    timed_out        INTEGER DEFAULT 0,
    error_message    TEXT
);

CREATE INDEX IF NOT EXISTS idx_subdomains_hunt    ON subdomains(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_hunt         ON hosts(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_status       ON hosts(hunt_id, status_code);
CREATE INDEX IF NOT EXISTS idx_ports_hunt         ON ports(hunt_id);
CREATE INDEX IF NOT EXISTS idx_ports_host         ON ports(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_urls_hunt          ON urls(hunt_id);
CREATE INDEX IF NOT EXISTS idx_urls_host          ON urls(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_technologies_hunt  ON technologies(hunt_id);
CREATE INDEX IF NOT EXISTS idx_directories_hunt   ON directories(hunt_id);
CREATE INDEX IF NOT EXISTS idx_parameters_hunt    ON parameters(hunt_id);
CREATE INDEX IF NOT EXISTS idx_parameters_url     ON parameters(hunt_id, url);
CREATE INDEX IF NOT EXISTS idx_tool_runs_hunt     ON tool_runs(hunt_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_status   ON tool_runs(hunt_id, status);

-- ═══════════════════ V2: Interaction tables ═══════════════════

CREATE TABLE IF NOT EXISTS http_history (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id               TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    session_name          TEXT,
    tool_run_id           INTEGER REFERENCES tool_runs(id),
    source                TEXT NOT NULL DEFAULT 'manual',

    method                TEXT NOT NULL,
    url                   TEXT NOT NULL,
    host                  TEXT NOT NULL,
    path                  TEXT NOT NULL DEFAULT '/',
    query                 TEXT,
    request_headers       TEXT NOT NULL DEFAULT '{}',
    request_body          TEXT,
    request_body_ref      TEXT,
    content_type          TEXT,

    status_code           INTEGER,
    response_headers      TEXT DEFAULT '{}',
    response_body         TEXT,
    response_body_ref     TEXT,
    response_length       INTEGER,
    response_content_type TEXT,

    elapsed_ms            REAL,
    tls_version           TEXT,
    ip_address            TEXT,
    resource_type         TEXT,
    is_redirect           INTEGER DEFAULT 0,
    redirect_url          TEXT,

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

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    finding_type     TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'info',
    title            TEXT NOT NULL,
    description      TEXT,
    url              TEXT,
    endpoint         TEXT,
    parameter        TEXT NOT NULL DEFAULT '',
    method           TEXT NOT NULL DEFAULT '',
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
    UNIQUE(hunt_id, finding_type, url, method, parameter)
);

CREATE INDEX IF NOT EXISTS idx_findings_hunt     ON findings(hunt_id);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(hunt_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(hunt_id, severity);

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

-- ═══════════════════ V3: Analysis tables ═══════════════════

CREATE TABLE IF NOT EXISTS coverage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    parameter       TEXT NOT NULL DEFAULT '',
    test_type       TEXT NOT NULL,
    tested_at       TEXT NOT NULL,
    tool_run_id     INTEGER REFERENCES tool_runs(id),
    finding_id      INTEGER REFERENCES findings(id),
    notes           TEXT,
    UNIQUE(hunt_id, url, method, parameter, test_type)
);

CREATE INDEX IF NOT EXISTS idx_coverage_hunt      ON coverage(hunt_id);
CREATE INDEX IF NOT EXISTS idx_coverage_url       ON coverage(url);
CREATE INDEX IF NOT EXISTS idx_coverage_test_type ON coverage(test_type);

CREATE TABLE IF NOT EXISTS dedup_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    canonical_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    reason          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, canonical_id)
);

CREATE INDEX IF NOT EXISTS idx_dedup_hunt ON dedup_groups(hunt_id);

CREATE TABLE IF NOT EXISTS chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    confidence      TEXT NOT NULL DEFAULT 'hypothetical',
    cvss_score      REAL,
    cvss_vector     TEXT,
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    chain_order     TEXT NOT NULL DEFAULT '[]',
    impact          TEXT,
    prerequisites   TEXT DEFAULT '[]',
    tags            TEXT DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, title)
);

CREATE INDEX IF NOT EXISTS idx_chains_hunt     ON chains(hunt_id);
CREATE INDEX IF NOT EXISTS idx_chains_severity ON chains(severity);

CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id             TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    finding_id          INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    chain_id            INTEGER REFERENCES chains(id) ON DELETE CASCADE,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    cvss_score          REAL,
    cvss_vector         TEXT,
    summary             TEXT,
    steps               TEXT DEFAULT '[]',
    impact              TEXT,
    remediation         TEXT,
    evidence_refs       TEXT DEFAULT '[]',
    request_ids         TEXT DEFAULT '[]',
    platform            TEXT,
    platform_report_id  TEXT,
    platform_status     TEXT,
    submitted_at        TEXT,
    status              TEXT NOT NULL DEFAULT 'draft',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE(hunt_id, finding_id, chain_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_finding
    ON reports(hunt_id, finding_id) WHERE chain_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_chain
    ON reports(hunt_id, chain_id) WHERE finding_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_reports_hunt   ON reports(hunt_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
"""
