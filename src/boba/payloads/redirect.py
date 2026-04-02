"""Open redirect payloads — URL manipulation techniques."""

# Direct external URLs
DIRECT: list[str] = [
    "https://evil.com",
    "http://evil.com",
    "https://evil.com/",
]

# Protocol-relative
PROTOCOL_RELATIVE: list[str] = [
    "//evil.com",
    "///evil.com",
    "////evil.com",
]

# Backslash tricks
BACKSLASH: list[str] = [
    "https://evil.com\\@target.com",
    "/\\evil.com",
    "\\/evil.com",
]

# URL encoding bypasses
ENCODED: list[str] = [
    "https://evil.com%00",
    "https://evil.com%0d%0a",
    "%2F%2Fevil.com",
    "/%2f/evil.com",
]

# Subdomain confusion
SUBDOMAIN: list[str] = [
    "https://target.com.evil.com",
    "https://targetcom.evil.com",
]

# All payloads combined
ALL: list[str] = DIRECT + PROTOCOL_RELATIVE + BACKSLASH + ENCODED + SUBDOMAIN
