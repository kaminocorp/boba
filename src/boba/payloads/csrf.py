"""CSRF testing payloads and utilities."""

# Common CSRF token parameter names to look for in responses
TOKEN_PARAM_NAMES: list[str] = [
    "csrf_token",
    "csrftoken",
    "csrf",
    "_csrf",
    "authenticity_token",
    "__RequestVerificationToken",
    "anti-csrf-token",
    "X-CSRF-Token",
    "X-XSRF-TOKEN",
    "_token",
    "token",
]

# Headers that indicate CSRF protection
PROTECTION_HEADERS: list[str] = [
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
]

# Cross-origin headers for testing
CROSS_ORIGIN_HEADERS: dict[str, str] = {
    "Origin": "https://evil.com",
    "Referer": "https://evil.com/attack",
}
