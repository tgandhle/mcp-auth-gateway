"""PKCE (RFC 7636) helpers for clients acquiring tokens to call this gateway.

The gateway itself verifies tokens; it does not run the authorization-code
flow. But MCP clients do, and PKCE is mandatory for public clients under
OAuth 2.1. These helpers generate a compliant verifier/challenge pair and
build the authorization-request URL, so a client (or a test harness) can drive
the flow without pulling in a heavier OAuth library.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class PkcePair:
    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce() -> PkcePair:
    """Create a high-entropy code_verifier and its S256 challenge.

    RFC 7636 requires the verifier to be 43-128 chars from the unreserved set.
    32 random bytes -> 43 base64url chars, the minimum-compliant strong choice.
    """
    verifier = _b64url(secrets.token_bytes(32))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = _b64url(digest)
    return PkcePair(verifier=verifier, challenge=challenge, method="S256")


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    pkce: PkcePair,
    state: str | None = None,
    audience: str | None = None,
) -> tuple[str, str]:
    """Return (url, state). Caller should persist (state, pkce.verifier) and
    compare on callback. Never log the verifier."""
    state = state or _b64url(secrets.token_bytes(16))
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": pkce.challenge,
        "code_challenge_method": pkce.method,
    }
    if audience:
        params["audience"] = audience
    return f"{authorization_endpoint}?{urlencode(params)}", state
