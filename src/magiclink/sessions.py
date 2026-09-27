"""Session issuance after a successful magic-link verify.

A verified link is exchanged for a short-lived, HMAC-signed session token
(stateless, like a JWT but minimal -- no dependency needed). Verifying only
needs the server secret, so any app instance can accept the session.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

SESSION_TTL_SECONDS = 24 * 3600  # sessions live 24h


def new_server_secret() -> str:
    return secrets.token_hex(32)


class SessionIssuer:
    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def _sign(self, payload_b64: str) -> str:
        sig = hmac.new(self.secret, payload_b64.encode("utf-8"),
                       hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def create(self, identifier: str,
               ttl: int = SESSION_TTL_SECONDS,
               now: float | None = None) -> str:
        now = time.time() if now is None else now
        payload = {"sub": identifier.strip().lower(),
                   "iat": int(now), "exp": int(now + ttl)}
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{payload_b64}.{self._sign(payload_b64)}"

    def validate(self, session_token: str,
                 now: float | None = None) -> dict | None:
        """Return the payload dict when the signature checks out and the
        session is unexpired; None otherwise."""
        now = time.time() if now is None else now
        try:
            payload_b64, sig = session_token.rsplit(".", 1)
        except ValueError:
            return None
        if not hmac.compare_digest(sig, self._sign(payload_b64)):
            return None
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        if payload.get("exp", 0) <= now:
            return None
        return payload
