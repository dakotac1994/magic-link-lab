"""Magic-link token generation and verification.

Security properties:
- 256-bit tokens from `secrets` (CSPRNG) -> ~10^77 possibilities; guessing
  is computationally infeasible even at billions of attempts/second.
- Only the SHA-256 *hash* of a token is stored. A database leak does not
  expose usable login links.
- Comparison uses `hmac.compare_digest` to avoid timing side-channels.
"""

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32          # 256 bits of entropy
DEFAULT_TTL_SECONDS = 15 * 60  # magic links live 15 minutes


def generate_token() -> str:
    """Create a new URL-safe random token."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash a token for storage. The raw token never touches the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(provided: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented token against a stored hash."""
    return hmac.compare_digest(hash_token(provided), stored_hash)


def build_link(base_url: str, token: str) -> str:
    """Assemble the magic link the user clicks. base_url must be HTTPS."""
    base_url = base_url.rstrip("/")
    return f"{base_url}/auth/magic-link/verify?token={token}"
