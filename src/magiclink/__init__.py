"""magic-link-lab: a runnable passwordless-auth lab.

Request a link -> deliver it -> verify it -> get a session.
Then watch the attack reel: replay, expiry, brute force, enumeration.
"""

from .api import Service, create_app
from .delivery import DeliveryService, Provider
from .rate_limit import RateLimiter
from .sessions import SessionIssuer
from .store import MagicLinkStore
from .tokens import build_link, generate_token, hash_token

__all__ = ["Service", "create_app", "DeliveryService", "Provider",
           "RateLimiter", "SessionIssuer", "MagicLinkStore",
           "build_link", "generate_token", "hash_token"]
