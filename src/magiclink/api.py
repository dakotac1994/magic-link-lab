"""FastAPI service wiring the whole magic-link flow together.

Endpoints
---------
POST /auth/magic-link        {"identifier", "channel"} -> always the same
                             generic response. Never reveals whether the
                             identifier exists (anti-enumeration).
GET  /auth/magic-link/verify?token=...  -> 200 + session token on success,
                             401 with a generic message otherwise (no oracle
                             distinguishing "bad token" from "expired").

Run with:  uvicorn magiclink.api:app  (PYTHONPATH=src)
"""

import re
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .delivery import default_delivery
from .rate_limit import default_limiters
from .sessions import SessionIssuer, new_server_secret
from .store import MagicLinkStore
from .tokens import build_link, generate_token

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9\s\-().]{7,20}$")
BASE_URL = "https://example.com"

_GENERIC_REQUEST_MSG = ("If this identifier can receive magic links, "
                        "one is on its way.")
_GENERIC_VERIFY_MSG = "This link is invalid or has expired."


class MagicLinkRequest(BaseModel):
    identifier: str
    channel: str = "email"  # "email" | "sms"


class Service:
    """The domain logic, independent of HTTP -- easy to test directly."""

    def __init__(self, store=None, delivery=None, limiters=None,
                 sessions=None, base_url: str = BASE_URL):
        self.store = store or MagicLinkStore()
        self.delivery = delivery or default_delivery()
        self.limiters = limiters or default_limiters()
        self.sessions = sessions or SessionIssuer(new_server_secret())
        self.base_url = base_url

    # -- request a link ---------------------------------------------------
    def _valid_identifier(self, identifier: str, channel: str) -> bool:
        identifier = identifier.strip()
        if channel == "email":
            return bool(EMAIL_RE.match(identifier))
        if channel == "sms":
            return bool(PHONE_RE.match(identifier))
        return False

    def request_link(self, identifier: str, channel: str,
                     ip: str | None = None) -> dict:
        """Always returns the generic response. Sends a link only when the
        identifier is well-formed and the rate limiters allow it."""
        identifier = identifier.strip().lower()
        if (self._valid_identifier(identifier, channel)
                and self.limiters["request_per_ip"].allow(f"ip:{ip}")
                and self.limiters["request_per_identifier"].allow(
                    f"ident:{identifier}")):
            token = generate_token()
            self.store.issue(token, identifier, channel, ip=ip)
            link = build_link(self.base_url, token)
            try:
                self.delivery.deliver(identifier, channel, link)
            except RuntimeError:
                pass  # provider outage: keep the generic response, log in prod
        return {"status": "ok", "message": _GENERIC_REQUEST_MSG}

    # -- verify a link ----------------------------------------------------
    def verify_link(self, token: str, ip: str | None = None) -> dict:
        """Exchange a magic link for a session. Single-use, TTL-enforced."""
        if not self.limiters["verify_per_ip"].allow(f"ip:{ip}"):
            raise _unauthorized()
        row = self.store.consume(token)
        if row is None:
            # Same response for unknown / expired / already-used: no oracle.
            raise _unauthorized()
        session = self.sessions.create(row["identifier"])
        return {"status": "ok", "identifier": row["identifier"],
                "session_token": session}


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail=_GENERIC_VERIFY_MSG)


def create_app(service: Service | None = None) -> FastAPI:
    service = service or Service()
    app = FastAPI(title="magic-link-lab")

    @app.post("/auth/magic-link")
    def post_magic_link(body: MagicLinkRequest, request: Request):
        ip = request.client.host if request.client else None
        return service.request_link(body.identifier, body.channel, ip=ip)

    @app.get("/auth/magic-link/verify")
    def get_verify(token: str, request: Request):
        ip = request.client.host if request.client else None
        return service.verify_link(token, ip=ip)

    @app.exception_handler(HTTPException)
    async def _http_handler(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code,
                            content={"status": "error", "message": exc.detail})

    return app


app = create_app()
