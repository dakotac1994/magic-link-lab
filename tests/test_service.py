"""Service + HTTP tests: the full request/verify flow and its guarantees."""

import re
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from magiclink.api import Service, create_app
from magiclink.delivery import DeliveryService, Provider
from magiclink.rate_limit import RateLimiter, default_limiters
from magiclink.sessions import SessionIssuer
from magiclink.store import MagicLinkStore

T0 = 1_750_000_000.0
GENERIC = "If this identifier can receive magic links, one is on its way."


def make_service(**kw) -> Service:
    kw.setdefault("store", MagicLinkStore())
    kw.setdefault("delivery",
                  DeliveryService(Provider("sendgrid"), Provider("mailgun")))
    kw.setdefault("limiters", default_limiters())
    kw.setdefault("sessions", SessionIssuer("test-secret" * 4))
    return Service(**kw)


def token_from_link(link: str) -> str:
    return parse_qs(urlparse(link).query)["token"][0]


# --- request path -------------------------------------------------------
def test_request_returns_generic_response_and_sends_link():
    svc = make_service()
    resp = svc.request_link("ada@example.com", "email", ip="10.0.0.1")
    assert resp == {"status": "ok", "message": GENERIC}
    assert svc.delivery.last_link_for("ada@example.com") is not None


def test_request_response_identical_for_unknown_and_malformed():
    # Passwordless means anyone can request a link for any well-formed
    # identifier -- the inbox IS the authentication. The guarantee is only
    # that the *response* reveals nothing.
    svc = make_service()
    r1 = svc.request_link("real@example.com", "email", ip="10.0.0.1")
    r2 = svc.request_link("nobody@example.com", "email", ip="10.0.0.2")
    r3 = svc.request_link("not-an-email", "email", ip="10.0.0.3")
    assert r1 == r2 == r3
    assert svc.delivery.last_link_for("nobody@example.com") is not None
    assert svc.delivery.last_link_for("not-an-email") is None  # malformed: no send


def test_request_rate_limited_per_identifier():
    limiters = default_limiters()
    limiters["request_per_identifier"] = RateLimiter(capacity=1,
                                                    refill_per_second=0)
    svc = make_service(limiters=limiters)
    svc.request_link("vic@example.com", "email", ip="10.0.0.1")
    svc.request_link("vic@example.com", "email", ip="10.0.0.2")
    sent = [m for m in svc.delivery.outbox
            if m.identifier == "vic@example.com"]
    assert len(sent) == 1  # second request swallowed, response still generic


def test_sms_channel_validates_phone_numbers():
    svc = make_service()
    svc.request_link("+1 415-555-0132", "sms", ip="10.0.0.1")
    assert svc.delivery.last_link_for("+1 415-555-0132") is not None
    svc.request_link("not-a-phone", "sms", ip="10.0.0.1")
    assert svc.delivery.last_link_for("not-a-phone") is None


# --- verify path --------------------------------------------------------
def test_verify_happy_path_issues_session():
    svc = make_service()
    svc.request_link("ada@example.com", "email", ip="10.0.0.1")
    token = token_from_link(svc.delivery.last_link_for("ada@example.com"))
    out = svc.verify_link(token, ip="10.0.0.1")
    assert out["status"] == "ok" and out["identifier"] == "ada@example.com"
    assert svc.sessions.validate(out["session_token"])["sub"] == "ada@example.com"


def test_verify_replay_rejected_with_generic_401():
    svc = make_service()
    svc.request_link("ada@example.com", "email", ip="10.0.0.1")
    token = token_from_link(svc.delivery.last_link_for("ada@example.com"))
    svc.verify_link(token, ip="10.0.0.1")
    with pytest.raises(HTTPException) as ei:
        svc.verify_link(token, ip="10.0.0.1")
    assert ei.value.status_code == 401


def test_verify_unknown_expired_share_one_generic_error():
    svc = make_service()
    svc.store.issue("short-lived", "a@b.c", "email", now=T0, ttl=1)
    with pytest.raises(HTTPException) as e1:
        svc.verify_link("totally-bogus", ip="10.0.0.1")
    with pytest.raises(HTTPException) as e2:
        svc.verify_link("short-lived", ip="10.0.0.1")  # real clock: expired
    assert e1.value.status_code == e2.value.status_code == 401
    assert e1.value.detail == e2.value.detail  # no oracle


def test_verify_rate_limited_per_ip():
    limiters = default_limiters()
    limiters["verify_per_ip"] = RateLimiter(capacity=1, refill_per_second=0)
    svc = make_service(limiters=limiters)
    svc.request_link("ada@example.com", "email", ip="10.0.0.1")
    token = token_from_link(svc.delivery.last_link_for("ada@example.com"))
    svc.verify_link(token, ip="10.0.0.9")
    with pytest.raises(HTTPException) as ei:
        svc.verify_link("anything", ip="10.0.0.9")
    assert ei.value.status_code == 401


# --- HTTP layer ---------------------------------------------------------
@pytest.fixture()
def client_and_service():
    svc = make_service()
    return TestClient(create_app(svc)), svc


def test_http_request_returns_generic_message(client_and_service):
    client, _ = client_and_service
    r = client.post("/auth/magic-link",
                    json={"identifier": "http@example.com", "channel": "email"})
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "message": GENERIC}


def test_http_verify_flow(client_and_service):
    client, svc = client_and_service
    client.post("/auth/magic-link",
                json={"identifier": "web@example.com", "channel": "email"})
    link = svc.delivery.last_link_for("web@example.com")
    token = token_from_link(link)
    r = client.get("/auth/magic-link/verify", params={"token": token})
    assert r.status_code == 200
    assert r.json()["identifier"] == "web@example.com"
    assert "session_token" in r.json()
    # replay over HTTP
    r2 = client.get("/auth/magic-link/verify", params={"token": token})
    assert r2.status_code == 401
    assert r2.json()["message"] == "This link is invalid or has expired."


def test_http_verify_unknown_token_is_401(client_and_service):
    client, _ = client_and_service
    r = client.get("/auth/magic-link/verify", params={"token": "nope"})
    assert r.status_code == 401
    assert r.json()["status"] == "error"
