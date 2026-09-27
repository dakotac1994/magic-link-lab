"""Unit tests: tokens, store, delivery, rate limiter, sessions."""

import time

import pytest

from magiclink.delivery import DeliveryService, Provider
from magiclink.rate_limit import RateLimiter
from magiclink.sessions import SessionIssuer
from magiclink.store import MagicLinkStore
from magiclink.tokens import build_link, generate_token, hash_token, tokens_match

T0 = 1_750_000_000.0


# --- tokens -------------------------------------------------------------
def test_tokens_are_unique_and_url_safe():
    toks = {generate_token() for _ in range(1000)}
    assert len(toks) == 1000
    for t in toks:
        assert "+" not in t and "/" not in t and "=" not in t


def test_token_hash_is_stable_and_hides_raw_value():
    t = generate_token()
    assert hash_token(t) == hash_token(t)
    assert t not in hash_token(t)
    assert len(hash_token(t)) == 64  # sha256 hex


def test_tokens_match_uses_constant_time_compare():
    t = generate_token()
    assert tokens_match(t, hash_token(t))
    assert not tokens_match(t + "x", hash_token(t))


def test_build_link_points_at_verify_endpoint():
    link = build_link("https://example.com/", "abc123")
    assert link == "https://example.com/auth/magic-link/verify?token=abc123"


# --- store --------------------------------------------------------------
def test_store_issue_and_lookup_roundtrip():
    s = MagicLinkStore()
    s.issue("tok-1", "Ada@Example.com", "email", now=T0)
    row = s.lookup("tok-1")
    assert row["identifier"] == "ada@example.com"  # normalized
    assert row["channel"] == "email"
    assert row["consumed_at"] is None
    assert row["token_hash"] == hash_token("tok-1")


def test_store_never_stores_raw_token():
    s = MagicLinkStore()
    s.issue("super-secret-token", "a@b.c", "email", now=T0)
    rows = s._conn.execute("SELECT token_hash FROM magic_links").fetchall()
    assert all("super-secret-token" not in r["token_hash"] for r in rows)


def test_consume_happy_path_and_replay_blocked():
    s = MagicLinkStore()
    s.issue("tok-2", "a@b.c", "email", now=T0)
    assert s.consume("tok-2", now=T0 + 5) is not None
    assert s.consume("tok-2", now=T0 + 6) is None  # replay -> None


def test_consume_rejects_expired_and_unknown():
    s = MagicLinkStore()
    s.issue("tok-3", "a@b.c", "email", now=T0, ttl=60)
    assert s.consume("tok-3", now=T0 + 61) is None
    assert s.consume("nope", now=T0) is None


def test_new_issue_revokes_prior_live_links():
    s = MagicLinkStore()
    s.issue("old", "a@b.c", "email", now=T0)
    s.issue("new", "a@b.c", "email", now=T0 + 1)
    assert s.consume("old", now=T0 + 2) is None
    assert s.consume("new", now=T0 + 2) is not None


def test_purge_expired_removes_dead_rows():
    s = MagicLinkStore()
    s.issue("dead", "a@b.c", "email", now=T0, ttl=1)
    s.issue("live", "a@b.c", "email", now=T0, ttl=3600)
    assert s.purge_expired(now=T0 + 10) == 1
    assert s.live_count(now=T0 + 10) == 1


# --- delivery -----------------------------------------------------------
def test_delivery_failover_to_secondary():
    primary = Provider("sendgrid", fail_rate=1.0)
    secondary = Provider("mailgun")
    svc = DeliveryService(primary, secondary)
    assert svc.deliver("a@b.c", "email", "https://x/y") == "mailgun"
    assert svc.failover_count == 1
    assert len(svc.outbox) == 1


def test_delivery_all_providers_down_raises():
    svc = DeliveryService(Provider("p1", fail_rate=1.0),
                          Provider("p2", fail_rate=1.0))
    with pytest.raises(RuntimeError):
        svc.deliver("a@b.c", "email", "https://x/y")


def test_last_link_for_returns_newest():
    svc = DeliveryService(Provider("p"))
    svc.deliver("a@b.c", "email", "https://x/1")
    svc.deliver("a@b.c", "email", "https://x/2")
    assert svc.last_link_for("A@B.C") == "https://x/2"


# --- rate limiter -------------------------------------------------------
def test_rate_limiter_capacity_and_refill():
    rl = RateLimiter(capacity=2, refill_per_second=1.0)
    assert rl.allow("k", now=T0)
    assert rl.allow("k", now=T0)
    assert not rl.allow("k", now=T0)          # bucket empty
    assert rl.allow("k", now=T0 + 1.5)          # refilled 1.5 tokens
    assert not rl.allow("other", now=T0) is False  # independent keys


def test_rate_limiter_keys_are_independent():
    rl = RateLimiter(capacity=1, refill_per_second=0.0)
    assert rl.allow("a", now=T0)
    assert rl.allow("b", now=T0)
    assert not rl.allow("a", now=T0)


# --- sessions -----------------------------------------------------------
def test_session_create_and_validate():
    iss = SessionIssuer("s3cret" * 8)
    tok = iss.create("ada@example.com", now=T0)
    payload = iss.validate(tok, now=T0 + 100)
    assert payload["sub"] == "ada@example.com"


def test_session_rejects_tampering_and_expiry():
    iss = SessionIssuer("s3cret" * 8)
    tok = iss.create("ada@example.com", ttl=60, now=T0)
    head, sig = tok.rsplit(".", 1)
    assert iss.validate(head + ".0000", now=T0) is None       # forged sig
    assert iss.validate("garbage", now=T0) is None            # malformed
    assert iss.validate(tok, now=T0 + 61) is None             # expired
    other = SessionIssuer("different" * 8)
    assert other.validate(tok, now=T0) is None                # wrong secret
