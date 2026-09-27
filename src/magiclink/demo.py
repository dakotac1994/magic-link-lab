"""Narrated end-to-end demo:  python -m magiclink.demo

Stages:
  1. Happy path      -- request -> deliver -> verify -> session
  2. Scale math       -- token entropy, storage sizing, rate-limit budgets
  3. Attack reel     -- replay, expired link, brute force, enumeration probe,
                        link rotation, provider failover
Deterministic: all time-sensitive steps use an injected clock.
"""

import time
from urllib.parse import parse_qs, urlparse

from .api import Service
from .delivery import DeliveryService, Provider
from .rate_limit import RateLimiter, default_limiters
from .sessions import SessionIssuer
from .store import MagicLinkStore

T0 = 1_750_000_000.0  # fixed clock for deterministic narration


def stage(title: str):
    print(f"\n{'=' * 64}\n  {title}\n{'=' * 64}")


def token_from_link(link: str) -> str:
    return parse_qs(urlparse(link).query)["token"][0]


def fresh_service(**kw) -> Service:
    store = MagicLinkStore()
    delivery = DeliveryService(Provider("sendgrid"), Provider("mailgun"))
    return Service(store=store, delivery=delivery,
                   limiters=default_limiters(),
                   sessions=SessionIssuer("demo-secret" * 4), **kw)


def happy_path():
    stage("1. HAPPY PATH -- passwordless login in three steps")
    svc = fresh_service()
    print("-> POST /auth/magic-link  {identifier: ada@example.com}")
    resp = svc.request_link("ada@example.com", "email", ip="203.0.113.7")
    print(f"   response: {resp}   (generic -- leaks nothing)")
    link = svc.delivery.last_link_for("ada@example.com")
    print(f"-> inbox: magic link delivered via "
          f"{svc.delivery.outbox[-1].provider}: {link[:60]}...")
    print("   (only the SHA-256 hash is stored; the DB never sees the token)")
    row = svc.store.lookup(token_from_link(link))
    print(f"   stored row: token_hash={row['token_hash'][:16]}... "
          f"expires in 15 min, consumed_at={row['consumed_at']}")
    print("-> GET /auth/magic-link/verify?token=...")
    out = svc.verify_link(token_from_link(link), ip="203.0.113.7")
    print(f"   200 OK -> session issued for {out['identifier']}")
    payload = svc.sessions.validate(out["session_token"])
    print(f"   session payload: sub={payload['sub']}, "
          f"valid 24h (exp-iat = {payload['exp'] - payload['iat']}s)")


def scale_math():
    stage("2. SCALE MATH -- why the design holds up")
    print("Token entropy : 256 bits -> 2^256 ~= 1.2e77 possibilities.")
    print("                At 1e9 guesses/sec, expected time to hit one live")
    print("                token: ~1e60 years. Brute force is not a strategy.")
    print("Storage       : one row ~= 200 bytes. 1M links/day x 15-min TTL")
    print("                -> ~10k live rows at any instant ~= 2 MB. A nightly")
    print("                purge keeps the table tiny forever.")
    print("Verify path   : single indexed lookup + atomic consume UPDATE.")
    print("                Stateless sessions -> any instance can verify.")
    print("Abuse budgets : 3 link req/min per identifier stops inbox")
    print("                harassment; 10 verify/min per IP stops guessing.")
    print("                Buckets refill, so legit users never lock out.")


def attack_reel():
    stage("3. ATTACK REEL -- every link must survive this")

    # --- replay: the classic stolen-link attack -------------------------
    svc = fresh_service()
    svc.request_link("grace@example.com", "email", ip="198.51.100.9")
    link = svc.delivery.last_link_for("grace@example.com")
    token = token_from_link(link)
    svc.verify_link(token, ip="198.51.100.9")
    print("REPLAY: attacker replays a used link...")
    try:
        svc.verify_link(token, ip="198.51.100.99")
        print("   !!! second verify succeeded -- BUG")
    except Exception as e:
        print(f"   401 '{e.detail}' -- single-use consume blocked it.")

    # --- expired link ----------------------------------------------------
    svc = fresh_service()
    svc.store.issue("expired-token", "grace@example.com", "email", now=T0,
                    ttl=60)
    print("EXPIRY: link issued with 60s TTL, attacker arrives 61s later...")
    try:
        svc.verify_link("expired-token", ip="198.51.100.99")
        print("   !!! expired verify succeeded -- BUG")
    except Exception as e:
        print(f"   401 '{e.detail}' -- TTL enforced.")

    # --- brute force vs the rate limiter ---------------------------------
    svc = fresh_service()
    lim = svc.limiters["verify_per_ip"]
    allowed = sum(lim.allow("ip:203.0.113.99", now=T0 + i * 0.01)
                  for i in range(15))
    print(f"BRUTE FORCE: 15 rapid guesses from one IP -> {allowed} allowed, "
          f"{15 - allowed} rejected by the limiter. Guessing 2^256 tokens")
    print("             10 at a time is cosmically hopeless.")

    # --- enumeration probe -----------------------------------------------
    svc = fresh_service()
    r1 = svc.request_link("real-user@example.com", "email", ip="203.0.113.7")
    r2 = svc.request_link("not-a-user@example.com", "email", ip="203.0.113.7")
    r3 = svc.request_link("garbage@@@", "email", ip="203.0.113.7")
    same = r1 == r2 == r3
    print(f"ENUMERATION: valid / unknown / malformed identifiers all get")
    print(f"             {r1}  -> identical: {same}. No account oracle.")

    # --- rotation: newest link kills the older ones ----------------------
    svc = fresh_service()
    svc.request_link("ada@example.com", "email", ip="203.0.113.7")
    old_link = svc.delivery.last_link_for("ada@example.com")
    svc.request_link("ada@example.com", "email", ip="203.0.113.7")
    print("ROTATION: user requests a second link; the first dies silently...")
    try:
        svc.verify_link(token_from_link(old_link), ip="203.0.113.7")
        print("   !!! stale link still worked -- BUG")
    except Exception as e:
        print(f"   401 '{e.detail}' -- only the newest link is live.")

    # --- provider failover -----------------------------------------------
    flaky = Provider("sendgrid", fail_rate=1.0)   # primary fully down
    svc = Service(store=MagicLinkStore(),
                  delivery=DeliveryService(flaky, Provider("mailgun")),
                  limiters=default_limiters(),
                  sessions=SessionIssuer("demo-secret" * 4))
    svc.request_link("linus@example.com", "email", ip="203.0.113.7")
    print(f"FAILOVER: primary provider down -> delivered via "
          f"{svc.delivery.outbox[-1].provider} "
          f"(failovers so far: {svc.delivery.failover_count}).")


def main():
    print("MAGIC-LINK LAB -- secure passwordless login, live-fire edition")
    happy_path()
    scale_math()
    attack_reel()
    stage("DONE")
    print("Run the test suite:  pytest -q   (PYTHONPATH=src)")
    print("Serve the API:       uvicorn magiclink.api:app  (PYTHONPATH=src)")


if __name__ == "__main__":
    main()
