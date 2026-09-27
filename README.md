# magic-link-lab

A runnable lab implementing a **secure magic-link service**: a time-limited,
single-use login URL delivered to an email address or phone number — no
password required. Built as a companion to the system-design lab series.

## What it teaches

Passwordless auth is simple to sketch and easy to get wrong. This lab
implements the full design, including every defense:

| Concept | Implementation |
|---|---|
| Unguessable tokens | 256-bit CSPRNG tokens (`secrets.token_urlsafe`) |
| Safe storage | Only the **SHA-256 hash** is stored; a DB leak yields no login links |
| Timing safety | `hmac.compare_digest` on verification |
| Time-limited | 15-minute TTL, enforced in the DB query |
| Single-use | Atomic consume — concurrent replays can't both succeed |
| No account enumeration | Request endpoint always returns the identical generic response |
| No verify oracle | Unknown / expired / used links share one generic 401 |
| Abuse protection | Token-bucket rate limits per IP and per identifier |
| Link rotation | A new link silently revokes older live ones |
| Delivery resilience | Primary/secondary provider failover (simulated SendGrid/Mailgun) |
| Sessions | Successful verify issues an HMAC-signed 24h session token |

## Quickstart

```bash
pip install -r requirements.txt

# narrated demo: happy path, scale math, then the attack reel
PYTHONPATH=src python -m magiclink.demo

# test suite
PYTHONPATH=src pytest -q

# serve the API
PYTHONPATH=src uvicorn magiclink.api:app
```

## API

```
POST /auth/magic-link          {"identifier": "ada@example.com", "channel": "email"}
  -> 200 {"status": "ok", "message": "If this identifier can receive magic links, one is on its way."}
     (always this response — valid, unknown, or malformed identifier alike)

GET /auth/magic-link/verify?token=<token>
  -> 200 {"status": "ok", "identifier": "...", "session_token": "..."}
  -> 401 {"status": "error", "message": "This link is invalid or has expired."}
```

## Layout

```
src/magiclink/
  tokens.py      token generation, hashing, constant-time compare
  store.py       SQLite registry: issue / lookup / atomic consume / purge
  delivery.py    simulated email+SMS providers with failover
  rate_limit.py  token-bucket limiters (per IP, per identifier)
  sessions.py    HMAC-signed session tokens
  api.py         FastAPI service + endpoints
  demo.py        narrated end-to-end demo incl. attack scenarios
tests/           pytest suite (core units + service + HTTP)
```

## Production notes

This is a teaching lab: delivery is simulated and the session secret is
in-process. A production deployment would add: real email/SMS providers,
a persistent database (the store already speaks SQLite; point it at a file),
secret rotation, audit logging, device-binding or IP-pinning of links,
and HTTPS-only cookies for the session token.

## License

MIT
