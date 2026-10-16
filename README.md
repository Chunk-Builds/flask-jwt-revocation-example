# Flask JWT Revocation Example

A minimal, single-file Flask API that shows how to make **logout actually revoke JWTs**.
It uses Flask-JWT-Extended's `token_in_blocklist_loader` with a SQLAlchemy blocklist of token IDs (`jti`).

This is the companion code for the tutorial: [ARTICLE LINK]

## What it does

| Endpoint | Auth | Description |
|---|---|---|
| `POST /auth/register` | – | Create a user and get an access token (15 min) and a refresh token (30 days) |
| `POST /auth/login` | – | Exchange email and password for the same token pair |
| `POST /auth/refresh` | refresh token | Get a new access token |
| `POST /auth/logout` | access **or** refresh token | Revoke the token you send |
| `GET /auth/me` | access token | Protected route. Returns 401 once the token is revoked |

There's also a CLI command, `flask --app app prune-blocklist`, which deletes blocklist rows older than the refresh-token lifetime. Those tokens have expired anyway.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/Chunk-Builds/flask-jwt-revocation-example && cd flask-jwt-revocation-example
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
export JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export DATABASE_URL="sqlite:///app.db"   # optional; this is the default
flask --app app run
```

If `JWT_SECRET_KEY` isn't set, the app warns and uses a random key that lasts only for that process, so every token becomes invalid on restart. Always set it outside local experiments.

## Tests

```bash
pytest -q
```

The 3 tests check that:
- logging out revokes the access token (`/auth/me` then returns 401)
- logging out with the refresh token stops it from refreshing
- an access token is rejected by `/auth/refresh`

## curl demo

```bash
B=http://127.0.0.1:5000

# Register and capture the access token
TOKEN=$(curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"a@example.com","password":"supersecret"}' \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s $B/auth/me -H "Authorization: Bearer $TOKEN"
# {"email":"a@example.com","id":1}

curl -s -X POST $B/auth/logout -H "Authorization: Bearer $TOKEN"
# {"message":"Token revoked"}

curl -s $B/auth/me -H "Authorization: Bearer $TOKEN"
# {"error":"Token has been revoked"}   (HTTP 401)
```

## Trade-offs

- **Every protected request hits the database.** That gives up some of the "stateless" benefit of JWTs. For high traffic, move the blocklist to Redis with a TTL equal to the token's remaining lifetime.
- **Logout revokes only the token you send.** A client should call logout with both its access and refresh tokens. "Log out of all devices" needs a per-user token version or a revoke-all timestamp, which isn't included here.
- **The blocklist grows** until you prune it. Run `prune-blocklist` on a schedule, for example with cron.
- **Short access tokens limit the damage** if a token leaks. The 15-minute lifetime is a reasonable default.
- **This is a teaching example, not a full app.** It has no input-validation library, rate limiting, migrations, email verification or password reset. `db.create_all()` stands in for migrations.

## Want more?

*Optional:* if you want a fuller base with user CRUD, marshmallow validation, Flask-Migrate, a pytest suite and Docker/Postgres/Gunicorn, I sell a **Flask REST API Starter Kit** (₹799) on Topmate (India only): [topmate.io/chunkbuilds](https://topmate.io/chunkbuilds)

## License

MIT © 2026 chunkbuilds. See [LICENSE](LICENSE).
