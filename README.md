# FastAPI Authentication Tutorials

Two self-contained FastAPI projects that implement user authentication in the two ways you'll meet in the wild:

| | Project | Mechanism | State |
|---|---|---|---|
| 1 | `session_with_cookies_hashing_tut/6_FastApi_` | Server-side session + signed cookie | **Stateful** |
| 2 | `oAuth_JWT_multi_route_tut` | OAuth2 password flow + JWT bearer token | **Stateless** |

Both use `bcrypt` for password hashing, Pydantic v2 for request/response validation, and a plain `database.json` file as the "database" so there's nothing to install or migrate.

---

## Repository structure

```
FASTAPI/
├── oAuth_JWT_multi_route_tut/
│   ├── .env
│   ├── database.json
│   └── main.py                  # OAuth2 + JWT app
│
└── session_with_cookies_hashing_tut/
    ├── .env
    ├── 5_create_hash.py         # standalone bcrypt demo
    └── 6_FastApi_/
        ├── database.json
        ├── main.py              # session + cookie app
        └── request_sender.py    # httpx client that persists cookies
```

---

## Requirements

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install fastapi uvicorn "pydantic>=2" bcrypt PyJWT python-dotenv python-multipart itsdangerous httpx
```

Notes on the packages that trip people up:

- **PyJWT** — install `PyJWT`, import `jwt`. Do *not* `pip install jwt`; that's an unrelated squatter package without `jwt.encode`.
- **python-multipart** — required by `OAuth2PasswordRequestForm`, which reads `application/x-www-form-urlencoded` bodies.
- **itsdangerous** — required by Starlette's `SessionMiddleware` to sign the cookie.

Both apps expect a `database.json` next to `main.py`, seeded with:

```json
{
    "ALL_SESSION_ID": []
}
```

---

## Project 1 — Sessions with cookies

`session_with_cookies_hashing_tut/6_FastApi_/main.py`

The server keeps the identity; the browser only carries a signed cookie pointing at it.

### Run

```bash
python session_with_cookies_hashing_tut/6_FastApi_/main.py
# → http://127.0.0.1:8786/docs
```

### Flow

1. `POST /signup` — validates the payload, bcrypt-hashes the password, writes the user to `database.json` with `user_session_id = -1` (meaning "no session yet").
2. `POST /login` with credentials — verifies the password with `bcrypt.checkpw`, allocates a session id, and stores `userName` + `user_session_id` in `request.session`. Starlette signs that into the `my_session_cookie` response cookie.
3. `POST /login` with **no body** — the cookie comes back on the request, `request.session` is populated, and the user is recognised without credentials.
4. `POST /logout` — `request.session.clear()` drops the session.

### Endpoints

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/` | — | health check |
| POST | `/signup` | `UserRequest` JSON | register |
| POST | `/login` | `UserLoginData` JSON *or* nothing | credential login / cookie login |
| POST | `/logout` | — | clear session |

### Middleware config

```python
my_custom_app.add_middleware(
    SessionMiddleware,
    secret_key=sec_key,
    session_cookie="my_session_cookie",
    max_age=60,          # seconds — cookie lifetime
    same_site="lax",     # "strict" | "lax" | "none"
    https_only=False,    # set True in production
)
```

### Testing with `request_sender.py`

`/docs` can't easily demonstrate the cookie round-trip, so this script uses `httpx.AsyncClient`, which persists cookies across requests like a browser:

```bash
python session_with_cookies_hashing_tut/6_FastApi_/request_sender.py
```

It signs up, logs in with credentials (printing the cookie jar), then logs in again sending *only* the cookie.

### `5_create_hash.py`

A standalone bcrypt walkthrough — reads `PASSWORD` from `.env`, hashes it, and verifies it:

```python
pwd_bytes = password.encode("utf-8")[:72]        # bcrypt's 72-byte input limit
hashed = bcrypt.hashpw(pwd_bytes, bcrypt.gensalt(rounds=12, prefix=b"2b"))
bcrypt.checkpw(pwd_bytes, hashed)                # → True
```

`rounds=12` is the cost factor: higher is slower and therefore more resistant to brute force.

---

## Project 2 — OAuth2 password flow with JWT

`oAuth_JWT_multi_route_tut/main.py`

No server-side session. The token itself carries the identity, signed so it can't be tampered with.

### Run

```bash
python oAuth_JWT_multi_route_tut/main.py
# → http://127.0.0.1:8786/docs
```

### Flow

1. `POST /signup` — same as project 1, plus a `gender` field.
2. `POST /login` — takes an `OAuth2PasswordRequestForm` (form fields `username` / `password`, **not** JSON), verifies the password, and returns:
   ```json
   { "access_token": "eyJhbGciOi...", "token_type": "bearer" }
   ```
   The payload holds `sub` (username), `iat` (issued at), and `exp` (expiry).
3. `GET /users/me` — the `validate_user_identity_using_token` dependency pulls the token out of the `Authorization` header, decodes it, and resolves the user.
4. `POST /logout` — JWTs are stateless, so there's nothing to invalidate server-side; the response just tells the client to discard its token.

### Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | — | health check |
| POST | `/signup` | — | register |
| POST | `/login` | form data | issue token |
| GET | `/users/me` | Bearer | current user |
| POST | `/logout` | Bearer | client-side token discard |

### Sending the token

The token goes in a **header**, not a query string:

```bash
curl -H "Authorization: Bearer eyJhbGciOi..." http://127.0.0.1:8786/users/me
```

`OAuth2PasswordBearer` only reads the `Authorization` header — `?token=...` is invisible to it and yields `401 {"detail": "Not authenticated"}`.

In `/docs`, click **Authorize** (top right), log in there, and Swagger attaches the header to every protected route automatically.

### JWT config

```python
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60
```

`HS256` is symmetric — the same secret signs and verifies. Keep the secret in `.env` and load it with `load_dotenv()`; if you generate it at import time with `secrets.token_hex(16)`, every `--reload` restart invents a new key and silently invalidates all outstanding tokens.

**API gotcha:** `encode` takes the singular, `decode` takes a plural list.

```python
jwt.encode(payload, SECRET, algorithm="HS256")      # algorithm=
jwt.decode(token, SECRET, algorithms=["HS256"])     # algorithms=[...]
```

---

## Validation models

Both apps share the same shape, defined with Pydantic v2:

```python
class UserRequest(BaseModel):
    userName: str = Field(min_length=3, max_length=20)
    password: str = Field(min_length=10, max_length=15)
    userDescription: Optional[str] = None
    userEmail: str = Field(pattern=r"^[\w.-]+@[\w.-]+\.\w+$")
    age: Optional[int] = Field(default=None, ge=18, le=100)
    gender: Literal["Male", "Female"] | None = None    # JWT project only
```

A `@field_validator("password")` additionally enforces at least one lowercase letter, one uppercase letter, one digit, and one special character.

`Literal["Male", "Female"] | None` restricts the field to a fixed set of string *values* while keeping the runtime type a plain `str` — `Optional["Male" | "Female"]` is a `TypeError`, since `|` unions types, not values.

---

## Sessions vs JWT

| | Session + cookie | JWT |
|---|---|---|
| Where identity lives | Server | Inside the token |
| Revoke a login | Clear the session | Not possible without a denylist |
| Scales across servers | Needs shared session store | Any server with the secret |
| Sent by | Browser, automatically | Client, in `Authorization` |
| Payload visible to client | No | Yes — base64, **not encrypted** |
| Best for | Server-rendered apps, same-origin | APIs, mobile, multi-service |

JWT payloads are signed, not encrypted. Anyone holding the token can read `sub`, `iat`, and `exp`. Never put secrets in one.

---

## Security caveats

This is tutorial code. Before anything resembling production:

- Replace `database.json` with a real database — concurrent writes to a JSON file will corrupt it.
- Move `secret_key` / `JWT_DUMMY_SECRET_KEY` into `.env` and keep `.env` out of git.
- Set `https_only=True` and `same_site="strict"` on the session cookie.
- Drop the 15-character password ceiling; long passphrases are strictly better.
- Shorten JWT expiry and add a refresh-token flow.
- Return an identical error for "user not found" and "wrong password" so the API can't be used to enumerate accounts.

---

## License

MIT
