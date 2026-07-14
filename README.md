# Auth Assignment — Register, Login, Protected Route

TypeScript + Express. Passwords hashed with `bcryptjs`, sessions handled with
a signed JWT (sent as an `Authorization: Bearer` header or an httpOnly cookie).

## Setup

```bash
npm install
cp .env.example .env   # then edit JWT_SECRET if you like
npm run dev            # starts on http://localhost:3000
```

## Routes

| Method | Route       | Auth needed | What it does                                  |
|--------|-------------|-------------|------------------------------------------------|
| POST   | `/register` | none        | `{ email, password }` → creates a user (hashed pw) |
| POST   | `/login`    | none        | `{ email, password }` → returns a JWT + sets cookie |
| POST   | `/logout`   | none        | clears the auth cookie                         |
| GET    | `/me`       | **yes**     | returns the logged-in user's profile           |
| GET    | `/admin`    | yes + admin role | demonstrates 403 vs 401                  |

## Try it with curl

```bash
# Register
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret123"}'

# Log in — grab the token from the JSON response
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"supersecret123"}'

# Call the protected route
curl http://localhost:3000/me -H "Authorization: Bearer <token>"

# No token / bad token -> 401
curl http://localhost:3000/me
```

## What to point out if you're asked to explain this

- **Where hashing happens:** `src/db.ts`, `createUser()` — `bcrypt.hash(password, 10)`.
  The plaintext password is never stored, only the hash.
- **Where the "who is calling" check happens:** `src/auth.ts`, `requireAuth`
  middleware. It reads the token, verifies its signature with `jwt.verify`,
  and attaches `req.user` if valid.
- **401 vs 403:** `requireAuth` returns 401 when there's no valid proof of
  identity at all. `requireRole` returns 403 when identity is known but the
  user isn't allowed to do that particular thing (see `/admin`).
- **Where "current user" comes from downstream:** any route after
  `requireAuth` can read `req.user.sub` (the user id) — that's the hook
  Thursday's isolation work will build on.

## Notes / things you might reasonably be asked in a review

- Users are stored in memory (`src/db.ts`) so data resets when the server
  restarts — swap in a real database once you're comfortable with the flow.
- `JWT_SECRET` in `.env.example` is a placeholder; never commit a real secret.
- Login intentionally returns the same error for "no such email" and "wrong
  password" — this avoids leaking which emails are registered.