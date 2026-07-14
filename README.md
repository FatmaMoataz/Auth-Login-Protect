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
