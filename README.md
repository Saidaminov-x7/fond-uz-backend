# FondUz API

Fastify 5 API for the FondUz site and admin panel. Production storage uses PostgreSQL; shared rate limits use Redis. Passwords are bcrypt hashes. Admin sessions are short lived JWTs in HttpOnly, SameSite cookies.

## Run locally

Use Node.js 22 or newer and PostgreSQL. Install dependencies with `npm ci`, configure the environment, then run `npm run dev`. For production use `npm run build && npm start`.

Required environment variables: `DATABASE_URL`, `JWT_SECRET` (32+ characters), `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH` (bcrypt cost 10–14), and `CORS_ORIGINS` (comma-separated exact public frontend and admin origins). Production also requires `RATE_LIMIT_REDIS_URL` or `REDIS_URL`. If the API should only accept traffic from the Cloudflare Worker, set `CLOUDFLARE_ORIGIN_SECRET` to a random value of at least 32 characters and configure the same value as a Worker secret. Never commit secret values.

Run `npm run seed` once with `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `DATABASE_URL` to create or update the initial admin record. The seed hashes the password with bcrypt and does not seed fictitious public content. Remove `ADMIN_PASSWORD` from the environment after seeding. Keep `ADMIN_PASSWORD_HASH` configured for the API's fallback authentication path.

## Routes

- `GET /health`
- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/session`
- `GET /api/users/all` requires an admin session; the response removes password and token fields.
- Public `GET /api/doctors`, `/services`, `/funds`, `/news`, `/faqs`, and `/prices`
- Admin-only `POST`, `PATCH`, and `DELETE` for those content collections
- `POST /api/contacts` accepts validated contact form submissions

The API validates inputs, limits request bodies, applies security headers and rate limits, and uses parameterized SQL. User content is rendered as text by the frontend; HTML is not interpreted. Production refuses to start without PostgreSQL, Redis, a strong admin hash, and exact allowed origins.
