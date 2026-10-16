# FondUz API

Fastify 5 API used by the FondUz website and admin panel. PostgreSQL stores users and content. Redis backs shared rate limits. Node.js 22+ is required.

## Local development

```powershell
npm ci
npm run dev
```

Set the following server environment variables in an ignored `.env` file before starting the API:

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Production | PostgreSQL connection string |
| `JWT_SECRET` | Production | At least 32 characters; Railway can generate this value |
| `ADMIN_EMAIL` | Yes | Initial admin address, normalized to lowercase |
| `ADMIN_PASSWORD_HASH` or `ADMIN_PASSWORD` | Yes | bcrypt hash (cost 10–14), or an admin password of up to 72 UTF-8 bytes that is hashed at startup |
| `RATE_LIMIT_REDIS_URL` or `REDIS_URL` | Production | Redis connection string for shared rate limits |
| `CORS_ORIGINS` | Production | Comma-separated exact site and admin origins |
| `CLOUDFLARE_ORIGIN_SECRET` | Optional | Shared 32+ character secret that restricts requests to the trusted Cloudflare Worker |
| `DATABASE_SSL` | Optional | Set to `disable` only for a local PostgreSQL without TLS; otherwise PostgreSQL TLS is enabled |
| `PORT` | Optional | Listen port; Railway supplies this automatically |
| `LOG_LEVEL` | Optional | Fastify log level; set `silent` to disable request logs |

When `ADMIN_PASSWORD` is configured instead of `ADMIN_PASSWORD_HASH`, the API creates a bcrypt hash at startup. Production always requires a persistent `JWT_SECRET`; the development server may generate an ephemeral one when none is configured. Never place secrets in client-side variables or commit `.env` files.

## Build and verify

```powershell
npm run verify
npm start
```

`npm run verify` runs the TypeScript check, compiles the API, and starts a local security smoke check. The smoke check uses a temporary local admin account and does not connect to production data.

## Database and initial admin

On startup, the API creates the `app_records` table and indexes if needed. When `ADMIN_EMAIL` and a password/hash are configured, it creates or synchronizes that admin by email without deleting other users or content. If the variables are absent but PostgreSQL is configured, existing active admin records can authenticate from their stored bcrypt hash. Without PostgreSQL, both bootstrap values are required. Existing legacy plaintext passwords are migrated to bcrypt hashes. Passwords, hashes, and JWTs are not returned by the admin user endpoint.

For a one-time manual seed, configure `DATABASE_URL`, `ADMIN_EMAIL`, and a strong `ADMIN_PASSWORD` in a private environment and run `npm run seed`. The seed uses bcrypt and leaves public content unchanged. Remove the cleartext seed password afterwards. The normal Railway deployment can perform initial admin setup from the same configured `ADMIN_EMAIL` and `ADMIN_PASSWORD` at API startup.

## API routes

- `GET /health` checks the database and returns `503` if PostgreSQL cannot answer.
- `POST /api/auth/login`, `POST /api/auth/logout`, and `GET /api/auth/session` manage an eight-hour HttpOnly, SameSite session.
- `GET /api/users/all` requires an administrator session; password and token fields are filtered from the response.
- `GET /api/doctors`, `/api/services`, `/api/funds`, `/api/news`, `/api/faqs`, and `/api/prices` return public content.
- `POST`, `PATCH`, and `DELETE` on content collections require an administrator session.
- `POST /api/contacts` validates and stores a contact request.

Payloads are validated with Zod, request bodies are capped at 128 KiB, SQL is parameterized, Helmet sets security headers, and login/contact endpoints have dedicated rate limits. Public content responses have a short cache. The API returns user-supplied content as JSON text; the clients must continue rendering it as text rather than interpreting it as HTML.

## Railway deployment

This repository is deployed from `main` as the `fond-uz-backend` service in the FondUz production project. Railway builds with the repository Dockerfile and supplies `PORT` to the container. The generated domain currently targets port `8080`, matching the running instance; re-check the domain target if Railway changes the runtime port. Configure `DATABASE_URL`, `RATE_LIMIT_REDIS_URL`, `CORS_ORIGINS`, and `JWT_SECRET` as encrypted service variables. Add `ADMIN_EMAIL` and `ADMIN_PASSWORD` (or `ADMIN_PASSWORD_HASH`) to bootstrap or synchronize a named admin; if omitted, login uses existing admin rows in Postgres. Use Railway service references for Postgres and Redis URLs. The `/health` check verifies database availability. The public API is at `https://fond-uz-backend-production.up.railway.app`.

Do not copy production credentials into this repository or a public issue. Verify Railway deployment status and query `GET /health` after each deploy. A Railway `SUCCESS` status checks the service health route; it does not prove that either Next.js client is deployed or that an authenticated admin can sign in. Test those separately in their browser deployments.
