# FondUz API

Fastify 5 API for the FondUz public site and admin panel. It stores users and content in PostgreSQL, and uses Redis for shared request rate limits when deployed. The container uses Node.js 22 and reads its listening port from `PORT` (default `4000` for local use).

## Local development

Requirements: Node.js 22+, npm, and a PostgreSQL database if you want data to survive process restarts. Redis is optional for local development; without it, rate limits are held in process memory.

```powershell
npm ci
npm run dev
```

Create an ignored `.env` in this directory. For an in-memory local run, set a development `JWT_SECRET` of at least 32 characters, `ADMIN_EMAIL`, and either `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`. For PostgreSQL-backed development, also set `DATABASE_URL`. `DATABASE_SSL=disable` is intended only for a local PostgreSQL instance without TLS; otherwise TLS is enabled. `PORT` defaults to `4000`.

The server creates the `app_records` table and its indexes on startup. Without PostgreSQL, records exist only in memory and are lost when the process stops. Do not use this mode for deployed data.

## Environment variables

Set these in the API service environment, not in frontend build-time variables. Treat every value containing a credential or shared secret as confidential.

| Variable | Required | Runtime behavior |
| --- | --- | --- |
| `DATABASE_URL` | Yes in production | PostgreSQL connection string. The server requires this in production, creates the `app_records` table/indexes, and checks PostgreSQL from `/health`. |
| `JWT_SECRET` | Yes in production | JWT signing key, at least 32 characters. Development can generate an ephemeral key; that invalidates sessions after restart. |
| `ADMIN_EMAIL` | Recommended for production bootstrap | Initial admin email, trimmed and lowercased. When used with a password setting, startup creates or synchronizes this admin record. |
| `ADMIN_PASSWORD_HASH` | Alternative to `ADMIN_PASSWORD` | bcrypt hash with cost 10 to 14. Prefer a hash where the platform can store it safely. |
| `ADMIN_PASSWORD` | Alternative to `ADMIN_PASSWORD_HASH` | Password hashed with bcrypt cost 12 during startup; maximum 72 UTF-8 bytes. Use only as an encrypted Railway variable and remove it after bootstrap if the operational process allows. |
| `RATE_LIMIT_REDIS_URL` | Yes in production | Redis connection string for shared rate limits. `REDIS_URL` is accepted as a fallback name. A Redis connection failure prevents startup. |
| `CORS_ORIGINS` | Yes in production | Comma-separated exact origins for the public site and admin panel, including scheme and any non-default port; no path or trailing slash. Requests without an `Origin` header are allowed by the CORS hook. |
| `CLOUDFLARE_ORIGIN_SECRET` | Optional | If set, requires matching `X-Fonduz-Origin` on all requests except `/health`; minimum 32 characters. Configure the same secret in the trusted Cloudflare Worker. This is a shared-origin check, not a substitute for authentication. |
| `DATABASE_SSL` | Optional | Set to `disable` only for local PostgreSQL without TLS. Otherwise the PostgreSQL client enables TLS and accepts the server certificate as configured by the current implementation. |
| `PORT` | Platform supplied in production | HTTP listen port. Railway supplies this automatically; local default is `4000`. |
| `LOG_LEVEL` | Optional | Fastify log level; defaults to `info`. Set to `silent` to suppress request logs. |
| `NODE_ENV` | Set by the container | Production mode enables secure session cookies and enforces production configuration. |

Do not commit `.env` or put secrets in a `NEXT_PUBLIC_*` variable. The checked-in `.gitignore` excludes `.env` files.

## Admin setup and data persistence

On startup, PostgreSQL-backed deployments create the `app_records` table and indexes if missing. If both `ADMIN_EMAIL` and either password setting are present, startup synchronizes the matching admin email: it updates that record's password hash and sets `active` to `true`, or inserts a new admin if none matches. This synchronization runs on every restart while those variables remain configured. Remove the password variable after bootstrap if subsequent password rotations are managed through a separate process; confirm that the existing admin can sign in before changing service variables.

If no bootstrap password is configured, an existing active admin row in PostgreSQL can sign in with its stored bcrypt `passwordHash`. Existing legacy user password fields are migrated to bcrypt hashes during startup and plaintext fields are removed. The user-list endpoint removes the `passwordHash`, `password`, `passwordPlain`, `token`, and `resetToken` properties from returned rows.

`npm run seed` is a one-time local/operational utility, not the normal Railway startup path. It requires `DATABASE_URL`, `ADMIN_EMAIL`, and an `ADMIN_PASSWORD` with at least 14 characters and at most 72 UTF-8 bytes, and upserts the fixed `initial-admin` record. Review the target database before running it: using it against a database that already contains that ID can replace its data. Normal API startup bootstrap is keyed by email and is the recommended Railway setup.

## API contract

All API payloads and responses are JSON. Collection reads return `{ items, total, limit, offset }`, ordered newest first; `limit` is clamped to 1–100 (default 50) and `offset` is non-negative (default 0). Public content reads include a short shared-cache header. Admin user reads set `Cache-Control: no-store` and remove `passwordHash`, `password`, `passwordPlain`, `token`, and `resetToken` properties.

| Route | Access | Behavior |
| --- | --- | --- |
| `GET /health` | Public | Returns `200 { "status": "ok" }` when the API is running and PostgreSQL answers `SELECT 1`; returns `503 { "status": "unavailable" }` if that database check fails. It does not verify Redis or client deployment. |
| `POST /api/auth/login` | Public, rate limited | Accepts `{ email, password }`; returns `{ success, user }` and sets an eight-hour `fond_session` HttpOnly, SameSite=Strict cookie on success. Invalid credentials return `401`. |
| `POST /api/auth/logout` | Public | Clears the `fond_session` cookie. |
| `GET /api/auth/session` | Admin session | Returns the authenticated user's email and role. |
| `GET /api/users/all` | Admin session | Paginated users with the listed password and token fields removed. |
| `GET /api/contacts` | Admin session | Paginated contact submissions containing visitor PII; no public read route. Only known contact fields are returned, with `Cache-Control: no-store`. |
| `GET /api/doctors`, `/api/services`, `/api/funds`, `/api/news`, `/api/faqs`, `/api/prices` | Public | Paginated collection records. |
| `POST /api/doctors`, `/api/services`, `/api/funds`, `/api/news`, `/api/faqs`, `/api/prices` | Admin session | Creates a record and returns `201 { item }`. |
| `PATCH /api/{collection}/:id` | Admin session | Updates allowed content fields by exact record ID, regardless of pagination position; returns `404` if no matching record is found. `id` and `createdAt` stay server-managed, and `updatedAt` is set by the API. |
| `DELETE /api/{collection}/:id` | Admin session | Deletes a matching record by exact ID, regardless of pagination position; returns `204`, or `404` if not found. |
| `POST /api/contacts` | Public, rate limited | Accepts name, message, and at least one reply method (`email` or `phone`); returns `201 { success: true }`. `consent` is an optional boolean for compatibility and is stored when supplied. |

The content body accepts up to 40 fields, with string values up to 8,000 characters, arrays of up to 50 strings (2,000 characters each), finite numbers, and booleans. Contact fields are validated separately: name 2–120 characters, email up to 254 characters when provided, phone up to 32 characters when provided, and message 5–3,000 characters. At least one non-empty email or phone is required. Contact consent, when provided, must be boolean and is stored with the submission. Request bodies are capped at 128 KiB. SQL values are parameterized. The API stores supplied content as JSON; clients must render it as text, not as executable HTML.

The global rate limit is 120 requests per minute per client address; login is limited to 5 per minute and contact submissions to 5 per 15 minutes. In production Redis is mandatory so these limits are shared between instances. The app does not trust arbitrary `X-Forwarded-For`; when a valid Cloudflare origin secret is configured, it uses Cloudflare's connecting IP header only for verified proxy requests.

## Build and local verification

```powershell
npm run verify
npm start
```

`npm run verify` runs TypeScript checking, builds `dist/`, then runs a local security smoke check covering health, unauthenticated/admin access, login cookie, JWT tampering, credential-field redaction, JSON handling of HTML-like content, and contact rate-limit spoof resistance. The smoke check starts an isolated in-memory development server with temporary credentials; it does not contact or modify production services or production data.

## Railway deployment and operational checks

The repository's `railway.toml` selects the checked-in `Dockerfile`, configures `/health` as the health check, and restarts on failure. The Docker image builds with Node.js 22, compiles TypeScript, installs production dependencies, and runs `npm start`. The API binds to Railway's `PORT`; Docker's `EXPOSE 4000` is documentation for the local default, not a fixed Railway routing port.

For the `fond-uz-backend` production service, configure encrypted Railway variables for `DATABASE_URL`, `JWT_SECRET`, `RATE_LIMIT_REDIS_URL` (or `REDIS_URL`), and `CORS_ORIGINS`. Add `ADMIN_EMAIL` with either `ADMIN_PASSWORD_HASH` or `ADMIN_PASSWORD` for initial admin bootstrap. Use Railway service references for managed PostgreSQL and Redis where possible. Configure `CLOUDFLARE_ORIGIN_SECRET` only when the Worker is set up to send the matching header; otherwise direct API requests will receive `403` except for `/health`.

Release checklist:

1. Run `npm run verify` against the exact source revision to deploy.
2. Confirm Railway built the intended commit and reports the service healthy; inspect startup logs for configuration or database/Redis failures without copying secret values.
3. Request `GET https://fond-uz-backend-production.up.railway.app/health`; expect HTTP `200` and `{ "status": "ok" }`. A healthy response proves database reachability, not Redis behavior, successful admin login, or a deployed/working frontend.
4. Verify the public content endpoints and admin login/session through the configured clients. Do not run destructive CRUD checks on production data without a separate approved test record and cleanup plan.

The production service hostname above is the configured API hostname recorded for this project; confirm it in Railway before use if the service domain has changed. Do not put production credentials in this repository, browser automation logs, or issue descriptions.
