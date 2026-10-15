# Cloudflare edge setup

The Worker is ready to use after a Cloudflare DNS zone, three public hostnames, and the Vercel/Railway origins are available. It adds an origin secret and routes the website and admin hosts to Vercel and the API host to Railway. The secret stays out of browser code.

## Required values

Create these DNS names in a Cloudflare zone you own:

- `FRONTEND_HOST`: public website hostname
- `ADMIN_HOST`: admin hostname
- `API_HOST`: API hostname

Set `FRONTEND_ORIGIN` and `ADMIN_ORIGIN` to HTTPS `*.vercel.app` deployment origins. Set `BACKEND_ORIGIN` to the HTTPS `*.up.railway.app` API origin.

## Deploy and configure the Worker

1. Deploy `worker.js` as a Cloudflare Worker.
2. Set the three `*_HOST` and three `*_ORIGIN` values in Worker settings.
3. Create a random origin secret with at least 32 characters and set it using `wrangler secret put ORIGIN_SECRET` or the Worker secrets UI.
4. Add routes `<FRONTEND_HOST>/*`, `<ADMIN_HOST>/*`, and `<API_HOST>/*` to the Worker.
5. Set the same secret as `CLOUDFLARE_ORIGIN_SECRET` in the frontend, admin, and backend server environments.
6. Set the frontend `NEXT_PUBLIC_API_URL` to `https://<API_HOST>` and server-side `API_URL` to the same API origin. Set `API_URL` in the admin panel too.
7. Set backend `CORS_ORIGINS` to the exact HTTPS frontend and admin origins, separated by commas.
8. Set backend `RATE_LIMIT_REDIS_URL` to its private Redis URL and configure `JWT_SECRET`, `ADMIN_EMAIL`, and the bcrypt `ADMIN_PASSWORD_HASH` as private Railway variables.

Do not enable origin-secret checks before the Worker routes and all three server secrets are ready, or public requests will be denied. The API keeps Redis-backed rate limits as a second layer behind Cloudflare.

## Rate-limit rules

In Cloudflare Security rules, add per-IP limits for `POST /api/auth/login` (5 requests per minute), `POST /api/contacts` (5 requests per 15 minutes), and `/api/*` (300 requests per minute). The available actions and windows depend on your zone plan.

Direct activation still needs a verified zone/domain and permission to configure Worker routes. No domain was supplied, so this repository contains the Worker and configuration guide only.
