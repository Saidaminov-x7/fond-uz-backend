# Logging audit — 2026-10-23

Scope: source, scripts, and package scripts in `fond-uz-backend`, `fond-uz-frontend`, and `fond-uz-admin-panel`. The search excluded dependency directories, generated build output, Git metadata, and lockfiles.

The audit searched for `console.log`, `console.error`, and `logger.info`, then checked their lines for `password`, `passwordHash`, `token`, `request.body`, and `cookie` references. It found no logging of credential values, complete request bodies, or cookie values, and no `logger.info` calls. The one sensitive-term match is a fixed status message in `fond-uz-backend/src/seed.ts` saying an admin account was initialized with a bcrypt password hash; it does not contain the hash or password. Other matches report check status, translation-audit errors/counts, and an optimized image's byte size.

Reproduction from the Fond_Uz workspace root (PowerShell):

```powershell
$roots = @('fond-uz-backend','fond-uz-frontend','fond-uz-admin-panel')
rtk proxy rg --no-heading --color never -n 'console\.(log|error)|logger\.info' $roots --glob '!**/node_modules/**' --glob '!**/.next/**' --glob '!**/dist/**' --glob '!**/build/**' --glob '!**/.git/**' --glob '!**/*.lock' --glob '!**/package-lock.json' --glob '!**/pnpm-lock.yaml' --glob '!**/yarn.lock'
rtk proxy rg --no-heading --color never -n '(console\.(log|error)|logger\.info).*(password|passwordHash|token|request\.body|cookie)|(password|passwordHash|token|request\.body|cookie).*(console\.(log|error)|logger\.info)' $roots --glob '!**/node_modules/**' --glob '!**/.next/**' --glob '!**/dist/**' --glob '!**/build/**' --glob '!**/.git/**' --glob '!**/*.lock' --glob '!**/package-lock.json' --glob '!**/pnpm-lock.yaml' --glob '!**/yarn.lock'
```

This is a static source audit. It does not claim to inspect hosting-provider logs or runtime traffic.
