import { spawn } from "node:child_process";
import { randomBytes, randomInt } from "node:crypto";
import bcrypt from "bcryptjs";

const port = randomInt(43_000, 49_000);
const adminEmail = "smoke-admin@example.invalid";
const adminPassword = "temporary-smoke-password-not-for-use";
const passwordHash = await bcrypt.hash(adminPassword, 10);
const child = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "src/server.ts"], {
  cwd: process.cwd(),
  env: { ...process.env, PORT: String(port), NODE_ENV: "development", LOG_LEVEL: "silent", JWT_SECRET: randomBytes(48).toString("base64url"), ADMIN_EMAIL: adminEmail, ADMIN_PASSWORD_HASH: passwordHash, DATABASE_URL: "", REDIS_URL: "", RATE_LIMIT_REDIS_URL: "", CLOUDFLARE_ORIGIN_SECRET: "" },
  stdio: "ignore",
});
let spawnError;
child.on("error", (error) => { spawnError = error; });
const base = `http://127.0.0.1:${port}`;
try {
  let healthy = false;
  for (let i = 0; i < 120; i++) {
    if (spawnError) throw new Error(`backend could not start: ${spawnError.message}`);
    if (child.exitCode !== null) throw new Error(`backend exited early (${child.exitCode})`);
    try { const response = await fetch(`${base}/health`); if (response.ok) { healthy = true; break; } } catch { await new Promise((resolve) => setTimeout(resolve, 250)); }
  }
  if (!healthy) throw new Error("health endpoint did not become ready");
  const unauth = await fetch(`${base}/api/users/all?limit=1`);
  if (unauth.status !== 401) throw new Error(`unauthenticated /api/users/all returned ${unauth.status}`);
  const publicNews = await fetch(`${base}/api/news`);
  if (publicNews.status !== 200) throw new Error("public news endpoint failed");
  const login = await fetch(`${base}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: adminEmail, password: adminPassword }) });
  if (login.status !== 200) throw new Error("configured admin could not sign in");
  const cookie = login.headers.get("set-cookie")?.split(";")[0];
  if (!cookie?.startsWith("fond_session=")) throw new Error("admin session cookie was not set");
  const authed = await fetch(`${base}/api/users/all?limit=1`, { headers: { cookie } });
  if (authed.status !== 200) throw new Error(`authenticated user enumeration returned ${authed.status}`);
  const users = await authed.json();
  if (users.items.length !== 1 || users.items[0].email !== adminEmail || "passwordHash" in users.items[0] || "password" in users.items[0]) throw new Error("user API leaked a password field or omitted the admin user");
  const [cookieName, token] = cookie.split("=", 2);
  const tokenSegments = token.split(".");
  tokenSegments[1] = `${tokenSegments[1][0] === "a" ? "b" : "a"}${tokenSegments[1].slice(1)}`;
  const changedToken = `${cookieName}=${tokenSegments.join(".")}`;
  const tampered = await fetch(`${base}/api/users/all`, { headers: { cookie: changedToken } });
  if (tampered.status !== 401) throw new Error("tampered JWT was accepted");
  const payload = `<img src=x onerror=alert(1)> <script>alert(2)</script>`;
  const created = await fetch(`${base}/api/news`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ slug: "xss-smoke", title: payload, subtitle: "xss test", date: "2026-10-15", content: [payload] }) });
  if (created.status !== 201 || !created.headers.get("content-type")?.includes("application/json")) throw new Error("XSS payload was not handled as JSON data");
  const listed = await fetch(`${base}/api/news`);
  const serialized = await listed.text();
  if (!serialized.includes(JSON.stringify(payload))) throw new Error("XSS test payload did not round-trip as text data");
  for (let i = 0; i < 6; i++) {
    const response = await fetch(`${base}/api/contacts`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `198.51.100.${i + 1}` }, body: JSON.stringify({ name: "Test User", email: `xss-test-${i}@example.invalid`, phone: "+998900000000", message: "Automated rate limit check" }) });
    if (i < 5 && response.status !== 201) throw new Error(`contact rate limit blocked request ${i + 1} early`);
    if (i === 5 && response.status !== 429) throw new Error("contact rate limit was bypassed with spoofed X-Forwarded-For");
  }
  let olderItem;
  for (let i = 0; i < 101; i++) {
    const title = i === 0 ? payload : `pagination-smoke-${i}`;
    const response = await fetch(`${base}/api/news`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ slug: `pagination-smoke-${i}`, title, subtitle: "CRUD pagination regression", date: "2026-10-16", content: [payload] }) });
    if (response.status !== 201) throw new Error(`content create ${i + 1}/101 returned ${response.status}`);
    const createdBody = await response.json();
    if (i === 0) olderItem = createdBody.item;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  if (!olderItem?.id || !olderItem.createdAt) throw new Error("oldest regression record was not created");
  const forgedDate = "2000-01-01T00:00:00.000Z";
  const patched = await fetch(`${base}/api/news/${encodeURIComponent(olderItem.id)}`, { method: "PATCH", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ id: "forged-id", createdAt: forgedDate, updatedAt: forgedDate, title: "patched pagination regression" }) });
  if (patched.status !== 200) throw new Error(`PATCH for a record outside the newest 100 returned ${patched.status}`);
  const patchedItem = (await patched.json()).item;
  if (patchedItem.id !== olderItem.id || patchedItem.createdAt !== olderItem.createdAt || patchedItem.updatedAt === forgedDate || patchedItem.title !== "patched pagination regression") throw new Error("PATCH allowed client metadata to replace the record identity or timestamps");
  const pages = await Promise.all([0, 100].map((offset) => fetch(`${base}/api/news?limit=100&offset=${offset}`).then((response) => response.json())));
  const persisted = pages.flatMap((page) => page.items).find((item) => item.id === olderItem.id);
  if (!persisted || persisted.title !== "patched pagination regression" || persisted.createdAt !== olderItem.createdAt) throw new Error("PATCH for the old record did not persist with its original identity and creation date");
  const deleted = await fetch(`${base}/api/news/${encodeURIComponent(olderItem.id)}`, { method: "DELETE", headers: { cookie } });
  if (deleted.status !== 204) throw new Error(`DELETE for a record outside the newest 100 returned ${deleted.status}`);
  process.stdout.write("BACKEND_SECURITY_SMOKE_PASSED: health, auth, JWT tampering, password redaction, inert XSS JSON, spoof-resistant contact limits, and CRUD beyond 100 with immutable metadata\n");
} finally {
  child.kill("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 300));
  if (child.exitCode === null) child.kill("SIGKILL");
}
