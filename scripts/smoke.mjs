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
const base = `http://127.0.0.1:${port}`;
try {
  let healthy = false;
  for (let i = 0; i < 50; i++) {
    if (child.exitCode !== null) throw new Error(`backend exited early (${child.exitCode})`);
    try { const response = await fetch(`${base}/health`); if (response.ok) { healthy = true; break; } } catch { await new Promise((resolve) => setTimeout(resolve, 200)); }
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
  const changedToken = cookie.replace(/.$/, cookie.endsWith("a") ? "b" : "a");
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
  process.stdout.write("BACKEND_SECURITY_SMOKE_PASSED: health, auth, JWT tampering, password redaction, inert XSS JSON, and spoof-resistant contact limits\n");
} finally {
  child.kill("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 300));
  if (child.exitCode === null) child.kill("SIGKILL");
}
