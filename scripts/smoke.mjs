import { spawn } from "node:child_process";
import { randomBytes, randomInt } from "node:crypto";
import bcrypt from "bcryptjs";

const port = randomInt(43_000, 49_000);
const adminEmail = "smoke-admin@example.invalid";
const adminPassword = "temporary-smoke-password-not-for-use";
const passwordHash = await bcrypt.hash(adminPassword, 10);
const serverEnv = { ...process.env, NODE_ENV: "development", LOG_LEVEL: "silent", JWT_SECRET: randomBytes(48).toString("base64url"), ADMIN_EMAIL: adminEmail, ADMIN_PASSWORD_HASH: passwordHash, DATABASE_URL: "", REDIS_URL: "", RATE_LIMIT_REDIS_URL: "", CLOUDFLARE_ORIGIN_SECRET: "" };
const child = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "src/server.ts"], { cwd: process.cwd(), env: { ...serverEnv, PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"] });
// Use a second isolated process so the CAPTCHA edge cases do not consume the legacy contact route's five-request rate-limit budget.
const captchaPort = randomInt(49_000, 55_000);
const captchaChild = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "src/server.ts"], { cwd: process.cwd(), env: { ...serverEnv, PORT: String(captchaPort) }, stdio: "ignore" });
let spawnError;
let childErrorOutput = "";
child.on("error", (error) => { spawnError = error; });
child.stderr.setEncoding("utf8").on("data", (chunk) => { childErrorOutput = `${childErrorOutput}${chunk}`.slice(-4_000); });
let captchaSpawnError;
captchaChild.on("error", (error) => { captchaSpawnError = error; });
const base = `http://127.0.0.1:${port}`;
const captchaBase = `http://127.0.0.1:${captchaPort}`;
try {
  let healthy = false;
  for (let i = 0; i < 120; i++) {
    if (spawnError) throw new Error(`backend could not start: ${spawnError.message}`);
    if (child.exitCode !== null) throw new Error(`backend exited early (${child.exitCode})`);
    try { const response = await fetch(`${base}/health`); if (response.ok) { healthy = true; break; } } catch { await new Promise((resolve) => setTimeout(resolve, 250)); }
  }
  if (!healthy) throw new Error(`health endpoint did not become ready${childErrorOutput ? `: ${childErrorOutput}` : ""}`);
  let captchaHealthy = false;
  for (let i = 0; i < 120; i++) {
    if (captchaSpawnError) throw new Error(`CAPTCHA test backend could not start: ${captchaSpawnError.message}`);
    if (captchaChild.exitCode !== null) throw new Error(`CAPTCHA test backend exited early (${captchaChild.exitCode})`);
    try { const response = await fetch(`${captchaBase}/health`); if (response.ok) { captchaHealthy = true; break; } } catch { await new Promise((resolve) => setTimeout(resolve, 250)); }
  }
  if (!captchaHealthy) throw new Error("CAPTCHA test backend health endpoint did not become ready");
  const unauth = await fetch(`${base}/api/users/all?limit=1`);
  if (unauth.status !== 401) throw new Error(`unauthenticated /api/users/all returned ${unauth.status}`);
  const privateContacts = await fetch(`${base}/api/contacts?limit=2`);
  if (privateContacts.status !== 401) throw new Error(`unauthenticated /api/contacts returned ${privateContacts.status}`);
  const publicNews = await fetch(`${base}/api/news`);
  if (publicNews.status !== 200) throw new Error("public news endpoint failed");
  const getCaptcha = async (serverBase = base) => {
    const response = await fetch(`${serverBase}/api/contacts/captcha`);
    if (response.status !== 200 || !response.headers.get("cache-control")?.includes("no-store")) throw new Error("contact CAPTCHA endpoint failed or was cacheable");
    const challenge = await response.json();
    const match = /^(\d+) \+ (\d+) = \?$/.exec(challenge.question ?? "");
    if (!challenge.id || !challenge.expiresAt || !match) throw new Error("contact CAPTCHA response contract is invalid");
    const secondsToExpiry = (Date.parse(challenge.expiresAt) - Date.now()) / 1000;
    if (secondsToExpiry < 295 || secondsToExpiry > 301) throw new Error("contact CAPTCHA expiry is not approximately five minutes");
    return { ...challenge, answer: Number(match[1]) + Number(match[2]) };
  };
  const missingCaptcha = await fetch(`${captchaBase}/api/contacts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Missing CAPTCHA", email: "missing@example.invalid", message: "Missing CAPTCHA should be rejected" }) });
  if (missingCaptcha.status !== 400 || JSON.stringify(await missingCaptcha.json()) !== JSON.stringify({ error: "CAPTCHA_INVALID" })) throw new Error("missing contact CAPTCHA was not rejected with the generic error");
  const wrongCaptcha = await getCaptcha(captchaBase);
  const invalidCaptcha = await fetch(`${captchaBase}/api/contacts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Invalid CAPTCHA", email: "invalid@example.invalid", message: "Invalid CAPTCHA should be rejected", captchaId: wrongCaptcha.id, captchaAnswer: String(wrongCaptcha.answer + 1) }) });
  if (invalidCaptcha.status !== 400 || JSON.stringify(await invalidCaptcha.json()) !== JSON.stringify({ error: "CAPTCHA_INVALID" })) throw new Error("incorrect contact CAPTCHA was not rejected with the generic error");
  const validCaptcha = await getCaptcha(captchaBase);
  const captchaContactBody = { name: "Captcha Contact", email: "captcha@example.invalid", message: "Valid CAPTCHA contact submission", captchaId: validCaptcha.id, captchaAnswer: String(validCaptcha.answer) };
  const captchaContact = await fetch(`${captchaBase}/api/contacts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(captchaContactBody) });
  if (captchaContact.status !== 201 || JSON.stringify(await captchaContact.json()) !== JSON.stringify({ success: true })) throw new Error("valid contact CAPTCHA did not preserve the 201 success contract");
  const replayedCaptcha = await fetch(`${captchaBase}/api/contacts`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(captchaContactBody) });
  if (replayedCaptcha.status !== 400 || JSON.stringify(await replayedCaptcha.json()) !== JSON.stringify({ error: "CAPTCHA_INVALID" })) throw new Error("replayed contact CAPTCHA was accepted");
  const captchaAdminLogin = await fetch(`${captchaBase}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: adminEmail, password: adminPassword }) });
  const captchaAdminCookie = captchaAdminLogin.headers.get("set-cookie")?.split(";")[0];
  const captchaInboxResponse = await fetch(`${captchaBase}/api/contacts?limit=10`, { headers: { cookie: captchaAdminCookie } });
  const captchaInbox = await captchaInboxResponse.json();
  if (captchaInboxResponse.status !== 200 || captchaInbox.items.length !== 1 || captchaInbox.items[0].name !== "Captcha Contact" || "captchaId" in captchaInbox.items[0] || "captchaAnswer" in captchaInbox.items[0]) throw new Error("contact CAPTCHA fields were persisted or contact submission was not stored");
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
  const unsafeWebsite = await fetch(`${base}/api/funds`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ professionSlug: "security-smoke", name: "Unsafe link", website: "javascript:alert(1)" }) });
  if (unsafeWebsite.status !== 400) throw new Error("unsafe website protocol was accepted");
  const unsafeImage = await fetch(`${base}/api/news`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ slug: "unsafe-image", title: "Unsafe image", image: "http://127.0.0.1/private" }) });
  if (unsafeImage.status !== 400) throw new Error("unsafe image URL was accepted");
  const listed = await fetch(`${base}/api/news`);
  const serialized = await listed.text();
  if (!serialized.includes(JSON.stringify(payload))) throw new Error("XSS test payload did not round-trip as text data");
  const contactRequests = [
    { expectedStatus: 400, body: { name: "Test User", message: "No reply method test" } },
    { expectedStatus: 201, body: { name: "Phone Only", phone: "+998900000001", message: "Phone contact test", consent: true } },
    { expectedStatus: 201, body: { name: "Email Only", email: "email-only@example.invalid", message: "Email contact test", consent: false } },
    { expectedStatus: 201, body: { name: "Legacy Contact", email: "legacy@example.invalid", phone: "+998900000003", message: "Legacy-compatible submission", passwordHash: "smoke-marker" } },
    { expectedStatus: 201, body: { name: "Full Contact", email: "full@example.invalid", phone: "+998900000004", message: "Contact with explicit consent", consent: true } },
    { expectedStatus: 429, body: { name: "Rate Limited", email: "limited@example.invalid", phone: "+998900000005", message: "Automated rate limit check" } },
  ];
  for (let i = 0; i < contactRequests.length; i++) {
    const { expectedStatus, body } = contactRequests[i];
    const challenge = i < 5 ? await getCaptcha(base) : null;
    const response = await fetch(`${base}/api/contacts`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `198.51.100.${i + 1}` }, body: JSON.stringify(challenge ? { ...body, captchaId: challenge.id, captchaAnswer: String(challenge.answer) } : body) });
    if (response.status !== expectedStatus) throw new Error(`contact request ${i + 1} returned ${response.status}, expected ${expectedStatus}`);
  }
  const inboxPages = await Promise.all([0, 2].map((offset) => fetch(`${base}/api/contacts?limit=2&offset=${offset}`, { headers: { cookie } })));
  if (inboxPages.some((response) => response.status !== 200 || !response.headers.get("cache-control")?.includes("no-store"))) throw new Error("admin contact inbox did not require a session or disable caching");
  const inboxData = await Promise.all(inboxPages.map((response) => response.json()));
  const contactItems = inboxData.flatMap((page) => page.items);
  const contactKeys = new Set(["id", "name", "email", "phone", "message", "consent", "createdAt", "updatedAt"]);
  if (inboxData.some((page) => page.total !== 4 || page.limit !== 2) || contactItems.length !== 4 || new Set(contactItems.map((item) => item.id)).size !== 4) throw new Error("admin contact inbox pagination is incorrect");
  if (contactItems.some((item) => Object.keys(item).some((key) => !contactKeys.has(key)) || "passwordHash" in item || "token" in item)) throw new Error("admin contact inbox returned fields outside the privacy allowlist");
  if (!contactItems.some((item) => item.name === "Phone Only" && !item.email && item.phone === "+998900000001" && item.consent === true)) throw new Error("phone-only contact or explicit consent was not persisted");
  if (!contactItems.some((item) => item.name === "Email Only" && item.email === "email-only@example.invalid" && !item.phone && item.consent === false)) throw new Error("email-only contact or explicit consent choice was not persisted");
  if (!contactItems.some((item) => item.name === "Legacy Contact" && !("consent" in item))) throw new Error("legacy contact submission without consent remained compatible");
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
  process.stdout.write("BACKEND_SECURITY_SMOKE_PASSED: health, auth, JWT tampering, one-time contact CAPTCHA, contact inbox privacy/auth/pagination, optional reply methods, consent persistence, rate limits, inert XSS JSON, and CRUD beyond 100\n");
} finally {
  child.kill("SIGTERM");
  captchaChild.kill("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 300));
  if (child.exitCode === null) child.kill("SIGKILL");
  if (captchaChild.exitCode === null) captchaChild.kill("SIGKILL");
}
