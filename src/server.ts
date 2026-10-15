import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { timingSafeEqual } from "node:crypto";
import pg from "pg";
import { Redis } from "ioredis";
import { z } from "zod";

type RecordItem = { id: string; createdAt: string; updatedAt: string; [key: string]: unknown };
const app = Fastify({ logger: process.env.LOG_LEVEL === "silent" ? false : { level: process.env.LOG_LEVEL ?? "info" }, bodyLimit: 128 * 1024, trustProxy: false, requestTimeout: 15_000, connectionTimeout: 10_000, keepAliveTimeout: 5_000 });
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");
const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const adminHash = process.env.ADMIN_PASSWORD_HASH;
if (!adminEmail || !adminHash) throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD_HASH are required");
if (!/^\$2[aby]\$(1[0-4])\$[./A-Za-z0-9]{53}$/.test(adminHash)) throw new Error("ADMIN_PASSWORD_HASH must be a bcrypt hash with cost 10 to 14");
const rateLimitRedisUrl = process.env.RATE_LIMIT_REDIS_URL ?? process.env.REDIS_URL;
if (process.env.NODE_ENV === "production" && !rateLimitRedisUrl) throw new Error("RATE_LIMIT_REDIS_URL (or REDIS_URL) is required in production for shared request limits");
const rateLimitRedis = rateLimitRedisUrl ? new Redis(rateLimitRedisUrl, { connectionName: "fond-uz-api-rate-limits", connectTimeout: 1_000, maxRetriesPerRequest: 1, enableOfflineQueue: false, lazyConnect: true }) : null;
if (rateLimitRedis) await rateLimitRedis.connect();
const cloudflareOriginSecret = process.env.CLOUDFLARE_ORIGIN_SECRET;
if (cloudflareOriginSecret && cloudflareOriginSecret.length < 32) throw new Error("CLOUDFLARE_ORIGIN_SECRET must be at least 32 characters");
function isCloudflareProxyRequest(request: { headers: Record<string, string | string[] | undefined> }) {
  const candidate = request.headers["x-fonduz-origin"];
  if (!cloudflareOriginSecret || typeof candidate !== "string") return false;
  const expectedBytes = Buffer.from(cloudflareOriginSecret);
  const candidateBytes = Buffer.from(candidate);
  return expectedBytes.length === candidateBytes.length && timingSafeEqual(expectedBytes, candidateBytes);
}
const allowedOrigins = (process.env.CORS_ORIGINS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
if (process.env.NODE_ENV === "production" && allowedOrigins.length === 0) throw new Error("CORS_ORIGINS must list the public frontend/admin origins in production");
const initialNow = new Date().toISOString();
const collections = new Map<string, RecordItem[]>([["users", [{ id: "local-admin", email: adminEmail, role: "admin", passwordHash: adminHash, active: true, createdAt: initialNow, updatedAt: initialNow }]], ["doctors", []], ["services", []], ["funds", []], ["news", []], ["faqs", []], ["prices", []], ["contacts", []]]);
const pool = process.env.DATABASE_URL ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === "disable" ? undefined : { rejectUnauthorized: false }, max: 10, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000, query_timeout: 10_000, statement_timeout: 5_000 }) : null;
if (!pool && process.env.NODE_ENV === "production") throw new Error("DATABASE_URL is required in production");
if (pool) {
  await pool.query("CREATE TABLE IF NOT EXISTS app_records (id text PRIMARY KEY, collection text NOT NULL, data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE INDEX IF NOT EXISTS app_records_collection_created_idx ON app_records(collection, created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS app_records_users_email_idx ON app_records (lower(data->>'email')) WHERE collection = 'users'");
  const legacyUsers = await pool.query("SELECT id, data FROM app_records WHERE collection = 'users' AND (data ? 'password' OR data ? 'passwordPlain' OR (data ? 'passwordHash' AND data->>'passwordHash' !~ '^\\$2[aby]\\$[0-9]{2}\\$'))");
  for (const row of legacyUsers.rows) {
    const data = row.data as Record<string, unknown>;
    const existing = typeof data.passwordHash === "string" ? data.passwordHash : typeof data.password === "string" ? data.password : typeof data.passwordPlain === "string" ? data.passwordPlain : null;
    const next = { ...data };
    delete next.password;
    delete next.passwordPlain;
    if (existing) next.passwordHash = /^\$2[aby]\$\d{2}\$/.test(existing) ? existing : await bcrypt.hash(existing, 12);
    await pool.query("UPDATE app_records SET data = $1, updated_at = now() WHERE id = $2 AND collection = 'users'", [next, row.id]);
  }
}
async function getRecords(collection: string, limit = 100, offset = 0): Promise<RecordItem[]> {
  if (!pool) return (collections.get(collection) ?? []).slice(offset, offset + limit);
  const result = await pool.query("SELECT data FROM app_records WHERE collection = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", [collection, limit, offset]);
  return result.rows.map((row) => row.data as RecordItem);
}
const contentSchema = z.record(z.string().max(80), z.union([
  z.string().max(8_000),
  z.array(z.string().max(2_000)).max(50),
  z.number().finite(),
  z.boolean(),
])).refine((value) => Object.keys(value).length <= 40, "Too many fields");

await app.register(helmet, { contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"], formAction: ["'none'"], objectSrc: ["'none'"] } } });
await app.register(cors, { credentials: true, origin(origin, cb) { if (!origin || allowedOrigins.includes(origin)) cb(null, true); else cb(new Error("Origin not allowed"), false); } });
await app.register(cookie);
await app.register(jwt, { secret, cookie: { cookieName: "fond_session", signed: false }, sign: { iss: "fond-uz-api", aud: "fond-uz-admin" }, verify: { onlyCookie: true, allowedIss: "fond-uz-api", allowedAud: "fond-uz-admin" } });
await app.register(rateLimit, { max: 120, timeWindow: "1 minute", ...(rateLimitRedis ? { redis: rateLimitRedis } : {}), keyGenerator: (request) => isCloudflareProxyRequest(request) && typeof request.headers["cf-connecting-ip"] === "string" ? request.headers["cf-connecting-ip"] as string : request.ip });
if (cloudflareOriginSecret) {
  app.addHook("onRequest", async (request, reply) => {
    if (request.url !== "/health" && !isCloudflareProxyRequest(request)) return reply.code(403).send({ error: "Forbidden" });
  });
}

app.decorate("authenticate", async (request: any, reply: any) => {
  try { await request.jwtVerify(); } catch { return reply.code(401).send({ error: "Authentication required" }); }
});
app.decorate("requireAdmin", async (request: any, reply: any) => {
  try { await request.jwtVerify(); if (request.user?.role !== "admin") return reply.code(403).send({ error: "Admin access required" }); }
  catch { return reply.code(401).send({ error: "Authentication required" }); }
});

app.get("/health", async (_request, reply) => {
  if (pool) {
    try { await pool.query("SELECT 1"); }
    catch { return reply.code(503).send({ status: "unavailable" }); }
  }
  return { status: "ok" };
});
app.post("/api/auth/login", { config: { rateLimit: { max: 5, timeWindow: "1 minute" } } }, async (request, reply) => {
  const parsed = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(200) }).safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "Invalid request" });
  if (Buffer.byteLength(parsed.data.password, "utf8") > 72) return reply.code(400).send({ error: "Invalid request" });
  const userResult = pool ? await pool.query("SELECT data FROM app_records WHERE collection='users' AND lower(data->>'email')=$1", [parsed.data.email.toLowerCase()]) : null;
  const storedHash = userResult?.rows[0]?.data?.passwordHash as string | undefined;
  const validEmail = parsed.data.email.toLowerCase() === adminEmail;
  const valid = validEmail && userResult?.rows[0]?.data?.active !== false && await bcrypt.compare(parsed.data.password, storedHash ?? adminHash);
  if (!valid) return reply.code(401).send({ error: "Invalid credentials" });
  const token = app.jwt.sign({ sub: adminEmail, role: "admin" }, { expiresIn: "8h" });
  reply.setCookie("fond_session", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 8 * 60 * 60 });
  return { success: true, user: { email: adminEmail, role: "admin" } };
});
app.post("/api/auth/logout", async (_request, reply) => { reply.clearCookie("fond_session", { path: "/", httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict" }); return { success: true }; });
app.get("/api/auth/session", { preHandler: (app as any).authenticate }, async (request: any) => ({ user: { email: request.user.sub, role: request.user.role } }));

app.get("/api/users/all", { preHandler: (app as any).requireAdmin }, async (request, reply) => {
  const limit = Math.min(Math.max(Number((request.query as any)?.limit) || 50, 1), 100);
  const offset = Math.max(Number((request.query as any)?.offset) || 0, 0);
  const rows = await getRecords("users", limit, offset);
  const total = pool ? Number((await pool.query("SELECT count(*)::int AS total FROM app_records WHERE collection = 'users'")).rows[0]?.total ?? 0) : (collections.get("users") ?? []).length;
  const safeUsers = rows.map((user) => Object.fromEntries(Object.entries(user).filter(([key]) => !["passwordHash", "password", "passwordPlain", "token", "resetToken"].includes(key))));
  return reply.header("Cache-Control", "no-store").send({ items: safeUsers, total, limit, offset });
});
for (const name of ["doctors", "services", "funds", "news", "faqs", "prices"] as const) {
  app.get(`/api/${name}`, async (request, reply) => {
    const limit = Math.min(Math.max(Number((request.query as any)?.limit) || 50, 1), 100);
    const offset = Math.max(Number((request.query as any)?.offset) || 0, 0);
    const rows = await getRecords(name, limit, offset);
    const total = pool ? Number((await pool.query("SELECT count(*)::int AS total FROM app_records WHERE collection = $1", [name])).rows[0]?.total ?? 0) : (collections.get(name) ?? []).length;
    return reply.header("Cache-Control", "public, max-age=30, stale-while-revalidate=120").send({ items: rows, total, limit, offset });
  });
  app.post(`/api/${name}`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const parsed = contentSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid content" });
    const now = new Date().toISOString(); const item = { ...parsed.data, id: randomUUID(), createdAt: now, updatedAt: now };
    if (pool) await pool.query("INSERT INTO app_records(id, collection, data) VALUES ($1,$2,$3)", [item.id, name, item]); else collections.get(name)!.push(item); return reply.code(201).send({ item });
  });
  app.patch(`/api/${name}/:id`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const parsed = contentSchema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: "Invalid content" });
    const rows = await getRecords(name); const idx = rows.findIndex((x) => x.id === (request.params as any).id);
    if (idx < 0) return reply.code(404).send({ error: "Not found" });
    rows[idx] = { ...rows[idx], ...parsed.data, updatedAt: new Date().toISOString() };
    if (pool) await pool.query("UPDATE app_records SET data=$1, updated_at=now() WHERE id=$2 AND collection=$3", [rows[idx], rows[idx].id, name]); else collections.set(name, rows); return { item: rows[idx] };
  });
  app.delete(`/api/${name}/:id`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const rows = await getRecords(name); const idx = rows.findIndex((x) => x.id === (request.params as any).id);
    if (idx < 0) return reply.code(404).send({ error: "Not found" });
    if (pool) await pool.query("DELETE FROM app_records WHERE id=$1 AND collection=$2", [rows[idx].id, name]); else { rows.splice(idx, 1); collections.set(name, rows); } return reply.code(204).send();
  });
}
app.post("/api/contacts", { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } }, async (request, reply) => {
  const schema = z.object({ name: z.string().trim().min(2).max(120), email: z.string().email().max(254), phone: z.string().max(32), message: z.string().trim().min(5).max(3000) });
  const parsed = schema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: "Invalid contact request" });
  const now = new Date().toISOString(); const record = { ...parsed.data, id: randomUUID(), createdAt: now, updatedAt: now };
  if (pool) await pool.query("INSERT INTO app_records(id, collection, data) VALUES ($1,'contacts',$2)", [record.id, record]); else collections.get("contacts")!.push(record);
  return reply.code(201).send({ success: true });
});

const port = Number(process.env.PORT ?? 4000);
app.addHook("onClose", async () => { if (pool) await pool.end(); if (rateLimitRedis) await rateLimitRedis.quit(); });
await app.listen({ host: "0.0.0.0", port });
