import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import bcrypt from "bcryptjs";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import pg from "pg";
import { Redis } from "ioredis";
import { z } from "zod";

type RecordItem = { id: string; createdAt: string; updatedAt: string; [key: string]: unknown };
const app = Fastify({ logger: process.env.LOG_LEVEL === "silent" ? false : { level: process.env.LOG_LEVEL ?? "info" }, bodyLimit: 128 * 1024, trustProxy: false, requestTimeout: 15_000, connectionTimeout: 10_000, keepAliveTimeout: 5_000 });
const production = process.env.NODE_ENV === "production";
const secret = process.env.JWT_SECRET ?? (production ? undefined : randomBytes(48).toString("base64url"));
if (!secret || secret.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");
const adminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
let adminHash = process.env.ADMIN_PASSWORD_HASH;
if (!adminHash && process.env.ADMIN_PASSWORD) {
  if (Buffer.byteLength(process.env.ADMIN_PASSWORD, "utf8") > 72) throw new Error("ADMIN_PASSWORD must not exceed 72 UTF-8 bytes");
  adminHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
}
if (adminHash && !/^\$2[aby]\$(1[0-4])\$[./A-Za-z0-9]{53}$/.test(adminHash)) throw new Error("ADMIN_PASSWORD_HASH must be a bcrypt hash with cost 10 to 14");
const rateLimitRedisUrl = process.env.RATE_LIMIT_REDIS_URL ?? process.env.REDIS_URL;
if (production && !rateLimitRedisUrl) throw new Error("RATE_LIMIT_REDIS_URL (or REDIS_URL) is required in production for shared request limits");
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
const adminRecord = adminEmail && adminHash ? { id: "local-admin", email: adminEmail, role: "admin", passwordHash: adminHash, active: true, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() } : null;
const fallbackAdminHash = adminHash;
const allowedOrigins = (process.env.CORS_ORIGINS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
if (production && allowedOrigins.length === 0) throw new Error("CORS_ORIGINS must list the public frontend/admin origins in production");
const initialNow = new Date().toISOString();
const collections = new Map<string, RecordItem[]>([["users", adminRecord ? [adminRecord] : []], ["doctors", []], ["services", []], ["funds", []], ["news", []], ["faqs", []], ["prices", []], ["contacts", []]]);
const pool = process.env.DATABASE_URL ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === "disable" ? undefined : { rejectUnauthorized: false }, max: 10, connectionTimeoutMillis: 5_000, idleTimeoutMillis: 30_000, query_timeout: 10_000, statement_timeout: 5_000 }) : null;
if (!pool && production) throw new Error("DATABASE_URL is required in production");
if (!pool && (!adminEmail || !adminHash)) throw new Error("ADMIN_EMAIL and either ADMIN_PASSWORD_HASH or ADMIN_PASSWORD are required when DATABASE_URL is not configured");
if (pool) {
  await pool.query("CREATE TABLE IF NOT EXISTS app_records (id text PRIMARY KEY, collection text NOT NULL, data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE INDEX IF NOT EXISTS app_records_collection_created_idx ON app_records(collection, created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS app_records_users_email_idx ON app_records (lower(data->>'email')) WHERE collection = 'users'");
  if (adminRecord) {
    const existingAdmin = await pool.query("SELECT id, data FROM app_records WHERE collection = 'users' AND lower(data->>'email') = $1 LIMIT 1", [adminEmail]);
    if (existingAdmin.rows.length) {
      const { id, data } = existingAdmin.rows[0] as { id: string; data: Record<string, unknown> };
      await pool.query("UPDATE app_records SET data = $1, updated_at = now() WHERE id = $2", [{ ...data, passwordHash: adminHash, active: true }, id]);
    } else {
      await pool.query("INSERT INTO app_records(id, collection, data, created_at, updated_at) VALUES ($1, 'users', $2, now(), now())", [adminRecord.id, adminRecord]);
    }
  }
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
  if (!pool) return [...(collections.get(collection) ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(offset, offset + limit);
  const result = await pool.query("SELECT data FROM app_records WHERE collection = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", [collection, limit, offset]);
  return result.rows.map((row) => row.data as RecordItem);
}
async function getRecord(collection: string, id: string): Promise<RecordItem | null> {
  if (!pool) return (collections.get(collection) ?? []).find((record) => record.id === id) ?? null;
  const result = await pool.query("SELECT data FROM app_records WHERE collection = $1 AND id = $2 LIMIT 1", [collection, id]);
  return (result.rows[0]?.data as RecordItem | undefined) ?? null;
}
const sensitiveContentKeyFragments = [
  "password", "passwd", "passphrase", "pwd", "token", "secret", "apikey", "credential",
  "ssn", "socialsecuritynumber", "passport", "nationalid", "governmentid", "personalid",
  "patientrecord", "patientdata", "medicalrecord", "healthrecord", "diagnosis",
  "cookie", "session", "authorization", "privatekey", "cardnumber", "securitycode",
  "cvv", "bankaccount", "routingnumber",
];
const contentSchema = z.record(z.string().max(80), z.union([
  z.string().max(8_000),
  z.array(z.string().max(2_000)).max(50),
  z.number().finite(),
  z.boolean(),
])).refine((value) => Object.keys(value).length <= 40, "Too many fields").superRefine((value, context) => {
  for (const [key, raw] of Object.entries(value)) {
    const normalizedKey = key.normalize("NFKC").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (sensitiveContentKeyFragments.some((fragment) => normalizedKey.includes(fragment))) {
      context.addIssue({ code: "custom", path: [key], message: "Sensitive field names are not allowed" });
    }
    if (typeof raw !== "string") continue;
    if ((key === "slug" || key === "professionSlug") && !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(raw)) {
      context.addIssue({ code: "custom", path: [key], message: "Invalid slug" });
    }
    if (key === "website") {
      try {
        const url = new URL(raw);
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Unsupported protocol");
      } catch {
        context.addIssue({ code: "custom", path: [key], message: "Invalid website URL" });
      }
    }
    if (key === "email" && raw && !z.string().email().max(254).safeParse(raw).success) {
      context.addIssue({ code: "custom", path: [key], message: "Invalid email" });
    }
    if (key === "phone" && raw && !/^[+()0-9\s.-]{3,32}$/.test(raw)) {
      context.addIssue({ code: "custom", path: [key], message: "Invalid phone" });
    }
    if (key === "image" && raw) {
      const localImage = raw.startsWith("/") && !raw.startsWith("//") && !raw.includes("\\");
      let remoteImage = false;
      try { remoteImage = new URL(raw).protocol === "https:"; } catch { /* local paths are handled above */ }
      if (!localImage && !remoteImage) context.addIssue({ code: "custom", path: [key], message: "Invalid image URL" });
    }
  }
});
const contactFields = new Set(["id", "name", "email", "phone", "message", "consent", "createdAt", "updatedAt"]);
const publicCollections = ["doctors", "services", "funds", "news", "faqs", "prices"] as const;
const publicCollectionFields: Record<(typeof publicCollections)[number], Set<string>> = {
  doctors: new Set(["id", "createdAt", "updatedAt", "name", "nameEn", "nameUz", "specialty", "specialtyEn", "specialtyUz", "profession", "bio", "bioEn", "bioUz", "email", "phone", "image"]),
  services: new Set(["id", "createdAt", "updatedAt", "slug", "name", "nameEn", "nameUz", "description", "descriptionEn", "descriptionUz", "fundsCount", "category", "categoryEn", "categoryUz"]),
  funds: new Set(["id", "createdAt", "updatedAt", "professionSlug", "name", "nameEn", "nameUz", "phone", "website", "description", "descriptionEn", "descriptionUz"]),
  news: new Set(["id", "createdAt", "updatedAt", "slug", "title", "titleEn", "titleUz", "subtitle", "subtitleEn", "subtitleUz", "date", "image", "content", "contentEn", "contentUz"]),
  faqs: new Set(["id", "createdAt", "updatedAt", "question", "questionEn", "questionUz", "answer", "answerEn", "answerUz", "category", "categoryEn", "categoryUz"]),
  prices: new Set(["id", "createdAt", "updatedAt", "title", "titleEn", "titleUz", "price", "priceEn", "priceUz", "includes", "includesEn", "includesUz"]),
};

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
  const userResult = pool ? await pool.query("SELECT data FROM app_records WHERE collection='users' AND lower(data->>'email')=$1 LIMIT 1", [parsed.data.email.toLowerCase()]) : null;
  const storedHash = userResult?.rows[0]?.data?.passwordHash as string | undefined;
  const user = userResult?.rows[0]?.data as Record<string, unknown> | undefined;
  const validEmail = userResult ? Boolean(user && user.role === "admin" && (!adminEmail || parsed.data.email.toLowerCase() === adminEmail)) : parsed.data.email.toLowerCase() === adminEmail;
  const candidateHash = typeof user?.passwordHash === "string" ? user.passwordHash : fallbackAdminHash;
  const valid = validEmail && user?.active !== false && Boolean(candidateHash) && await bcrypt.compare(parsed.data.password, candidateHash!);
  if (!valid) return reply.code(401).send({ error: "Invalid credentials" });
  const email = typeof user?.email === "string" ? user.email : adminEmail!;
  const token = app.jwt.sign({ sub: email, role: "admin" }, { expiresIn: "8h" });
  reply.setCookie("fond_session", token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: 8 * 60 * 60 });
  return { success: true, user: { email, role: "admin" } };
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
app.get("/api/contacts", { preHandler: (app as any).requireAdmin }, async (request, reply) => {
  const limit = Math.min(Math.max(Number((request.query as any)?.limit) || 50, 1), 100);
  const offset = Math.max(Number((request.query as any)?.offset) || 0, 0);
  const rows = await getRecords("contacts", limit, offset);
  const total = pool ? Number((await pool.query("SELECT count(*)::int AS total FROM app_records WHERE collection = 'contacts'")).rows[0]?.total ?? 0) : (collections.get("contacts") ?? []).length;
  const safeContacts = rows.map((contact) => Object.fromEntries(Object.entries(contact).filter(([key]) => contactFields.has(key))));
  return reply.header("Cache-Control", "no-store").send({ items: safeContacts, total, limit, offset });
});
for (const name of publicCollections) {
  app.get(`/api/${name}`, async (request, reply) => {
    const limit = Math.min(Math.max(Number((request.query as any)?.limit) || 50, 1), 100);
    const offset = Math.max(Number((request.query as any)?.offset) || 0, 0);
    const rows = await getRecords(name, limit, offset);
    const total = pool ? Number((await pool.query("SELECT count(*)::int AS total FROM app_records WHERE collection = $1", [name])).rows[0]?.total ?? 0) : (collections.get(name) ?? []).length;
    const safeRecords = rows.map((record) => Object.fromEntries(Object.entries(record).filter(([key]) => publicCollectionFields[name].has(key))));
    return reply.header("Cache-Control", "public, max-age=30, stale-while-revalidate=120").send({ items: safeRecords, total, limit, offset });
  });
  app.post(`/api/${name}`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const parsed = contentSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid content" });
    const now = new Date().toISOString(); const item = { ...parsed.data, id: randomUUID(), createdAt: now, updatedAt: now };
    if (pool) await pool.query("INSERT INTO app_records(id, collection, data) VALUES ($1,$2,$3)", [item.id, name, item]); else collections.get(name)!.push(item); return reply.code(201).send({ item });
  });
  app.patch(`/api/${name}/:id`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const parsed = contentSchema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: "Invalid content" });
    const id = (request.params as any).id as string;
    const existing = await getRecord(name, id);
    if (!existing) return reply.code(404).send({ error: "Not found" });
    const patch = Object.fromEntries(Object.entries(parsed.data).filter(([key]) => !["id", "createdAt", "updatedAt"].includes(key)));
    const item = { ...existing, ...patch, id: existing.id, createdAt: existing.createdAt, updatedAt: new Date().toISOString() };
    if (pool) {
      const updated = await pool.query("UPDATE app_records SET data=$1, updated_at=now() WHERE id=$2 AND collection=$3 RETURNING data", [item, id, name]);
      if (!updated.rowCount) return reply.code(404).send({ error: "Not found" });
      return { item: updated.rows[0].data as RecordItem };
    }
    const rows = collections.get(name) ?? [];
    const idx = rows.findIndex((record) => record.id === id);
    if (idx < 0) return reply.code(404).send({ error: "Not found" });
    rows[idx] = item;
    collections.set(name, rows);
    return { item };
  });
  app.delete(`/api/${name}/:id`, { preHandler: (app as any).requireAdmin }, async (request, reply) => {
    const id = (request.params as any).id as string;
    if (pool) {
      const deleted = await pool.query("DELETE FROM app_records WHERE id=$1 AND collection=$2 RETURNING id", [id, name]);
      if (!deleted.rowCount) return reply.code(404).send({ error: "Not found" });
      return reply.code(204).send();
    }
    const rows = collections.get(name) ?? [];
    const idx = rows.findIndex((record) => record.id === id);
    if (idx < 0) return reply.code(404).send({ error: "Not found" });
    rows.splice(idx, 1);
    collections.set(name, rows);
    return reply.code(204).send();
  });
}
app.post("/api/contacts", { config: { rateLimit: { max: 5, timeWindow: "15 minutes" } } }, async (request, reply) => {
  const schema = z.object({
    name: z.string().trim().min(2).max(120),
    email: z.string().trim().max(254).refine((value) => value === "" || z.string().email().safeParse(value).success).default(""),
    phone: z.string().trim().max(32).default(""),
    message: z.string().trim().min(5).max(3000),
    consent: z.boolean().optional(),
  }).refine((contact) => Boolean(contact.email || contact.phone), "At least one reply method is required");
  const parsed = schema.safeParse(request.body); if (!parsed.success) return reply.code(400).send({ error: "Invalid contact request" });
  const now = new Date().toISOString(); const record = { ...parsed.data, ...(parsed.data.consent === undefined ? {} : { consent: parsed.data.consent }), id: randomUUID(), createdAt: now, updatedAt: now };
  if (pool) await pool.query("INSERT INTO app_records(id, collection, data) VALUES ($1,'contacts',$2)", [record.id, record]); else collections.get("contacts")!.push(record);
  return reply.code(201).send({ success: true });
});

const port = Number(process.env.PORT ?? 4000);
app.addHook("onClose", async () => { if (pool) await pool.end(); if (rateLimitRedis) await rateLimitRedis.quit(); });
await app.listen({ host: "0.0.0.0", port });
