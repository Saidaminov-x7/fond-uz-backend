import "dotenv/config";
import bcrypt from "bcryptjs";
import pg from "pg";

const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD;
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!email || !password || password.length < 14 || Buffer.byteLength(password, "utf8") > 72) {
  throw new Error("Set ADMIN_EMAIL and a strong ADMIN_PASSWORD of 14 to 72 UTF-8 bytes");
}

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "disable" ? undefined : { rejectUnauthorized: false },
  max: 2,
});

try {
  await pool.query("CREATE TABLE IF NOT EXISTS app_records (id text PRIMARY KEY, collection text NOT NULL, data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE INDEX IF NOT EXISTS app_records_collection_created_idx ON app_records(collection, created_at DESC)");
  const passwordHash = await bcrypt.hash(password, 12);
  const now = new Date().toISOString();
  const admin = { id: "initial-admin", email, role: "admin", passwordHash, active: true, createdAt: now, updatedAt: now };
  await pool.query(
    "INSERT INTO app_records(id, collection, data, created_at, updated_at) VALUES ('initial-admin', 'users', $1, now(), now()) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()",
    [admin],
  );
  console.log("Admin account initialized with a bcrypt password hash. Existing content was preserved.");
} finally {
  await pool.end();
}
