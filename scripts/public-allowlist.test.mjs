import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { randomBytes, randomInt, randomUUID } from "node:crypto";
import { test } from "node:test";
import bcrypt from "bcryptjs";

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  const exited = once(child, "exit");
  child.kill();
  await Promise.race([exited, delay(5_000)]);

  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([once(child, "exit"), delay(1_000)]);
  }
}

test("public doctors endpoint only returns allowlisted fields", async () => {
  const port = randomInt(42_000, 62_000);
  const adminEmail = `allowlist-${randomUUID()}@example.invalid`;
  const adminPassword = randomBytes(24).toString("base64url");
  const adminPasswordHash = await bcrypt.hash(adminPassword, 10);
  const serverEnv = {
    ...process.env,
    NODE_ENV: "development",
    LOG_LEVEL: "silent",
    PORT: String(port),
    JWT_SECRET: randomBytes(48).toString("base64url"),
    ADMIN_EMAIL: adminEmail,
    ADMIN_PASSWORD_HASH: adminPasswordHash,
    DATABASE_URL: "",
    DATABASE_SSL: "disable",
    REDIS_URL: "",
    RATE_LIMIT_REDIS_URL: "",
    CLOUDFLARE_ORIGIN_SECRET: "",
  };
  const child = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "src/server.ts"], {
    cwd: process.cwd(),
    env: serverEnv,
    stdio: ["ignore", "ignore", "pipe"],
  });
  let spawnError = null;
  let stderr = "";
  child.on("error", (error) => { spawnError = error; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-2_000); });
  const baseUrl = `http://127.0.0.1:${port}`;
  const safeStderr = () => stderr
    .replaceAll(adminEmail, "[redacted]")
    .replaceAll(adminPassword, "[redacted]")
    .replaceAll(adminPasswordHash, "[redacted]")
    .replaceAll(serverEnv.JWT_SECRET, "[redacted]");

  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (spawnError) throw new Error("Local backend process could not start");
      if (child.exitCode !== null || child.signalCode !== null) {
        throw new Error(`Local backend exited before becoming ready${stderr ? `: ${safeStderr()}` : ""}`);
      }
      try {
        const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(1_000) });
        if (response.ok) {
          ready = true;
          break;
        }
      } catch {
        // The listener may not be ready yet; retry within the bounded startup window.
      }
      await delay(100);
    }
    assert.equal(ready, true, stderr ? `Local in-memory backend did not become ready: ${safeStderr()}` : "Local in-memory backend did not become ready");

    const loginResponse = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: adminEmail, password: adminPassword }),
    });
    assert.equal(loginResponse.status, 200, "Temporary local admin could not authenticate");
    const sessionCookie = loginResponse.headers.get("set-cookie")?.split(";")[0];
    assert.ok(sessionCookie?.startsWith("fond_session="), "Backend did not issue the admin session cookie");

    const name = `Allowlist fixture ${randomUUID()}`;
    const createResponse = await fetch(`${baseUrl}/api/doctors`, {
      method: "POST",
      headers: { cookie: sessionCookie, "content-type": "application/json" },
      body: JSON.stringify({ name, internalNote: `private marker ${randomUUID()}` }),
    });
    assert.equal(createResponse.status, 201, "Admin could not create the doctor fixture");

    const listResponse = await fetch(`${baseUrl}/api/doctors`);
    assert.equal(listResponse.status, 200, "Public doctors endpoint did not succeed");
    const listing = await listResponse.json();
    const createdDoctor = listing.items.find((doctor) => doctor.name === name);
    assert.ok(createdDoctor, "Created doctor was not present in the public listing");
    assert.equal(createdDoctor.name, name, "Allowlisted doctor name was not available");
    assert.equal(Object.hasOwn(createdDoctor, "internalNote"), false, "Non-allowlisted internalNote was exposed publicly");
  } finally {
    await stopChild(child);
  }
});
