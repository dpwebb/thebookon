/** Portfolio administrator provisioning — The Book On (local JSON store). Idempotent, never destructive. */
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = process.env.DATA_DIR ? resolve(process.env.DATA_DIR) : join(appRoot, "data");
assertLocalTarget(dataDir);
mkdirSync(dataDir, { recursive: true });

const usersPath = join(dataDir, "users.json");
const users = readJson(usersPath, []);
const email = (process.env.COMPND_ADMIN_EMAIL ?? "admin@compnd.systems").trim().toLowerCase();
const fullName = process.env.COMPND_ADMIN_DISPLAY_NAME ?? "Compnd Systems Admin";
const password = process.env.COMPND_ADMIN_PASSWORD ?? "";
if (password.length < 15) fail("COMPND_ADMIN_PASSWORD must be at least 15 characters.");

const now = new Date().toISOString();
const index = users.findIndex((user) => String(user.email).toLowerCase() === email);
const record = {
  ...(index >= 0 ? users[index] : { id: `usr_syn_${crypto.randomBytes(5).toString("hex")}`, createdAt: now }),
  fullName,
  email,
  phone: "+1 555 0100",
  passwordHash: hashPassword(password),
  updatedAt: now,
  internalAdmin: true,
  entitlement: "full-author-workspace",
};

if (index >= 0) users[index] = record;
else users.push(record);
writeJson(usersPath, users);

console.log(JSON.stringify({
  application: "the-book-on",
  admin: email,
  userId: record.id,
  store: usersPath,
  internalAdmin: true,
  entitlement: "full-author-workspace",
  note: "Local JSON store only. MFA remains available and is not disabled by this seeder.",
}, null, 2));

function hashPassword(value) {
  const iterations = 210000;
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = crypto.pbkdf2Sync(value, salt, iterations, 32, "sha256").toString("base64url");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  const text = readFileSync(path, "utf8").trim();
  return text ? JSON.parse(text) : fallback;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function assertLocalTarget(target) {
  if (process.env.COMPND_ADMIN_ALLOW_PRODUCTION === "true") return;
  const normalized = target.replaceAll("\\", "/").toLowerCase();
  if (/(^|\/)(prod|production|live|customer)(\/|$)/.test(normalized)) {
    fail("the-book-on: refusing to write an administrator into a production-looking data directory.");
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
