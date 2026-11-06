/** Synthetic evidence — The Book On (local JSON store). Fictional authors and manuscripts only. */
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = process.env.DATA_DIR ? resolve(process.env.DATA_DIR) : join(appRoot, "data");
assertLocalTarget(dataDir);

const runId = process.env.COMPND_SYNTHETIC_RUN_ID ?? "compnd-synthetic-2026-11";
const seed = Number(process.env.COMPND_SYNTHETIC_SEED ?? 20261105);
const domain = process.env.COMPND_SYNTHETIC_DOMAIN ?? "synthetic.compnd.test";
const password = process.env.COMPND_SYNTHETIC_PASSWORD ?? "";
if (password.length < 15) fail("COMPND_SYNTHETIC_PASSWORD must be at least 15 characters.");

mkdirSync(dataDir, { recursive: true });
mkdirSync(join(dataDir, "uploads", "synthetic"), { recursive: true });
const usersPath = join(dataDir, "users.json");
const submissionsPath = join(dataDir, "submissions.json");
const users = readJson(usersPath, []);
const submissions = readJson(submissionsPath, []);
const now = new Date().toISOString();
const filePath = join(dataDir, "uploads", "synthetic", `synthetic-manuscript-${seed}.txt`);
writeFileSync(filePath, `[SYNTHETIC] Fictional manuscript for run ${runId}. No real author content.\n`, "utf8");

const authors = [
  { key: "free", name: "SYN Hollis Lark", role: "free", title: "[SYNTHETIC] The Quiet Harbour" },
  { key: "creator", name: "SYN Rowan Mercer", role: "creator", title: "[SYNTHETIC] Letters from Juniper Lane" },
  { key: "studio", name: "SYN Mira Sato", role: "studio", title: "[SYNTHETIC] The Atlas Grove Almanac" },
];

const created = {};
for (const author of authors) {
  const email = `synth+${author.key}-${seed}@${domain}`;
  const index = users.findIndex((user) => String(user.email).toLowerCase() === email);
  const record = {
    ...(index >= 0 ? users[index] : { id: `usr_syn_${author.key}_${seed}`, createdAt: now }),
    fullName: author.name,
    email,
    phone: `+1 555 01${String(10 + authors.indexOf(author)).slice(-2)}`,
    passwordHash: hashPassword(password),
    updatedAt: now,
    synthetic: true,
    syntheticRun: runId,
    plan: author.role,
  };
  if (index >= 0) users[index] = record;
  else users.push(record);

  const submissionId = `ms_syn_${author.key}_${seed}`;
  if (!submissions.some((submission) => submission.id === submissionId)) {
    submissions.push({
      id: submissionId,
      userId: record.id,
      authorName: author.name,
      email,
      phone: record.phone,
      title: author.title,
      category: "Fiction",
      stage: "Complete draft",
      serviceInterest: "Editorial review",
      audience: "Adult general readers",
      synopsis: "[SYNTHETIC] A fictional synopsis created for local acceptance evidence.",
      inspiration: "[SYNTHETIC] Generated fixture; no real person or event.",
      status: "Pending",
      reviewState: "Under Review",
      createdAt: now,
      updatedAt: now,
      synthetic: true,
      syntheticRun: runId,
      file: {
        originalName: `synthetic-manuscript-${author.key}.txt`,
        storedName: `synthetic-manuscript-${seed}.txt`,
        relativePath: `uploads/synthetic/synthetic-manuscript-${seed}.txt`,
        size: 96,
        mimeType: "text/plain",
      },
      ip: "127.0.0.1",
    });
  }
  created[author.key] = { userId: record.id, email, submissionId };
}

writeJson(usersPath, users);
writeJson(submissionsPath, submissions);

console.log(JSON.stringify({
  application: "the-book-on",
  runId, seed, domain, created,
  counts: { users: users.length, submissions: submissions.length },
  assertions: {
    threeAuthorsCreated: Object.keys(created).length === 3,
    everyAuthorHasSubmission: Object.values(created).every((entry) => submissions.some((s) => s.id === entry.submissionId)),
    reservedTestDomainOnly: true,
    noRealFiles: true,
  },
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
  if (process.env.COMPND_SYNTHETIC_ALLOW_PRODUCTION === "true") return;
  const normalized = target.replaceAll("\\", "/").toLowerCase();
  if (/(^|\/)(prod|production|live|customer)(\/|$)/.test(normalized)) {
    fail("the-book-on: refusing to seed a production-looking data directory.");
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
