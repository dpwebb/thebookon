const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const express = require("express");
const multer = require("multer");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const COOKIE_NAME = "tbo_session";

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SUBMISSIONS_FILE = path.join(DATA_DIR, "submissions.json");
const CONTACTS_FILE = path.join(DATA_DIR, "contacts.json");
const RESET_REQUESTS_FILE = path.join(DATA_DIR, "password-reset-requests.json");
const SECRET_FILE = path.join(DATA_DIR, "session-secret.txt");

const allowedManuscriptExtensions = new Set([
  ".doc",
  ".docx",
  ".odt",
  ".pdf",
  ".rtf",
  ".txt"
]);

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function ensureStore() {
  ensureDir(DATA_DIR);
  ensureDir(UPLOAD_DIR);
  for (const file of [USERS_FILE, SUBMISSIONS_FILE, CONTACTS_FILE, RESET_REQUESTS_FILE]) {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, "[]\n", "utf8");
    }
  }
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  const tempFile = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempFile, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  fs.renameSync(tempFile, file);
}

function getSecret() {
  if (process.env.SESSION_SECRET) {
    return process.env.SESSION_SECRET;
  }
  if (fs.existsSync(SECRET_FILE)) {
    return fs.readFileSync(SECRET_FILE, "utf8").trim();
  }
  const secret = crypto.randomBytes(32).toString("base64url");
  fs.writeFileSync(SECRET_FILE, `${secret}\n`, { encoding: "utf8", mode: 0o600 });
  return secret;
}

ensureStore();
const sessionSecret = getSecret();

function createId(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(5).toString("hex")}`;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function cleanText(value, maxLength = 2000) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function cleanLongText(value, maxLength = 12000) {
  return String(value || "").replace(/\r\n/g, "\n").trim().slice(0, maxLength);
}

function sanitizeFilename(filename) {
  const ext = path.extname(filename).toLowerCase();
  const base = path.basename(filename, ext)
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "manuscript";
  return `${base}${ext}`;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashPassword(password) {
  const iterations = 210000;
  const salt = crypto.randomBytes(16).toString("base64url");
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64url");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}

function verifyPassword(password, storedHash) {
  const [scheme, iterationsValue, salt, expectedHash] = String(storedHash || "").split("$");
  if (scheme !== "pbkdf2" || !iterationsValue || !salt || !expectedHash) {
    return false;
  }
  const iterations = Number(iterationsValue);
  const actual = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64url");
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expectedHash);
  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function signPayload(payload) {
  return crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
}

function encodeSession(user) {
  const payload = Buffer.from(JSON.stringify({
    uid: user.id,
    email: user.email,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");
  return `${payload}.${signPayload(payload)}`;
}

function parseCookies(req) {
  const cookies = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return cookies;
}

function getUserFromRequest(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || signPayload(payload) !== signature) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Date.now()) return null;
    const users = readJson(USERS_FILE, []);
    return users.find((user) => user.id === data.uid && user.email === data.email) || null;
  } catch {
    return null;
  }
}

function setSessionCookie(req, res, user) {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  const cookie = [
    `${COOKIE_NAME}=${encodeURIComponent(encodeSession(user))}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=604800"
  ];
  if (secure) cookie.push("Secure");
  res.setHeader("Set-Cookie", cookie.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

function confirmationPage({ title, eyebrow = "The Book On Publishing", body, status = 200 }) {
  return {
    status,
    html: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/styles.css?v=reading-room-20260604">
</head>
<body>
  <header class="site-header">
    <div class="header-inner">
      <a class="brand" href="/">
        <img src="/assets/thebookonlogo-transparent.png" alt="" width="54" height="54">
        <span>The Book On Publishing</span>
      </a>
      <nav class="nav" aria-label="Main navigation">
        <a href="/">Home</a>
        <a href="/series/">Series</a>
        <a href="/authors/">Authors</a>
        <a href="/the-book-on-getting-published/">Publishing</a>
        <a href="/author-success-guides/">Writing</a>
        <a href="/manuscript-submission/">Submit</a>
        <a href="/contact-us/">Contact</a>
      </nav>
    </div>
  </header>
  <main class="section">
    <div class="section-inner content">
      <p class="eyebrow">${escapeHtml(eyebrow)}</p>
      <h1>${escapeHtml(title)}</h1>
      <div class="notice">${body}</div>
    </div>
  </main>
  <footer class="site-footer">
    <div class="footer-inner">
      <span>&copy; The Book On Publishing</span>
      <span><a href="/privacy-policy/">Privacy Policy</a> &middot; <a href="/terms-conditions/">Terms & Conditions</a></span>
    </div>
  </footer>
</body>
</html>`
  };
}

function sendConfirmation(res, page) {
  res.status(page.status).type("html").send(page.html);
}

function isSpam(req) {
  return Boolean(cleanText(req.body.website || req.body.company_url || "", 200));
}

function requireAuth(req, res, next) {
  const user = getUserFromRequest(req);
  if (!user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  req.user = user;
  next();
}

app.set("trust proxy", true);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "thebookon" });
});

app.use(express.urlencoded({ extended: false, limit: "160kb" }));
app.use(express.json({ limit: "160kb" }));

const upload = multer({
  storage: multer.diskStorage({
    destination(req, file, callback) {
      const date = new Date();
      const dir = path.join(
        UPLOAD_DIR,
        String(date.getUTCFullYear()),
        String(date.getUTCMonth() + 1).padStart(2, "0")
      );
      ensureDir(dir);
      callback(null, dir);
    },
    filename(req, file, callback) {
      req.submissionId = req.submissionId || createId("ms");
      callback(null, `${req.submissionId}-${sanitizeFilename(file.originalname)}`);
    }
  }),
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 1,
    fields: 24
  },
  fileFilter(req, file, callback) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedManuscriptExtensions.has(ext)) {
      callback(new Error("Unsupported file type. Upload a PDF, DOC, DOCX, ODT, RTF, or TXT file."));
      return;
    }
    callback(null, true);
  }
});

app.post("/api/register", (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const fullName = cleanText(req.body.full_name, 160);
  const email = normalizeEmail(req.body.email);
  const phone = cleanText(req.body.phone, 80);
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirm_password || "");

  if (!fullName || !validateEmail(email) || password.length < 8 || password !== confirmPassword) {
    sendConfirmation(res, confirmationPage({
      title: "Registration Needs Attention",
      status: 400,
      body: "<p>Please provide your name, a valid email address, and a matching password of at least eight characters.</p><p><a class=\"button\" href=\"/register/\">Return to registration</a></p>"
    }));
    return;
  }

  const users = readJson(USERS_FILE, []);
  if (users.some((user) => user.email === email)) {
    sendConfirmation(res, confirmationPage({
      title: "Account Already Exists",
      status: 409,
      body: "<p>An author account already exists for that email address.</p><p><a class=\"button\" href=\"/login/\">Log in</a></p>"
    }));
    return;
  }

  const now = new Date().toISOString();
  const user = {
    id: createId("usr"),
    fullName,
    email,
    phone,
    passwordHash: hashPassword(password),
    createdAt: now,
    updatedAt: now
  };
  users.push(user);
  writeJson(USERS_FILE, users);
  setSessionCookie(req, res, user);
  res.redirect(303, "/my-author-account/?registered=1");
});

app.post("/api/login", (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const users = readJson(USERS_FILE, []);
  const user = users.find((candidate) => candidate.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    sendConfirmation(res, confirmationPage({
      title: "Login Failed",
      status: 401,
      body: "<p>The email or password did not match an author account.</p><p><a class=\"button\" href=\"/login/\">Try again</a></p>"
    }));
    return;
  }

  setSessionCookie(req, res, user);
  res.redirect(303, "/my-author-account/?login=1");
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  res.redirect(303, "/login/?logged-out=1");
});

app.post("/api/contact", (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const name = cleanText(req.body.name, 160);
  const email = normalizeEmail(req.body.email);
  const phone = cleanText(req.body.phone, 80);
  const topic = cleanText(req.body.topic, 160);
  const message = cleanLongText(req.body.message, 8000);

  if (!name || !validateEmail(email) || !message) {
    sendConfirmation(res, confirmationPage({
      title: "Message Needs Attention",
      status: 400,
      body: "<p>Please include your name, a valid email address, and a message.</p><p><a class=\"button\" href=\"/contact-us/\">Return to contact</a></p>"
    }));
    return;
  }

  const contacts = readJson(CONTACTS_FILE, []);
  const id = createId("msg");
  contacts.push({
    id,
    name,
    email,
    phone,
    topic,
    message,
    status: "New",
    createdAt: new Date().toISOString(),
    ip: req.ip
  });
  writeJson(CONTACTS_FILE, contacts);

  sendConfirmation(res, confirmationPage({
    title: "Message Received",
    body: `<p>Thank you. Your message has been recorded and our team can follow up using the contact details you provided.</p><p><strong>Reference:</strong> ${escapeHtml(id)}</p><p><a class="button" href="/manuscript-submission/">Submit a manuscript</a> <a class="button secondary" href="/">Return home</a></p>`
  }));
});

app.post("/api/password-reset", (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const email = normalizeEmail(req.body.email);
  if (!validateEmail(email)) {
    sendConfirmation(res, confirmationPage({
      title: "Reset Request Needs Attention",
      status: 400,
      body: "<p>Please enter a valid email address.</p><p><a class=\"button\" href=\"/password-reset/\">Try again</a></p>"
    }));
    return;
  }

  const users = readJson(USERS_FILE, []);
  const user = users.find((candidate) => candidate.email === email);
  const requests = readJson(RESET_REQUESTS_FILE, []);
  requests.push({
    id: createId("rst"),
    email,
    userId: user ? user.id : null,
    status: "Requested",
    createdAt: new Date().toISOString(),
    ip: req.ip
  });
  writeJson(RESET_REQUESTS_FILE, requests);

  sendConfirmation(res, confirmationPage({
    title: "Reset Request Recorded",
    body: "<p>If the email address belongs to an author account, a reset-help request has been recorded for support review. For urgent access help, contact support@thebookon.ca.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
  }));
});

app.post("/api/manuscripts", upload.single("manuscript_file"), (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const currentUser = getUserFromRequest(req);
  const authorName = cleanText(req.body.author_name || (currentUser && currentUser.fullName), 160);
  const email = normalizeEmail(req.body.email || (currentUser && currentUser.email));
  const phone = cleanText(req.body.phone || (currentUser && currentUser.phone), 80);
  const title = cleanText(req.body.title, 240);
  const category = cleanText(req.body.category, 120);
  const stage = cleanText(req.body.stage, 120);
  const serviceInterest = cleanText(req.body.service_interest, 160);
  const audience = cleanLongText(req.body.audience, 3000);
  const synopsis = cleanLongText(req.body.synopsis, 8000);
  const inspiration = cleanLongText(req.body.inspiration, 4000);
  const rightsConfirmed = req.body.rights_confirm === "yes";
  const termsConfirmed = req.body.terms_confirm === "yes";

  const missing = [];
  if (!authorName) missing.push("author name");
  if (!validateEmail(email)) missing.push("valid email");
  if (!title) missing.push("book title");
  if (!category) missing.push("category");
  if (!stage) missing.push("project stage");
  if (!serviceInterest) missing.push("publishing path");
  if (!audience) missing.push("target reader");
  if (!synopsis) missing.push("synopsis");
  if (!req.file) missing.push("manuscript or proposal file");
  if (!rightsConfirmed) missing.push("rights confirmation");
  if (!termsConfirmed) missing.push("terms confirmation");

  if (missing.length) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    sendConfirmation(res, confirmationPage({
      title: "Submission Needs Attention",
      status: 400,
      body: `<p>Please complete the missing item${missing.length === 1 ? "" : "s"}: ${escapeHtml(missing.join(", "))}.</p><p><a class="button" href="/manuscript-submission/">Return to submission</a></p>`
    }));
    return;
  }

  const submissions = readJson(SUBMISSIONS_FILE, []);
  const id = req.submissionId || createId("ms");
  const now = new Date().toISOString();
  const relativeUploadPath = path.relative(DATA_DIR, req.file.path).replaceAll(path.sep, "/");
  submissions.push({
    id,
    userId: currentUser ? currentUser.id : null,
    authorName,
    email,
    phone,
    title,
    category,
    stage,
    serviceInterest,
    audience,
    synopsis,
    inspiration,
    status: "Pending",
    reviewState: "Under Review",
    createdAt: now,
    updatedAt: now,
    file: {
      originalName: req.file.originalname,
      storedName: req.file.filename,
      relativePath: relativeUploadPath,
      size: req.file.size,
      mimeType: req.file.mimetype
    },
    ip: req.ip
  });
  writeJson(SUBMISSIONS_FILE, submissions);

  sendConfirmation(res, confirmationPage({
    title: "Submission Received",
    body: `<p>Your manuscript has been received and logged for editorial review.</p><p><strong>Reference:</strong> ${escapeHtml(id)}</p><p>Initial status: <strong>Pending</strong>. Review state: <strong>Under Review</strong>.</p><p>If you submitted while logged in, this will appear in your dashboard. If you submitted as a guest, create an account with ${escapeHtml(email)} to see it there.</p><p><a class="button" href="/my-author-account/">View dashboard</a> <a class="button secondary" href="/contact-us/">Contact support</a></p>`
  }));
});

app.get("/api/session", (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    res.json({ authenticated: false, submissions: [] });
    return;
  }
  const submissions = readJson(SUBMISSIONS_FILE, [])
    .filter((submission) => submission.userId === user.id || normalizeEmail(submission.email) === user.email)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .map((submission) => ({
      id: submission.id,
      title: submission.title,
      category: submission.category,
      stage: submission.stage,
      serviceInterest: submission.serviceInterest,
      status: submission.status,
      reviewState: submission.reviewState,
      createdAt: submission.createdAt,
      updatedAt: submission.updatedAt,
      fileName: submission.file && submission.file.originalName
    }));

  res.json({
    authenticated: true,
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone || ""
    },
    submissions
  });
});

app.get("/api/submissions", requireAuth, (req, res) => {
  const submissions = readJson(SUBMISSIONS_FILE, [])
    .filter((submission) => submission.userId === req.user.id || normalizeEmail(submission.email) === req.user.email)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  res.json({ submissions });
});

app.use(express.static(PUBLIC_DIR, {
  extensions: ["html"],
  maxAge: "1h"
}));

app.use((req, res) => {
  res.status(404).sendFile(path.join(PUBLIC_DIR, "404.html"));
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }
  const message = err instanceof multer.MulterError
    ? "The upload could not be accepted. Please use one manuscript file under 50 MB."
    : err.message || "The request could not be completed.";
  sendConfirmation(res, confirmationPage({
    title: "Request Could Not Be Completed",
    status: 400,
    body: `<p>${escapeHtml(message)}</p><p><a class="button" href="/manuscript-submission/">Return to submission</a></p>`
  }));
});

app.listen(PORT, () => {
  console.log(`The Book On service listening on ${PORT}`);
});
