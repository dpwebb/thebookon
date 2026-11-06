const { notifications } = require("./notifications/project.cjs");
notifications.start();
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const express = require("express");
const multer = require("multer");
const mfa = require("./helpers/mfa");
const { createCgssAdmin } = require("./helpers/cgssAdmin");

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
const MFA_CHALLENGES_FILE = path.join(DATA_DIR, "mfa-challenges.json");
const SECRET_FILE = path.join(DATA_DIR, "session-secret.txt");

const allowedManuscriptExtensions = new Set([
  ".doc",
  ".docx",
  ".odt",
  ".pdf",
  ".rtf",
  ".txt"
]);

const ADMIN_SUBMISSION_STATUSES = ["Pending", "In Review", "Editorial Review", "On Hold", "Accepted", "Declined"];
const ADMIN_REVIEW_STATES = ["Under Review", "Needs Information", "Ready for Decision", "Accepted", "Declined"];

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function ensureStore() {
  ensureDir(DATA_DIR);
  ensureDir(UPLOAD_DIR);
  for (const file of [USERS_FILE, SUBMISSIONS_FILE, CONTACTS_FILE, RESET_REQUESTS_FILE, MFA_CHALLENGES_FILE]) {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, "[]\n", "utf8");
    }
  }
}

function readJson(file) {
  let records;
  try {
    records = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    console.error("Unable to read author portal store", path.basename(file), error.code || error.name);
    throw new Error("The author portal is temporarily unable to access its records.");
  }
  if (!Array.isArray(records)) {
    console.error("Invalid author portal store", path.basename(file));
    throw new Error("The author portal is temporarily unable to access its records.");
  }
  return records;
}

function handleAsync(handler) {
  return (req, res, next) => handler(req, res).catch(next);
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

function encodeSession(user, { mfaVerified = mfaEnabled(user), ttlMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
  const payload = Buffer.from(JSON.stringify({
    uid: user.id,
    email: user.email,
    mfa: Boolean(mfaVerified),
    exp: Date.now() + ttlMs
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
    const user = users.find((candidate) => candidate.id === data.uid && candidate.email === data.email);
    if (!user) return null;
    Object.defineProperty(user, "__sessionMfa", {
      value: data.mfa === true,
      enumerable: false,
      configurable: true
    });
    return user;
  } catch {
    return null;
  }
}

function setSessionCookie(req, res, user, { mfaVerified = mfaEnabled(user), ttlMs = 7 * 24 * 60 * 60 * 1000 } = {}) {
  const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
  const cookie = [
    `${COOKIE_NAME}=${encodeURIComponent(encodeSession(user, { mfaVerified, ttlMs }))}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.max(1, Math.floor(ttlMs / 1000))}`
  ];
  if (secure) cookie.push("Secure");
  res.setHeader("Set-Cookie", cookie.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

const cgssAdmin = createCgssAdmin({
  usersFile: USERS_FILE,
  dataDir: DATA_DIR,
  setSessionCookie
});

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

function adminDeniedPage(res, title, body) {
  adminHeaders(res);
  sendConfirmation(res, confirmationPage({ title, status: 403, body }));
}

function adminPageUser(req, res) {
  const user = getUserFromRequest(req);
  if (!user) {
    res.redirect(303, "/login/");
    return null;
  }
  if (user.internalAdmin !== true) {
    adminDeniedPage(res, "Administrator Access Required", "<p>This account is not an administrator for The Book On.</p><p><a class=\"button\" href=\"/my-author-account/\">Return to your account</a></p>");
    return null;
  }
  if (user.__sessionMfa !== true) {
    adminDeniedPage(res, "Administrator MFA Required", "<p>This session has not completed two-factor verification. Use the portfolio CGSSO sign-in or sign in with a native account that has MFA enabled.</p><p><a class=\"button\" href=\"/auth/admin/start\">Portfolio administrator sign-in</a></p><p><a class=\"button secondary\" href=\"/login/\">Native sign in</a></p>");
    return null;
  }
  return user;
}

function requireAdminApi(req, res, next) {
  const user = getUserFromRequest(req);
  if (!user) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  if (user.internalAdmin !== true) {
    res.status(403).json({ error: "Administrator access required" });
    return;
  }
  if (user.__sessionMfa !== true) {
    res.status(403).json({ error: "Administrator MFA is required" });
    return;
  }
  req.user = user;
  next();
}

function adminData() {
  const users = readJson(USERS_FILE, []);
  const submissions = readJson(SUBMISSIONS_FILE, [])
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const contacts = readJson(CONTACTS_FILE, [])
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const resetRequests = readJson(RESET_REQUESTS_FILE, [])
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return {
    users: users.map((user) => ({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone || "",
      createdAt: user.createdAt,
      internalAdmin: user.internalAdmin === true,
      mfaEnabled: mfaEnabled(user)
    })),
    submissions,
    contacts,
    resetRequests,
    counts: {
      users: users.length,
      submissions: submissions.length,
      pendingSubmissions: submissions.filter((submission) => submission.status === "Pending").length,
      contacts: contacts.length,
      resetRequests: resetRequests.filter((request) => Number(request.completedAt || 0) === 0).length
    }
  };
}

function adminHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function adminOptions(values, current) {
  return values.map((value) => `<option value="${escapeHtml(value)}"${value === current ? " selected" : ""}>${escapeHtml(value)}</option>`).join("");
}

function adminLayout(title, user, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header class="site-header"><div class="header-inner">
<a class="brand" href="/admin">The Book On Admin</a>
<nav class="nav" aria-label="Admin navigation"><a href="/admin">Submissions</a><a href="/">Public site</a></nav>
<form action="/api/logout" method="post"><button class="button secondary" type="submit">Sign out</button></form>
</div></header><main class="section"><div class="section-inner">
<p class="eyebrow">Administrator: ${escapeHtml(user.email)}</p><h1>${escapeHtml(title)}</h1>${body}
</div></main></body></html>`;
}

function adminDashboardPage({ user, data, message, error }) {
  const submissionRows = data.submissions.map((submission) => `<tr>
<td><a href="/admin/submissions/${encodeURIComponent(submission.id)}">${escapeHtml(submission.title || "Untitled")}</a><br><small>${escapeHtml(submission.id)}</small></td>
<td>${escapeHtml(submission.authorName || "Unknown")}<br><small>${escapeHtml(submission.email || "")}</small></td>
<td>${escapeHtml(submission.status || "Pending")}<br><small>${escapeHtml(submission.reviewState || "Under Review")}</small></td>
<td>${escapeHtml(submission.createdAt || "")}</td>
<td><a href="/admin/download/${encodeURIComponent(submission.id)}">Download</a></td></tr>`).join("");
  const userRows = data.users.map((account) => `<tr><td>${escapeHtml(account.fullName || "")}<br><small>${escapeHtml(account.email || "")}</small></td><td>${account.internalAdmin ? "Administrator" : "Author"}</td><td>${account.mfaEnabled ? "Enabled" : "Not enabled"}</td><td>${escapeHtml(account.createdAt || "")}</td></tr>`).join("");
  const contactRows = data.contacts.slice(0, 50).map((contact) => `<li><strong>${escapeHtml(contact.name || contact.email || "Contact")}</strong> ${escapeHtml(contact.email || "")}<br>${escapeHtml(contact.message || contact.subject || "")}<br><small>${escapeHtml(contact.createdAt || "")}</small></li>`).join("") || "<li>No contact messages.</li>";
  const resetRows = data.resetRequests.slice(0, 50).map((request) => `<li>${escapeHtml(request.email || "Unknown")} <small>${escapeHtml(request.createdAt || "")}</small></li>`).join("") || "<li>No password reset requests.</li>";
  return adminLayout("Admin overview", user, `
    ${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}${message ? `<p role="status">${escapeHtml(message)}</p>` : ""}
    <div class="notice"><strong>${data.counts.users}</strong> accounts · <strong>${data.counts.submissions}</strong> submissions · <strong>${data.counts.pendingSubmissions}</strong> pending · <strong>${data.counts.contacts}</strong> contact messages · <strong>${data.counts.resetRequests}</strong> open reset requests</div>
    <h2>Submissions</h2><div style="overflow:auto"><table><thead><tr><th>Title</th><th>Author</th><th>Status</th><th>Received</th><th>File</th></tr></thead><tbody>${submissionRows || "<tr><td colspan=\"5\">No submissions.</td></tr>"}</tbody></table></div>
    <h2>Author accounts</h2><div style="overflow:auto"><table><thead><tr><th>Account</th><th>Role</th><th>MFA</th><th>Created</th></tr></thead><tbody>${userRows}</tbody></table></div>
    <h2>Contact messages</h2><ul>${contactRows}</ul>
    <h2>Password reset requests</h2><ul>${resetRows}</ul>`);
}

function adminSubmissionPage({ user, submission, message, error }) {
  const notes = (submission.adminNotes || []).map((note) => `<li>${escapeHtml(note.note || "")}<br><small>${escapeHtml(note.at || "")} · ${escapeHtml(note.by || "")}</small></li>`).join("") || "<li>No administrator notes.</li>";
  return adminLayout("Submission review", user, `
    ${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}${message ? `<p role="status">${escapeHtml(message)}</p>` : ""}
    <p><a href="/admin">Back to admin overview</a> · <a href="/admin/download/${encodeURIComponent(submission.id)}">Download manuscript</a></p>
    <dl>
      <dt>Reference</dt><dd>${escapeHtml(submission.id)}</dd>
      <dt>Author</dt><dd>${escapeHtml(submission.authorName || "Unknown")} · ${escapeHtml(submission.email || "")}</dd>
      <dt>Title</dt><dd>${escapeHtml(submission.title || "Untitled")}</dd>
      <dt>Category / stage</dt><dd>${escapeHtml(submission.category || "")} · ${escapeHtml(submission.stage || "")}</dd>
      <dt>Service interest</dt><dd>${escapeHtml(submission.serviceInterest || "")}</dd>
      <dt>Synopsis</dt><dd><pre style="white-space:pre-wrap">${escapeHtml(submission.synopsis || "")}</pre></dd>
      <dt>Target reader</dt><dd><pre style="white-space:pre-wrap">${escapeHtml(submission.audience || "")}</pre></dd>
      <dt>Received / updated</dt><dd>${escapeHtml(submission.createdAt || "")} · ${escapeHtml(submission.updatedAt || "")}</dd>
    </dl>
    <h2>Review decision</h2>
    <form action="/admin/submissions/${encodeURIComponent(submission.id)}" method="post">
      <p><label>Status<br><select name="status">${adminOptions(ADMIN_SUBMISSION_STATUSES, submission.status || "Pending")}</select></label></p>
      <p><label>Review state<br><select name="reviewState">${adminOptions(ADMIN_REVIEW_STATES, submission.reviewState || "Under Review")}</select></label></p>
      <p><label>Administrator note (optional)<br><textarea name="note" rows="4" maxlength="2000"></textarea></label></p>
      <p><button class="button" type="submit">Save review</button></p>
    </form>
    <h2>Administrator notes</h2><ul>${notes}</ul>`);
}

const MFA_ISSUER = process.env.MFA_ISSUER || "The Book On Publishing";
const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MFA_ENROLLMENT_TTL_MS = 10 * 60 * 1000;
const MFA_LOCK_MS = 15 * 60 * 1000;

function saveUser(user) {
  const users = readJson(USERS_FILE, []);
  const index = users.findIndex((candidate) => candidate.id === user.id);
  if (index !== -1) users[index] = user;
  writeJson(USERS_FILE, users);
}

function mfaEnabled(user) {
  return Boolean(user && user.mfa && user.mfa.enabledAt && user.mfa.secret);
}

function issueMfaChallenge(userId) {
  const { token, hash } = mfa.newChallengeToken();
  const now = Date.now();
  const challenges = readJson(MFA_CHALLENGES_FILE, [])
    .filter((challenge) => challenge.expiresAt > now && challenge.userId !== userId);
  challenges.push({
    hash,
    userId,
    expiresAt: now + MFA_CHALLENGE_TTL_MS,
    attempts: 0,
    createdAt: now
  });
  writeJson(MFA_CHALLENGES_FILE, challenges);
  return token;
}

function findMfaChallenge(token) {
  if (!token || String(token).length > 200) return null;
  const hash = mfa.sha256Hex(token);
  const now = Date.now();
  const challenges = readJson(MFA_CHALLENGES_FILE, []);
  const current = challenges.find((challenge) => challenge.hash === hash);
  const active = challenges.filter((challenge) => challenge.expiresAt > now);
  if (active.length !== challenges.length) writeJson(MFA_CHALLENGES_FILE, active);
  return current && current.expiresAt > now ? current : null;
}

function updateMfaChallenge(challenge, changes) {
  const challenges = readJson(MFA_CHALLENGES_FILE, []);
  const index = challenges.findIndex((candidate) => candidate.hash === challenge.hash);
  if (index !== -1) {
    challenges[index] = { ...challenges[index], ...changes };
    writeJson(MFA_CHALLENGES_FILE, challenges);
  }
}

function removeMfaChallenges(userId) {
  const challenges = readJson(MFA_CHALLENGES_FILE, [])
    .filter((challenge) => challenge.userId !== userId);
  writeJson(MFA_CHALLENGES_FILE, challenges);
}

function issueBackupCodes(user) {
  const codes = mfa.generateBackupCodes();
  user.mfa = user.mfa || {};
  user.mfa.backupCodes = codes.map((code) => ({
    hash: mfa.backupCodeHash(user.id, code),
    usedAt: null,
    createdAt: Date.now()
  }));
  return codes;
}

function verifyUserSecondFactor(user, code, backupCode) {
  const state = user.mfa;
  if (!state || !state.enabledAt || !state.secret) return null;
  if (code) {
    try {
      const step = mfa.matchTotp(
        mfa.decryptSecret(state.secret, sessionSecret),
        code,
        Number(state.lastUsedStep ?? -1)
      );
      if (step !== null) {
        state.lastUsedStep = step;
        return "totp";
      }
    } catch {
      return null;
    }
  }
  if (backupCode) {
    const normalized = mfa.normalizeBackupCode(backupCode);
    if (!/^[A-F0-9]{16}$/.test(normalized)) return null;
    const hash = mfa.backupCodeHash(user.id, normalized);
    const entry = (state.backupCodes || []).find(
      (candidate) => !candidate.usedAt && candidate.hash === hash
    );
    if (entry) {
      entry.usedAt = Date.now();
      return "backup";
    }
  }
  return null;
}

function mfaLocked(user) {
  return Boolean(user.mfa && user.mfa.lockedUntil && user.mfa.lockedUntil > Date.now());
}

function registerMfaFailure(user) {
  user.mfa = user.mfa || {};
  user.mfa.failedAttempts = Number(user.mfa.failedAttempts || 0) + 1;
  if (user.mfa.failedAttempts >= mfa.MAX_ATTEMPTS) {
    user.mfa.lockedUntil = Date.now() + MFA_LOCK_MS;
    user.mfa.failedAttempts = 0;
  }
}

function clearMfaFailures(user) {
  if (!user.mfa) return;
  user.mfa.failedAttempts = 0;
  user.mfa.lockedUntil = 0;
}
function mfaLoginPage({ token, error }) {
  return confirmationPage({
    title: "Two-Factor Verification",
    status: error ? 401 : 200,
    body: `
      ${error ? `<p role="alert">${escapeHtml(error)}</p>` : ""}
      <p>Enter the 6-digit code from your authenticator app, or one of your backup codes.</p>
      <form action="/api/login/mfa" method="post">
        <input type="hidden" name="challenge" value="${escapeHtml(token || "")}">
        <p><label>Authenticator code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}"></label></p>
        <p><label>Or a backup code<br><input name="backup_code" autocomplete="one-time-code" maxlength="64"></label></p>
        <p><button class="button" type="submit">Verify and sign in</button></p>
      </form>
      <p><a href="/login/">Start over</a></p>
    `
  });
}

function accountMfaPage({ user, error, message, backupCodes }) {
  const state = user.mfa || {};
  const enabled = mfaEnabled(user);
  const pending =
    state.pendingSecret && Number(state.pendingExpiresAt || 0) > Date.now();
  const remaining = (state.backupCodes || []).filter((code) => !code.usedAt).length;

  let body = "";
  if (error) body += `<p role="alert">${escapeHtml(error)}</p>`;
  if (message) body += `<p role="status">${escapeHtml(message)}</p>`;
  body += `<p>Status: <strong>${enabled ? "Enabled" : "Not enabled"}</strong>${
    enabled ? ` &middot; ${remaining} backup code${remaining === 1 ? "" : "s"} remaining` : ""
  }</p>`;

  if (backupCodes && backupCodes.length) {
    body += `<p><strong>Save these backup codes now.</strong> Each code works once and they will not be shown again.</p>
      <ul>${backupCodes.map((code) => `<li><code>${escapeHtml(code)}</code></li>`).join("")}</ul>`;
  }

  if (!backupCodes && pending) {
    let secret = "";
    let uri = "";
    try {
      secret = mfa.decryptSecret(state.pendingSecret, sessionSecret);
      uri = mfa.buildOtpAuthUrl({ issuer: MFA_ISSUER, accountName: user.email, secret });
    } catch {
      body += `<p role="alert">The pending authenticator setup could not be read. Start setup again.</p>`;
    }
    if (secret) {
      body += `<p>Scan this QR code with your authenticator app, or enter the setup key manually.</p>
        <div id="mfa-qr" data-uri="${escapeHtml(uri)}" style="width:200px;height:200px"></div>
        <p>Setup key: <code>${escapeHtml(secret)}</code></p>
        <form action="/account/mfa/confirm" method="post">
          <p><label>Six-digit code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required></label></p>
          <p><button class="button" type="submit">Enable two-factor authentication</button></p>
        </form>
        <script src="/qrcode-generator.js"></script>
        <script>
          (function () {
            var el = document.getElementById("mfa-qr");
            if (!el || !window.qrcode) return;
            try {
              var qr = qrcode(0, "M");
              qr.addData(el.getAttribute("data-uri"));
              qr.make();
              el.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4 });
            } catch (error) {
              el.textContent = "QR code unavailable. Use the setup key shown below.";
            }
          }());
        </script>`;
    }
  }

  if (!backupCodes && !enabled && !pending) {
    body += `<form action="/account/mfa/setup" method="post">
      <p><label>Confirm your password<br><input type="password" name="password" autocomplete="current-password" required></label></p>
      <p><button class="button" type="submit">Set up authenticator app</button></p>
    </form>`;
  }

  if (!backupCodes && enabled) {
    body += `<form action="/account/mfa/backup-codes" method="post">
      <p><strong>Replace backup codes</strong></p>
      <p><label>Password<br><input type="password" name="password" autocomplete="current-password" required></label></p>
      <p><label>Authenticator code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label></p>
      <p><label>Or a backup code<br><input name="backup_code" autocomplete="one-time-code" maxlength="64"></label></p>
      <p><button class="button secondary" type="submit">Replace backup codes</button></p>
    </form>
    <form action="/account/mfa/disable" method="post">
      <p><strong>Turn off two-factor authentication</strong></p>
      <p><label>Password<br><input type="password" name="password" autocomplete="current-password" required></label></p>
      <p><label>Authenticator code<br><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6"></label></p>
      <p><label>Or a backup code<br><input name="backup_code" autocomplete="one-time-code" maxlength="64"></label></p>
      <p><button class="button secondary" type="submit">Turn off two-factor authentication</button></p>
    </form>`;
  }

  body += `<p><a href="/my-author-account/">Back to your account</a></p>`;
  return confirmationPage({ title: "Account Security", body });
}

function sendAccountMfaPage(res, user, options = {}, status = 200) {
  res.setHeader("Cache-Control", "no-store");
  res.status(status).type("html").send(accountMfaPage({ user, ...options }).html);
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

app.post("/api/register", handleAsync(async (req, res) => {
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

  const users = readJson(USERS_FILE);
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
  await notifications.notify({event:"author.registered",key:user.id,reference:user.id,to:user.email});
  setSessionCookie(req, res, user);
  res.redirect(303, "/my-author-account/?registered=1");
}));

app.post("/api/login", (req, res) => {
  if (isSpam(req)) {
    res.redirect(303, "/");
    return;
  }

  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const users = readJson(USERS_FILE);
  const user = users.find((candidate) => candidate.email === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    sendConfirmation(res, confirmationPage({
      title: "Login Failed",
      status: 401,
      body: "<p>The email or password did not match an author account.</p><p><a class=\"button\" href=\"/login/\">Try again</a></p>"
    }));
    return;
  }

  if (mfaEnabled(user)) {
    if (mfaLocked(user)) {
      sendConfirmation(res, confirmationPage({
        title: "Login Temporarily Locked",
        status: 429,
        body: "<p>Too many verification attempts. Wait 15 minutes and try again.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
      }));
      return;
    }
    const challengeToken = issueMfaChallenge(user.id);
    res.setHeader("Cache-Control", "no-store");
    sendConfirmation(res, mfaLoginPage({ token: challengeToken }));
    return;
  }

  setSessionCookie(req, res, user);
  res.redirect(303, "/my-author-account/?login=1");
});

app.post("/api/login/mfa", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const token = String(req.body.challenge || "");
  const challenge = findMfaChallenge(token);

  if (!challenge) {
    sendConfirmation(res, confirmationPage({
      title: "Verification Expired",
      status: 401,
      body: "<p>The sign-in challenge expired. Enter your password again to continue.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
    }));
    return;
  }

  const users = readJson(USERS_FILE, []);
  const user = users.find((candidate) => candidate.id === challenge.userId);
  if (!user || !mfaEnabled(user)) {
    removeMfaChallenges(challenge.userId);
    sendConfirmation(res, confirmationPage({
      title: "Verification Unavailable",
      status: 401,
      body: "<p>Two-factor authentication is not enabled for this account.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
    }));
    return;
  }

  if (mfaLocked(user)) {
    removeMfaChallenges(user.id);
    sendConfirmation(res, confirmationPage({
      title: "Login Temporarily Locked",
      status: 429,
      body: "<p>Too many verification attempts. Wait 15 minutes and try again.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
    }));
    return;
  }

  if (Number(challenge.attempts || 0) >= mfa.MAX_ATTEMPTS) {
    removeMfaChallenges(user.id);
    sendConfirmation(res, confirmationPage({
      title: "Verification Expired",
      status: 401,
      body: "<p>Too many attempts were made for this challenge.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
    }));
    return;
  }

  const method = verifyUserSecondFactor(
    user,
    cleanText(req.body.code || "", 10),
    cleanText(req.body.backup_code || "", 64)
  );

  if (!method) {
    registerMfaFailure(user);
    saveUser(user);
    const attempts = Number(challenge.attempts || 0) + 1;
    if (attempts >= mfa.MAX_ATTEMPTS) {
      removeMfaChallenges(user.id);
    } else {
      updateMfaChallenge(challenge, { attempts });
    }
    sendConfirmation(res, mfaLoginPage({
      token,
      error: "That code was not accepted. Check your authenticator and try again."
    }));
    return;
  }

  clearMfaFailures(user);
  saveUser(user);
  removeMfaChallenges(user.id);
  setSessionCookie(req, res, user);
  res.redirect(303, "/my-author-account/?login=1");
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  res.redirect(303, "/login/?logged-out=1");
});

app.post("/api/contact", handleAsync(async (req, res) => {
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

  const contacts = readJson(CONTACTS_FILE);
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
  await notifications.notify({event:"contact.received",key:id,reference:id,to:email});
  await notifications.notify({event:"intake.contact",key:id,reference:id});

  sendConfirmation(res, confirmationPage({
    title: "Message Received",
    body: `<p>Thank you. Your message has been recorded and our team can follow up using the contact details you provided.</p><p><strong>Reference:</strong> ${escapeHtml(id)}</p><p><a class="button" href="/manuscript-submission/">Submit a manuscript</a> <a class="button secondary" href="/">Return home</a></p>`
  }));
}));

app.post("/api/password-reset", handleAsync(async (req, res) => {
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

  const users = readJson(USERS_FILE);
  const user = users.find((candidate) => candidate.email === email);
  const requests = readJson(RESET_REQUESTS_FILE);
  requests.push({
    id: createId("rst"),
    email,
    userId: user ? user.id : null,
    status: "Requested",
    createdAt: new Date().toISOString(),
    ip: req.ip
  });
  writeJson(RESET_REQUESTS_FILE, requests);
  if(user) await notifications.notify({event:"account.reset_help",key:requests[requests.length-1].id,reference:requests[requests.length-1].id});

  sendConfirmation(res, confirmationPage({
    title: "Reset Request Recorded",
    body: "<p>If the email address belongs to an author account, a reset-help request has been recorded for support review. For urgent access help, contact support@thebookon.ca.</p><p><a class=\"button\" href=\"/login/\">Return to login</a></p>"
  }));
}));

app.post("/api/manuscripts", upload.single("manuscript_file"), handleAsync(async (req, res) => {
  let saved = false;
  try {
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
      sendConfirmation(res, confirmationPage({
        title: "Submission Needs Attention",
        status: 400,
        body: `<p>Please complete the missing item${missing.length === 1 ? "" : "s"}: ${escapeHtml(missing.join(", "))}.</p><p><a class="button" href="/manuscript-submission/">Return to submission</a></p>`
      }));
      return;
    }

    const submissions = readJson(SUBMISSIONS_FILE);
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
    saved = true;
    await notifications.notify({event:"manuscript.received",key:id,reference:id,to:email});
    await notifications.notify({event:"intake.manuscript",key:id,reference:id});

    sendConfirmation(res, confirmationPage({
      title: "Submission Received",
      body: `<p>Your manuscript has been received and logged for editorial review.</p><p><strong>Reference:</strong> ${escapeHtml(id)}</p><p>Initial status: <strong>Pending</strong>. Review state: <strong>Under Review</strong>.</p><p>If you submitted while logged in, this will appear in your dashboard. If you submitted as a guest, keep this reference and contact support to request a status update or withdrawal.</p><p><a class="button" href="/my-author-account/">View dashboard</a> <a class="button secondary" href="/contact-us/">Contact support</a></p>`
    }));
  } finally {
    if (req.file && !saved) fs.rmSync(req.file.path, { force: true });
  }
}));

app.post("/api/manuscripts/withdrawal", handleAsync(async (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) return res.redirect(303, "/login/");
  const submissions = readJson(SUBMISSIONS_FILE);
  const submission = submissions.find((row) => row.id === req.body.id && row.userId === user.id);
  if (!submission) return res.sendStatus(404);
  if (!submission.withdrawal) {
    submission.updatedAt = new Date().toISOString();
    submission.withdrawal = { requestedAt: submission.updatedAt };
    writeJson(SUBMISSIONS_FILE, submissions);
  }
  if (!submission.withdrawal.resolvedAt) {
    await notifications.notify({ event: "intake.withdrawal", key: submission.id, reference: submission.id });
  }
  res.redirect(303, "/my-author-account/");
}));

app.post("/internal/editorial/withdrawal", handleAsync(async (req, res) => {
  const expected = Buffer.from(signPayload("thebookon:editorial-withdrawal:v1"));
  const supplied = Buffer.from(req.get("X-Editorial-Key") || "");
  if (req.socket.remoteAddress !== "127.0.0.1" && req.socket.remoteAddress !== "::ffff:127.0.0.1") {
    return res.sendStatus(404);
  }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.sendStatus(404);
  }
  if (req.body.preAgreementVerified !== true) return res.sendStatus(400);
  const submissions = readJson(SUBMISSIONS_FILE);
  const submission = submissions.find((row) => row.id === req.body.id);
  if (!submission?.withdrawal?.requestedAt) return res.sendStatus(404);
  const author = readJson(USERS_FILE).find((row) => row.id === submission.userId);
  if (!author || !validateEmail(author.email)) return res.sendStatus(409);
  if (!submission.withdrawal.resolvedAt) {
    submission.updatedAt = new Date().toISOString();
    submission.withdrawal.resolvedAt = submission.updatedAt;
    submission.withdrawal.confirmationEmail = author.email;
    submission.status = "Withdrawn";
    submission.reviewState = "Closed";
    writeJson(SUBMISSIONS_FILE, submissions);
  }
  const notice = await notifications.notify({
    event: "manuscript.withdrawn", key: submission.id, reference: submission.id,
    to: submission.withdrawal.confirmationEmail
  });
  res.json({ id: submission.id, status: submission.status, confirmation: notice.status });
}));

function authorSubmissions(user) {
  return readJson(SUBMISSIONS_FILE)
    .filter((submission) => submission.userId === user.id)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .map((submission) => ({
      id: submission.id,
      title: submission.title,
      category: submission.category,
      stage: submission.stage,
      serviceInterest: submission.serviceInterest,
      status: submission.status,
      reviewState: submission.reviewState,
      withdrawalState: submission.withdrawal?.resolvedAt ? "confirmed" : submission.withdrawal?.requestedAt ? "requested" : null,
      createdAt: submission.createdAt,
      updatedAt: submission.updatedAt,
      fileName: submission.file && submission.file.originalName
    }));

}

app.use(["/api/session", "/api/submissions"], (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.get("/api/session", (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    res.json({ authenticated: false, submissions: [] });
    return;
  }

  res.json({
    authenticated: true,
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone || ""
    },
    submissions: authorSubmissions(user)
  });
});

app.get("/api/submissions", requireAuth, (req, res) => {
  res.json({ submissions: authorSubmissions(req.user) });
});

function accountUser(req, res) {
  const user = getUserFromRequest(req);
  if (!user) {
    res.redirect(303, "/login/");
    return null;
  }
  return user;
}

app.get("/account/mfa", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  sendAccountMfaPage(res, user);
});

app.post("/account/mfa/setup", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (mfaEnabled(user)) {
    sendAccountMfaPage(res, user, {
      error: "An authenticator is already enabled. Turn it off before setting up a new one."
    }, 409);
    return;
  }
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  user.mfa = user.mfa || {};
  user.mfa.pendingSecret = mfa.encryptSecret(mfa.generateSecret(), sessionSecret);
  user.mfa.pendingExpiresAt = Date.now() + MFA_ENROLLMENT_TTL_MS;
  saveUser(user);
  res.redirect(303, "/account/mfa?setup=1");
});

app.post("/account/mfa/confirm", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  const state = user.mfa || {};
  if (!state.pendingSecret || Number(state.pendingExpiresAt || 0) <= Date.now()) {
    sendAccountMfaPage(res, user, {
      error: "Authenticator setup expired. Start setup again."
    }, 410);
    return;
  }
  let step = null;
  try {
    step = mfa.matchTotp(
      mfa.decryptSecret(state.pendingSecret, sessionSecret),
      cleanText(req.body.code || "", 10),
      -1
    );
  } catch {
    step = null;
  }
  if (step === null) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator code is not valid."
    }, 400);
    return;
  }
  user.mfa = {
    secret: state.pendingSecret,
    enabledAt: Date.now(),
    lastUsedStep: step,
    failedAttempts: 0,
    lockedUntil: 0
  };
  const backupCodes = issueBackupCodes(user);
  saveUser(user);
  removeMfaChallenges(user.id);
  sendAccountMfaPage(res, user, {
    message: "Two-factor authentication is enabled.",
    backupCodes
  });
});

app.post("/account/mfa/disable", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  if (!mfaEnabled(user)) {
    sendAccountMfaPage(res, user, { error: "Two-factor authentication is not enabled." }, 409);
    return;
  }
  const method = verifyUserSecondFactor(
    user,
    cleanText(req.body.code || "", 10),
    cleanText(req.body.backup_code || "", 64)
  );
  if (!method) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator or backup code is not valid."
    }, 401);
    return;
  }
  delete user.mfa;
  saveUser(user);
  removeMfaChallenges(user.id);
  sendAccountMfaPage(res, user, { message: "Two-factor authentication is turned off." });
});

app.post("/account/mfa/backup-codes", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  const method = verifyUserSecondFactor(
    user,
    cleanText(req.body.code || "", 10),
    cleanText(req.body.backup_code || "", 64)
  );
  if (!method) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator or backup code is not valid."
    }, 401);
    return;
  }
  const backupCodes = issueBackupCodes(user);
  saveUser(user);
  sendAccountMfaPage(res, user, {
    message: "New backup codes issued.",
    backupCodes
  });
});

app.get("/auth/admin/start", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    res.redirect(302, await cgssAdmin.start(req));
  } catch (error) {
    res.status(error.statusCode || 503).json({ error: "Admin sign-in is unavailable." });
  }
});

app.get("/auth/admin/callback", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    await cgssAdmin.callback(req, res);
    res.redirect(303, "/admin");
  } catch (error) {
    res.status(error.statusCode || 401).json({ error: "Admin sign-in failed." });
  }
});

app.get("/admin", (req, res) => {
  const user = adminPageUser(req, res);
  if (!user) return;
  adminHeaders(res);
  res.status(200).type("html").send(adminDashboardPage({
    user,
    data: adminData(),
    message: req.query.updated ? "Submission review saved." : ""
  }));
});

app.get("/api/admin/overview", requireAdminApi, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(adminData());
});

app.get("/admin/submissions/:id", (req, res) => {
  const user = adminPageUser(req, res);
  if (!user) return;
  const submission = readJson(SUBMISSIONS_FILE, []).find((candidate) => candidate.id === req.params.id);
  if (!submission) {
    adminHeaders(res);
    sendConfirmation(res, confirmationPage({
      title: "Submission Not Found",
      status: 404,
      body: "<p>The requested submission does not exist.</p><p><a class=\"button\" href=\"/admin\">Back to admin overview</a></p>"
    }));
    return;
  }
  adminHeaders(res);
  res.status(200).type("html").send(adminSubmissionPage({
    user,
    submission,
    message: req.query.updated ? "Submission review saved." : ""
  }));
});

app.post("/admin/submissions/:id", (req, res) => {
  const user = adminPageUser(req, res);
  if (!user) return;
  const status = cleanText(req.body.status, 80);
  const reviewState = cleanText(req.body.reviewState, 80);
  const note = cleanLongText(req.body.note, 2000);
  if (!ADMIN_SUBMISSION_STATUSES.includes(status) || !ADMIN_REVIEW_STATES.includes(reviewState)) {
    adminHeaders(res);
    const submission = readJson(SUBMISSIONS_FILE, []).find((candidate) => candidate.id === req.params.id);
    if (!submission) {
      sendConfirmation(res, confirmationPage({ title: "Submission Not Found", status: 404, body: "<p>The requested submission does not exist.</p>" }));
      return;
    }
    sendConfirmation(res, confirmationPage({
      title: "Review Decision Needs Attention",
      status: 400,
      body: `<p>Choose a valid status and review state.</p><p><a class="button" href="/admin/submissions/${escapeHtml(encodeURIComponent(submission.id))}">Return to review</a></p>`
    }));
    return;
  }
  const submissions = readJson(SUBMISSIONS_FILE, []);
  const submission = submissions.find((candidate) => candidate.id === req.params.id);
  if (!submission) {
    adminHeaders(res);
    sendConfirmation(res, confirmationPage({ title: "Submission Not Found", status: 404, body: "<p>The requested submission does not exist.</p>" }));
    return;
  }
  const now = new Date().toISOString();
  submission.status = status;
  submission.reviewState = reviewState;
  submission.updatedAt = now;
  if (note) {
    submission.adminNotes = Array.isArray(submission.adminNotes) ? submission.adminNotes : [];
    submission.adminNotes.push({ at: now, by: user.email, note });
  }
  writeJson(SUBMISSIONS_FILE, submissions);
  res.redirect(303, `/admin/submissions/${encodeURIComponent(submission.id)}?updated=1`);
});

app.get("/admin/download/:id", (req, res) => {
  const user = adminPageUser(req, res);
  if (!user) return;
  const submission = readJson(SUBMISSIONS_FILE, []).find((candidate) => candidate.id === req.params.id);
  if (!submission || !submission.file || !submission.file.relativePath) {
    res.status(404).json({ error: "Manuscript file not found" });
    return;
  }
  const root = path.resolve(DATA_DIR) + path.sep;
  const filePath = path.resolve(DATA_DIR, submission.file.relativePath);
  if (!filePath.startsWith(root) || !fs.existsSync(filePath)) {
    res.status(404).json({ error: "Manuscript file not found" });
    return;
  }
  res.setHeader("Cache-Control", "no-store");
  res.download(filePath, submission.file.originalName || "manuscript");
});

function accountUser(req, res) {
  const user = getUserFromRequest(req);
  if (!user) {
    res.redirect(303, "/login/");
    return null;
  }
  return user;
}

app.get("/account/mfa", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  sendAccountMfaPage(res, user);
});

app.post("/account/mfa/setup", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (mfaEnabled(user)) {
    sendAccountMfaPage(res, user, {
      error: "An authenticator is already enabled. Turn it off before setting up a new one."
    }, 409);
    return;
  }
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  user.mfa = user.mfa || {};
  user.mfa.pendingSecret = mfa.encryptSecret(mfa.generateSecret(), sessionSecret);
  user.mfa.pendingExpiresAt = Date.now() + MFA_ENROLLMENT_TTL_MS;
  saveUser(user);
  res.redirect(303, "/account/mfa?setup=1");
});

app.post("/account/mfa/confirm", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  const state = user.mfa || {};
  if (!state.pendingSecret || Number(state.pendingExpiresAt || 0) <= Date.now()) {
    sendAccountMfaPage(res, user, {
      error: "Authenticator setup expired. Start setup again."
    }, 410);
    return;
  }
  let step = null;
  try {
    step = mfa.matchTotp(
      mfa.decryptSecret(state.pendingSecret, sessionSecret),
      cleanText(req.body.code || "", 10),
      -1
    );
  } catch {
    step = null;
  }
  if (step === null) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator code is not valid."
    }, 400);
    return;
  }
  user.mfa = {
    secret: state.pendingSecret,
    enabledAt: Date.now(),
    lastUsedStep: step,
    failedAttempts: 0,
    lockedUntil: 0
  };
  const backupCodes = issueBackupCodes(user);
  saveUser(user);
  removeMfaChallenges(user.id);
  sendAccountMfaPage(res, user, {
    message: "Two-factor authentication is enabled.",
    backupCodes
  });
});

app.post("/account/mfa/disable", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  if (!mfaEnabled(user)) {
    sendAccountMfaPage(res, user, { error: "Two-factor authentication is not enabled." }, 409);
    return;
  }
  const method = verifyUserSecondFactor(
    user,
    cleanText(req.body.code || "", 10),
    cleanText(req.body.backup_code || "", 64)
  );
  if (!method) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator or backup code is not valid."
    }, 401);
    return;
  }
  delete user.mfa;
  saveUser(user);
  removeMfaChallenges(user.id);
  sendAccountMfaPage(res, user, { message: "Two-factor authentication is turned off." });
});

app.post("/account/mfa/backup-codes", (req, res) => {
  const user = accountUser(req, res);
  if (!user) return;
  if (!verifyPassword(String(req.body.password || ""), user.passwordHash)) {
    sendAccountMfaPage(res, user, { error: "Password is incorrect." }, 401);
    return;
  }
  const method = verifyUserSecondFactor(
    user,
    cleanText(req.body.code || "", 10),
    cleanText(req.body.backup_code || "", 64)
  );
  if (!method) {
    sendAccountMfaPage(res, user, {
      error: "That authenticator or backup code is not valid."
    }, 401);
    return;
  }
  const backupCodes = issueBackupCodes(user);
  saveUser(user);
  sendAccountMfaPage(res, user, {
    message: "New backup codes issued.",
    backupCodes
  });
});

app.use(express.static(PUBLIC_DIR, {
  extensions: ["html"],
  maxAge: "1h",
  setHeaders(res, filePath) {
    if (path.extname(filePath).toLowerCase() === ".html") {
      res.setHeader("Cache-Control", "no-cache");
    }
  }
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

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`The Book On service listening on ${PORT}`);
  });
}
module.exports = { app };
