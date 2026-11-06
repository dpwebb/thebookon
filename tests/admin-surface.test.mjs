import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tbo-admin-'));
process.env.DATA_DIR = dataDir;
process.env.SESSION_SECRET = 'test-session-secret-with-enough-entropy-123456789';
const require = createRequire(import.meta.url);
const { app } = require('../server.js');

const admin = {
  id: 'usr_admin',
  fullName: 'Compnd Systems Admin',
  email: 'admin@example.test',
  phone: '',
  passwordHash: 'pbkdf2$210000$salt$hash',
  internalAdmin: true,
  mfa: { enabledAt: Date.now(), secret: 'encrypted-secret', lastUsedStep: -1 },
  createdAt: new Date().toISOString()
};
const adminNoMfa = {
  id: 'usr_admin_nomfa',
  fullName: 'Admin Without MFA',
  email: 'admin-nomfa@example.test',
  phone: '',
  passwordHash: 'pbkdf2$210000$salt$hash',
  internalAdmin: true,
  createdAt: new Date().toISOString()
};
const author = {
  id: 'usr_author',
  fullName: 'Author Example',
  email: 'author@example.test',
  phone: '',
  passwordHash: 'pbkdf2$210000$salt$hash',
  internalAdmin: false,
  createdAt: new Date().toISOString()
};
const submission = {
  id: 'ms_1',
  userId: author.id,
  authorName: author.fullName,
  email: author.email,
  title: 'A Test Manuscript',
  category: 'Fiction',
  stage: 'Complete',
  serviceInterest: 'Editing',
  audience: 'Adult readers',
  synopsis: 'A test synopsis',
  status: 'Pending',
  reviewState: 'Under Review',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  file: {
    originalName: 'manuscript.txt',
    relativePath: 'uploads/2026/01/manuscript.txt',
    size: 8,
    mimeType: 'text/plain'
  }
};

fs.mkdirSync(path.join(dataDir, 'uploads', '2026', '01'), { recursive: true });
fs.writeFileSync(path.join(dataDir, 'uploads', '2026', '01', 'manuscript.txt'), 'manuscript');
fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify([admin, adminNoMfa, author], null, 2));
fs.writeFileSync(path.join(dataDir, 'submissions.json'), JSON.stringify([submission], null, 2));
fs.writeFileSync(path.join(dataDir, 'contacts.json'), JSON.stringify([{ id: 'contact_1', name: 'Reader', email: 'reader@example.test', message: 'Question', createdAt: new Date().toISOString() }], null, 2));
fs.writeFileSync(path.join(dataDir, 'password-reset-requests.json'), JSON.stringify([{ id: 'reset_1', email: author.email, createdAt: new Date().toISOString() }], null, 2));

function cookieFor(user, { mfa = Boolean(user.mfa && user.mfa.enabledAt) } = {}) {
  const payload = Buffer.from(JSON.stringify({
    uid: user.id,
    email: user.email,
    mfa,
    exp: Date.now() + 60_000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payload).digest('base64url');
  return `tbo_session=${encodeURIComponent(`${payload}.${signature}`)}`;
}

const server = http.createServer(app);
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

test.after(() => {
  server.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('admin surface requires login, administrator flag and MFA', async () => {
  const anonymous = await fetch(`${base}/admin`, { redirect: 'manual' });
  assert.equal(anonymous.status, 303);
  assert.equal(anonymous.headers.get('location'), '/login/');

  const nonAdmin = await fetch(`${base}/admin`, { headers: { cookie: cookieFor(author) }, redirect: 'manual' });
  assert.equal(nonAdmin.status, 403);
  assert.match(await nonAdmin.text(), /Administrator Access Required/);

  const noMfa = await fetch(`${base}/admin`, {
    headers: { cookie: cookieFor(adminNoMfa) },
    redirect: 'manual'
  });
  assert.equal(noMfa.status, 403);
  assert.match(await noMfa.text(), /Administrator MFA Required/);

  const stalePreMfaSession = await fetch(`${base}/admin`, {
    headers: { cookie: cookieFor(admin, { mfa: false }) },
    redirect: 'manual'
  });
  assert.equal(stalePreMfaSession.status, 403);
  assert.match(await stalePreMfaSession.text(), /Administrator MFA Required/);

  const adminPage = await fetch(`${base}/admin`, { headers: { cookie: cookieFor(admin) }, redirect: 'manual' });
  assert.equal(adminPage.status, 200);
  const html = await adminPage.text();
  assert.match(html, /Admin overview/);
  assert.match(html, /A Test Manuscript/);
  assert.match(html, /author@example\.test/);
  assert.doesNotMatch(html, /passwordHash|encrypted-secret/);
});

test('admin overview API is admin-only and returns sanitized data', async () => {
  const denied = await fetch(`${base}/api/admin/overview`, { headers: { cookie: cookieFor(author) } });
  assert.equal(denied.status, 403);

  const allowed = await fetch(`${base}/api/admin/overview`, { headers: { cookie: cookieFor(admin) } });
  assert.equal(allowed.status, 200);
  const body = await allowed.json();
  assert.equal(body.counts.submissions, 1);
  assert.equal(body.counts.users, 3);
  assert.equal(body.submissions[0].title, 'A Test Manuscript');
  assert.equal(body.users.find((user) => user.id === admin.id).mfaEnabled, true);
});

test('admin can update a review and download a manuscript', async () => {
  const update = await fetch(`${base}/admin/submissions/ms_1`, {
    method: 'POST',
    headers: {
      cookie: cookieFor(admin),
      'content-type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({ status: 'In Review', reviewState: 'Needs Information', note: 'Request a longer synopsis.' }),
    redirect: 'manual'
  });
  assert.equal(update.status, 303);
  assert.equal(update.headers.get('location'), '/admin/submissions/ms_1?updated=1');

  const stored = JSON.parse(fs.readFileSync(path.join(dataDir, 'submissions.json'), 'utf8'));
  assert.equal(stored[0].status, 'In Review');
  assert.equal(stored[0].reviewState, 'Needs Information');
  assert.equal(stored[0].adminNotes[0].by, admin.email);
  assert.equal(stored[0].adminNotes[0].note, 'Request a longer synopsis.');

  const detail = await fetch(`${base}/admin/submissions/ms_1`, { headers: { cookie: cookieFor(admin) } });
  assert.equal(detail.status, 200);
  assert.match(await detail.text(), /Request a longer synopsis/);

  const download = await fetch(`${base}/admin/download/ms_1`, { headers: { cookie: cookieFor(admin) } });
  assert.equal(download.status, 200);
  assert.equal(await download.text(), 'manuscript');
});
