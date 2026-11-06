import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createCgssAdmin } = require('../helpers/cgssAdmin.js');

const ADMIN_SUBJECT = 'e0dab951-27da-4d75-b1df-ced8fcb250e5';
const ADMIN_EMAIL = 'admin@example.test';
const HOST = '127.0.0.1:3515';
const env = {
  CGSS_ISSUER: 'http://issuer.test/application/o/the-book-on/',
  CGSS_CLIENT_ID: 'the-book-on-local',
  CGSS_CLIENT_SECRET: 'local-test-secret',
  CGSS_REDIRECT_URI: `http://${HOST}/auth/admin/callback`,
  CGSS_ADMIN_SUBJECT: ADMIN_SUBJECT,
  CGSS_ADMIN_GROUP: 'portfolio-superadmin'
};

function claims(overrides = {}) {
  return {
    sub: ADMIN_SUBJECT,
    email: ADMIN_EMAIL,
    emailVerified: true,
    groups: ['portfolio-superadmin'],
    acr: 'goauthentik.io/providers/oauth2/default',
    amr: ['pwd', 'mfa'],
    authTime: 1_800_000_000,
    nonce: 'nonce',
    ...overrides
  };
}

function fakeClient(value = claims()) {
  const calls = { begin: [], complete: [] };
  return {
    calls,
    client: {
      issuer: env.CGSS_ISSUER,
      async beginAuthorization(options = {}) {
        calls.begin.push(options);
        return { url: 'http://issuer.test/authorize?state=test-state', state: 'test-state' };
      },
      async completeAuthorization(options) {
        calls.complete.push(options);
        return { claims: value, returnTo: '/admin', tokens: {}, idToken: 'test' };
      }
    }
  };
}

function fakeAdapter() {
  return {
    requirePortfolioAdmin(value, config) {
      if (value.sub !== config.adminSubject || !value.groups.includes(config.adminGroup)) {
        throw new Error('PORTFOLIO_ADMIN_REQUIRED');
      }
      return true;
    }
  };
}

function request(url) {
  return { headers: { host: HOST }, originalUrl: url };
}

function harness({ value = claims(), admin = true } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tbo-cgss-'));
  const usersFile = path.join(dataDir, 'users.json');
  fs.writeFileSync(usersFile, JSON.stringify([
    { id: 'usr_admin', email: ADMIN_EMAIL, fullName: 'Admin', internalAdmin: admin },
    { id: 'usr_author', email: 'author@example.test', fullName: 'Author', internalAdmin: false }
  ], null, 2));
  const sessions = [];
  const { client } = fakeClient(value);
  const service = createCgssAdmin({
    usersFile,
    dataDir,
    setSessionCookie: (_req, _res, user, options) => sessions.push({ user, options }),
    env,
    client,
    adapter: fakeAdapter()
  });
  return { service, dataDir, usersFile, sessions };
}

function cleanup(dataDir) {
  fs.rmSync(dataDir, { recursive: true, force: true });
}

test('start requests the fixed admin destination', async () => {
  const h = harness();
  try {
    assert.equal(await h.service.start(request('/auth/admin/start')), 'http://issuer.test/authorize?state=test-state');
  } finally {
    cleanup(h.dataDir);
  }
});

test('callback issues a native MFA-verified session and records one link', async () => {
  const h = harness();
  try {
    const user = await h.service.callback(request('/auth/admin/callback?code=test&state=test-state'));
    assert.equal(user.email, ADMIN_EMAIL);
    assert.equal(h.sessions.length, 1);
    assert.equal(h.sessions[0].options.mfaVerified, true);
    assert.equal(h.sessions[0].options.ttlMs, 900000);
    await h.service.callback(request('/auth/admin/callback?code=test&state=test-state'));
    const links = JSON.parse(fs.readFileSync(path.join(h.dataDir, 'cgss-admin-links.json'), 'utf8'));
    assert.equal(links.length, 1);
    assert.equal(links[0].subject, ADMIN_SUBJECT);
    assert.equal(links[0].email, ADMIN_EMAIL);
  } finally {
    cleanup(h.dataDir);
  }
});

test('callback rejects a different subject, missing MFA and non-admin account', async () => {
  for (const [value, admin] of [
    [claims({ sub: 'different-user' }), true],
    [claims({ amr: ['pwd'] }), true],
    [claims(), false]
  ]) {
    const h = harness({ value, admin });
    try {
      await assert.rejects(
        () => h.service.callback(request('/auth/admin/callback?code=test&state=test-state')),
        /CGSSO_/
      );
      assert.equal(h.sessions.length, 0);
    } finally {
      cleanup(h.dataDir);
    }
  }
});
