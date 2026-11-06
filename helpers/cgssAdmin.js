"use strict";

const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("node:url");

const DEFAULT_ADMIN_GROUP = "portfolio-superadmin";
let client;
let adapter;

function required(env, name) {
  const value = env[name]?.trim();
  if (!value) {
    throw Object.assign(new Error("CGSSO_NOT_CONFIGURED"), { statusCode: 503 });
  }
  return value;
}

function config(env) {
  return {
    issuer: required(env, "CGSS_ISSUER"),
    clientId: required(env, "CGSS_CLIENT_ID"),
    clientSecret: required(env, "CGSS_CLIENT_SECRET"),
    redirectUri: required(env, "CGSS_REDIRECT_URI"),
    adminSubject: required(env, "CGSS_ADMIN_SUBJECT"),
    adminGroup: env.CGSS_ADMIN_GROUP?.trim() || DEFAULT_ADMIN_GROUP
  };
}

async function modules() {
  if (adapter) return adapter;
  try {
    adapter = await import("@compnd/cgsso-adapter");
  } catch {
    adapter = await import(pathToFileURL(path.resolve(__dirname, "../../../governance/portfolio/sso/adapter/index.mjs")).href);
  }
  return adapter;
}

async function getClient(env) {
  if (client) return client;
  const value = config(env);
  const { createMemoryTransactionStore, createOidcClient } = await modules();
  client = createOidcClient({
    issuer: value.issuer,
    clientId: value.clientId,
    clientSecret: value.clientSecret,
    redirectUri: value.redirectUri,
    adminSubject: value.adminSubject,
    adminGroup: value.adminGroup,
    transactionStore: createMemoryTransactionStore({ maxEntries: 200 }),
    clientAuthMethod: env.CGSS_CLIENT_AUTH_METHOD?.trim() || "client_secret_basic"
  });
  return client;
}

function assertHost(req, env) {
  const expected = new URL(required(env, "CGSS_REDIRECT_URI")).host;
  if (req.headers.host !== expected) {
    throw Object.assign(new Error("CGSSO_HOST_REQUIRED"), { statusCode: 403 });
  }
}

function writeLink(dataDir, record) {
  const file = path.join(dataDir, "cgss-admin-links.json");
  let links = [];
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    if (Array.isArray(parsed)) links = parsed;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  links = links.filter((item) => item && item.email !== record.email);
  links.push(record);
  fs.writeFileSync(file, `${JSON.stringify(links)}\n`, { mode: 0o600 });
}

function createCgssAdmin({ usersFile, dataDir, setSessionCookie, env = process.env, client: injectedClient = null, adapter: injectedAdapter = null }) {
  if (injectedClient) client = injectedClient;
  if (injectedAdapter) adapter = injectedAdapter;

  async function start(req) {
    assertHost(req, env);
    const authorization = await (await getClient(env)).beginAuthorization({ returnTo: "/admin" });
    return authorization.url;
  }

  async function callback(req, res) {
    assertHost(req, env);
    const requestUrl = new URL(req.originalUrl || req.url, "http://local");
    const code = requestUrl.searchParams.get("code") || "";
    const state = requestUrl.searchParams.get("state") || "";
    if (!code || !state) {
      throw Object.assign(new Error("CGSSO_RESPONSE_INCOMPLETE"), { statusCode: 400 });
    }

    let completed;
    try {
      completed = await (await getClient(env)).completeAuthorization({ code, state });
    } catch {
      throw Object.assign(new Error("CGSSO_TOKEN_INVALID"), { statusCode: 401 });
    }

    const value = config(env);
    const { requirePortfolioAdmin } = await modules();
    try {
      requirePortfolioAdmin(completed.claims, {
        adminSubject: value.adminSubject,
        adminGroup: value.adminGroup
      });
    } catch {
      throw Object.assign(new Error("CGSSO_ADMIN_REQUIRED"), { statusCode: 403 });
    }
    if (!Array.isArray(completed.claims.amr) || !completed.claims.amr.includes("mfa")) {
      throw Object.assign(new Error("CGSSO_MFA_REQUIRED"), { statusCode: 403 });
    }

    const email = completed.claims.email?.trim().toLowerCase();
    if (!email) throw Object.assign(new Error("CGSSO_EMAIL_REQUIRED"), { statusCode: 403 });
    const users = JSON.parse(fs.readFileSync(usersFile, "utf8"));
    const user = users.find((candidate) => candidate.email === email && candidate.internalAdmin === true);
    if (!user) throw Object.assign(new Error("CGSSO_ADMIN_ACCOUNT_REQUIRED"), { statusCode: 403 });

    writeLink(dataDir, {
      issuer: value.issuer,
      subject: completed.claims.sub,
      email,
      updated_at: new Date().toISOString()
    });
    setSessionCookie(req, res, user, { mfaVerified: true, ttlMs: 15 * 60 * 1000 });
    return user;
  }

  return { start, callback };
}

module.exports = { createCgssAdmin };
