import { randomBytes } from "node:crypto";
import { assertAuthTime, normalizeClaims, requirePortfolioAdmin } from "./claims.mjs";
import { createJwksCache, verifyJwt } from "./jwks.mjs";
import { createPkcePair } from "./pkce.mjs";

const DEFAULT_TRANSACTION_TTL_MS = 10 * 60_000;
const DEFAULT_SESSION_TTL_SECONDS = 15 * 60;
const DEFAULT_ALGORITHMS = Object.freeze(["RS256", "ES256"]);

export class OidcError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "OidcError";
    this.code = code;
  }
}

function normalizedIssuer(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new OidcError("ISSUER_REQUIRED", "An OIDC issuer is required.");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new OidcError("INVALID_ISSUER", "OIDC issuer must be an absolute URL.");
  }
  return url.toString().replace(/\/+$/, "");
}

function requiredUrl(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new OidcError("INVALID_DISCOVERY", `Discovery document is missing ${name}.`);
  }
  try {
    new URL(value);
  } catch {
    throw new OidcError("INVALID_DISCOVERY", `Discovery document has an invalid ${name}.`);
  }
  return value;
}

function safeReturnTo(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function createMemoryTransactionStore({ ttlMs = DEFAULT_TRANSACTION_TTL_MS, maxEntries = 1000, now = Date.now } = {}) {
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new OidcError("INVALID_TRANSACTION_STORE", "Transaction store maxEntries must be a positive integer.");
  }
  const entries = new Map();

  function cleanup() {
    const current = now();
    for (const [key, value] of entries) {
      if (value.expiresAt <= current) entries.delete(key);
    }
  }

  function put(transaction) {
    if (!transaction || typeof transaction.state !== "string" || transaction.state.length === 0) {
      throw new OidcError("INVALID_TRANSACTION", "Authorization transaction must contain a state.");
    }
    cleanup();
    if (entries.size >= maxEntries) {
      throw new OidcError("TRANSACTION_STORE_FULL", "Too many pending authorization transactions.");
    }
    entries.set(transaction.state, {
      ...transaction,
      expiresAt: transaction.expiresAt ?? now() + ttlMs,
    });
    return transaction;
  }

  function take(state) {
    cleanup();
    const transaction = entries.get(state);
    if (!transaction) return null;
    entries.delete(state);
    return transaction.expiresAt > now() ? transaction : null;
  }

  return {
    put,
    take,
    get size() {
      cleanup();
      return entries.size;
    },
  };
}

export function createOidcClient({
  issuer,
  clientId,
  clientSecret = null,
  redirectUri,
  scopes = ["openid", "profile", "email"],
  adminSubject,
  adminGroup,
  sessionCodec = null,
  transactionStore = null,
  fetcher = fetch,
  now = Date.now,
  clockSkewSeconds = 60,
  sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
  algorithms = DEFAULT_ALGORITHMS,
  clientAuthMethod = clientSecret ? "client_secret_basic" : "none",
  transactionTtlMs = DEFAULT_TRANSACTION_TTL_MS,
} = {}) {
  const baseIssuer = normalizedIssuer(issuer);
  if (typeof clientId !== "string" || clientId.length === 0) {
    throw new OidcError("CLIENT_ID_REQUIRED", "OIDC client ID is required.");
  }
  if (typeof redirectUri !== "string" || redirectUri.length === 0) {
    throw new OidcError("REDIRECT_URI_REQUIRED", "OIDC redirect URI is required.");
  }
  try {
    new URL(redirectUri);
  } catch {
    throw new OidcError("INVALID_REDIRECT_URI", "OIDC redirect URI must be absolute.");
  }
  if (typeof adminSubject !== "string" || adminSubject.length === 0) {
    throw new OidcError("ADMIN_SUBJECT_REQUIRED", "An exact admin subject is required.");
  }
  if (typeof adminGroup !== "string" || adminGroup.length === 0) {
    throw new OidcError("ADMIN_GROUP_REQUIRED", "An admin group is required.");
  }
  if (typeof fetcher !== "function") {
    throw new OidcError("INVALID_FETCHER", "The OIDC fetcher must be a function.");
  }
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some((scope) => typeof scope !== "string" || !scope)) {
    throw new OidcError("INVALID_SCOPES", "OIDC scopes must be a non-empty array of strings.");
  }
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new OidcError("INVALID_ALGORITHMS", "OIDC algorithms must be a non-empty array.");
  }
  if (!["client_secret_basic", "client_secret_post", "none"].includes(clientAuthMethod)) {
    throw new OidcError("INVALID_CLIENT_AUTH", "Unsupported client authentication method.");
  }
  if (clientAuthMethod !== "none" && !clientSecret) {
    throw new OidcError("CLIENT_SECRET_REQUIRED", "Client secret is required for the selected client authentication method.");
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new OidcError("INVALID_CLOCK_SKEW", "Clock skew must be a non-negative number.");
  }
  if (!Number.isInteger(sessionTtlSeconds) || sessionTtlSeconds < 1 || sessionTtlSeconds > 3600) {
    throw new OidcError("INVALID_SESSION_TTL", "Session TTL must be an integer from 1 to 3600 seconds.");
  }
  if (!Number.isInteger(transactionTtlMs) || transactionTtlMs < 1) {
    throw new OidcError("INVALID_TRANSACTION_TTL", "Transaction TTL must be a positive integer.");
  }

  const store = transactionStore ?? createMemoryTransactionStore({ ttlMs: transactionTtlMs, now });
  let discoveryPromise = null;
  let jwksCache = null;

  async function loadDiscovery() {
    const discoveryUrl = new URL(`${baseIssuer}/.well-known/openid-configuration`);
    const response = await fetcher(discoveryUrl, {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    if (!response || !response.ok) {
      throw new OidcError("DISCOVERY_FAILED", `OIDC discovery failed with status ${response?.status ?? "unknown"}.`);
    }
    const document = await response.json();
    if (!document || typeof document !== "object" || Array.isArray(document)) {
      throw new OidcError("DISCOVERY_INVALID", "OIDC discovery document must be an object.");
    }
    if (normalizedIssuer(document.issuer) !== baseIssuer) {
      throw new OidcError("DISCOVERY_ISSUER_MISMATCH", "Discovery issuer does not match the configured issuer.");
    }
    requiredUrl(document.authorization_endpoint, "authorization_endpoint");
    requiredUrl(document.token_endpoint, "token_endpoint");
    requiredUrl(document.jwks_uri, "jwks_uri");
    if (document.end_session_endpoint !== undefined) {
      requiredUrl(document.end_session_endpoint, "end_session_endpoint");
    }
    if (document.userinfo_endpoint !== undefined) {
      requiredUrl(document.userinfo_endpoint, "userinfo_endpoint");
    }
    return document;
  }

  function getDiscovery() {
    if (!discoveryPromise) {
      discoveryPromise = loadDiscovery().catch((error) => {
        discoveryPromise = null;
        throw error;
      });
    }
    return discoveryPromise;
  }

  async function getJwks() {
    if (!jwksCache) {
      const document = await getDiscovery();
      jwksCache = createJwksCache({ jwksUri: document.jwks_uri, fetcher, now });
    }
    return jwksCache;
  }

  async function beginAuthorization({ returnTo = "/", maxAgeSeconds = null, prompt = null } = {}) {
    const document = await getDiscovery();
    if (maxAgeSeconds !== null && (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 0)) {
      throw new OidcError("INVALID_MAX_AGE", "maxAgeSeconds must be a non-negative integer or null.");
    }
    if (prompt !== null && (typeof prompt !== "string" || prompt.length === 0)) {
      throw new OidcError("INVALID_PROMPT", "prompt must be a non-empty string or null.");
    }
    const state = randomToken();
    const nonce = randomToken();
    const pair = createPkcePair();
    const transaction = {
      state,
      nonce,
      codeVerifier: pair.verifier,
      redirectUri,
      returnTo: safeReturnTo(returnTo),
      maxAgeSeconds,
      prompt,
      expiresAt: now() + transactionTtlMs,
    };
    store.put(transaction);
    const url = new URL(document.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", pair.challenge);
    url.searchParams.set("code_challenge_method", pair.method);
    if (maxAgeSeconds !== null) url.searchParams.set("max_age", String(maxAgeSeconds));
    if (prompt !== null) url.searchParams.set("prompt", prompt);
    return Object.freeze({ url: url.toString(), state });
  }

  async function completeAuthorization({ code, state, transaction = null } = {}) {
    if (typeof code !== "string" || code.length === 0) {
      throw new OidcError("CODE_REQUIRED", "Authorization code is required.");
    }
    if (typeof state !== "string" || state.length === 0) {
      throw new OidcError("STATE_REQUIRED", "Authorization state is required.");
    }
    const saved = transaction ?? store.take(state);
    if (!saved || saved.state !== state) {
      throw new OidcError("STATE_MISMATCH", "Authorization state is invalid or already used.");
    }
    if (saved.expiresAt <= now()) {
      throw new OidcError("AUTHORIZATION_EXPIRED", "Authorization transaction has expired.");
    }

    const document = await getDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: saved.redirectUri,
      code_verifier: saved.codeVerifier,
    });
    const headers = {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    };
    if (clientAuthMethod === "client_secret_basic") {
      headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
    } else {
      body.set("client_id", clientId);
      if (clientAuthMethod === "client_secret_post") body.set("client_secret", clientSecret);
    }

    const response = await fetcher(document.token_endpoint, { method: "POST", headers, body });
    if (!response || !response.ok) {
      throw new OidcError("TOKEN_EXCHANGE_FAILED", `Token exchange failed with status ${response?.status ?? "unknown"}.`);
    }
    const tokens = await response.json();
    if (!tokens || typeof tokens.id_token !== "string") {
      throw new OidcError("ID_TOKEN_REQUIRED", "Token response did not contain an ID token.");
    }

    const keys = await getJwks();
    const nowSeconds = Math.floor(now() / 1000);
    const verified = await verifyJwt(tokens.id_token, {
      keys,
      issuer: document.issuer,
      audience: clientId,
      algorithms,
      clockSkewSeconds,
      nowSeconds,
    });
    if (verified.claims.nonce !== saved.nonce) {
      throw new OidcError("NONCE_MISMATCH", "ID token nonce does not match the authorization request.");
    }
    requirePortfolioAdmin(verified.claims, { adminSubject, adminGroup });
    if (saved.maxAgeSeconds !== null) {
      assertAuthTime(verified.claims, saved.maxAgeSeconds, { nowSeconds, clockSkewSeconds });
    }

    const session = sessionCodec
      ? sessionCodec.issue(verified.claims, { sessionTtlSeconds })
      : null;
    return Object.freeze({
      claims: verified.claims,
      session,
      returnTo: saved.returnTo,
      tokens: Object.freeze({
        accessToken: tokens.access_token ?? null,
        tokenType: tokens.token_type ?? null,
        expiresIn: tokens.expires_in ?? null,
      }),
      idToken: tokens.id_token,
    });
  }

  async function logoutUrl({ idTokenHint = null, postLogoutRedirectUri = null, state = null } = {}) {
    const document = await getDiscovery();
    if (!document.end_session_endpoint) return null;
    const url = new URL(document.end_session_endpoint);
    url.searchParams.set("client_id", clientId);
    if (idTokenHint) url.searchParams.set("id_token_hint", idTokenHint);
    if (postLogoutRedirectUri) url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
    if (state) url.searchParams.set("state", state);
    return url.toString();
  }

  async function checkUserInfo(accessToken, { expectedAdminSubject = adminSubject, expectedAdminGroup = adminGroup } = {}) {
    if (typeof accessToken !== "string" || accessToken.length === 0) {
      throw new OidcError("ACCESS_TOKEN_REQUIRED", "A server-side access token is required for the userinfo check.");
    }
    const document = await getDiscovery();
    if (!document.userinfo_endpoint) {
      throw new OidcError("USERINFO_UNAVAILABLE", "The provider does not advertise a userinfo endpoint.");
    }
    const response = await fetcher(document.userinfo_endpoint, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });
    if (!response || !response.ok) {
      throw new OidcError("USERINFO_FAILED", `Userinfo check failed with status ${response?.status ?? "unknown"}.`);
    }
    const payload = await response.json();
    const claims = normalizeClaims(payload);
    requirePortfolioAdmin(claims, {
      adminSubject: expectedAdminSubject,
      adminGroup: expectedAdminGroup,
    });
    return claims;
  }

  function validateSession(token, { maxAgeSeconds = null } = {}) {
    if (!sessionCodec) {
      throw new OidcError("SESSION_CODEC_REQUIRED", "A session codec is required to validate a session.");
    }
    const session = sessionCodec.read(token);
    requirePortfolioAdmin(session.claims, { adminSubject, adminGroup });
    if (maxAgeSeconds !== null) {
      assertAuthTime(session.claims, maxAgeSeconds, {
        nowSeconds: Math.floor(now() / 1000),
        clockSkewSeconds,
      });
    }
    return session;
  }

  return Object.freeze({
    beginAuthorization,
    completeAuthorization,
    getDiscovery,
    checkUserInfo,
    logoutUrl,
    validateSession,
    clientId,
    issuer: baseIssuer,
    redirectUri,
    adminSubject,
    adminGroup,
    sessionTtlSeconds,
    transactionStore: store,
  });
}
