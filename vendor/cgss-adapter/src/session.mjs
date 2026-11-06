import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { normalizeClaims } from "./claims.mjs";

const VERSION = 1;
const MIN_SECRET_BYTES = 32;
const DEFAULT_TTL_SECONDS = 15 * 60;
const MAX_TTL_SECONDS = 60 * 60;

export class SessionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SessionError";
    this.code = code;
  }
}

function secretBuffer(secret) {
  const value = Buffer.isBuffer(secret) ? secret : typeof secret === "string" ? Buffer.from(secret, "utf8") : null;
  if (!value || value.length < MIN_SECRET_BYTES) {
    throw new SessionError("SESSION_SECRET_REQUIRED", `Session secret must be at least ${MIN_SECRET_BYTES} bytes.`);
  }
  return value;
}

function signature(secret, body) {
  return createHmac("sha256", secret).update(body).digest("base64url");
}

function signatureMatches(actual, expected) {
  if (typeof actual !== "string" || actual.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

function assertTtl(value, maxTtlSeconds) {
  if (!Number.isInteger(value) || value < 1 || value > maxTtlSeconds) {
    throw new SessionError("INVALID_SESSION_TTL", `Session TTL must be an integer from 1 to ${maxTtlSeconds} seconds.`);
  }
  return value;
}

function cookieAttributes({ secure, sameSite, path }) {
  return [
    "HttpOnly",
    secure ? "Secure" : null,
    `SameSite=${sameSite}`,
    `Path=${path}`,
  ].filter(Boolean);
}

export function createSessionCodec({
  secret,
  cookieName = "compnd_admin_session",
  ttlSeconds = DEFAULT_TTL_SECONDS,
  maxTtlSeconds = MAX_TTL_SECONDS,
  now = Date.now,
  clockSkewSeconds = 30,
  secure = true,
  sameSite = "Lax",
  path = "/",
} = {}) {
  const key = secretBuffer(secret);
  if (typeof cookieName !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(cookieName)) {
    throw new SessionError("INVALID_COOKIE_NAME", "Cookie name must be 1-64 URL-safe characters.");
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new SessionError("INVALID_CLOCK_SKEW", "Clock skew must be a non-negative number.");
  }
  assertTtl(ttlSeconds, maxTtlSeconds);
  if (!["Strict", "Lax", "None"].includes(sameSite)) {
    throw new SessionError("INVALID_SAME_SITE", "SameSite must be Strict, Lax or None.");
  }
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new SessionError("INVALID_COOKIE_PATH", "Cookie path must start with /.");
  }

  function cookie(token, { maxAge = ttlSeconds } = {}) {
    assertTtl(maxAge, maxTtlSeconds);
    return [
      `${cookieName}=${encodeURIComponent(token)}`,
      ...cookieAttributes({ secure, sameSite, path }),
      `Max-Age=${maxAge}`,
    ].join("; ");
  }

  function clearCookie() {
    return [
      `${cookieName}=`,
      ...cookieAttributes({ secure, sameSite, path }),
      "Max-Age=0",
    ].join("; ");
  }

  function issue(rawClaims, { sessionTtlSeconds = ttlSeconds } = {}) {
    const claims = normalizeClaims(rawClaims);
    const ttl = assertTtl(sessionTtlSeconds, maxTtlSeconds);
    const issuedAt = Math.floor(now() / 1000);
    const payload = {
      v: VERSION,
      sid: randomBytes(16).toString("base64url"),
      sub: claims.sub,
      email: claims.email,
      email_verified: claims.emailVerified,
      groups: [...claims.groups],
      acr: claims.acr,
      amr: [...claims.amr],
      auth_time: claims.authTime,
      iat: issuedAt,
      exp: issuedAt + ttl,
    };
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const token = `${body}.${signature(key, body)}`;
    return Object.freeze({
      token,
      claims,
      sid: payload.sid,
      issuedAt,
      expiresAt: payload.exp,
      cookie: cookie(token, { maxAge: ttl }),
    });
  }

  function read(token) {
    const parts = String(token ?? "").split(".");
    if (parts.length !== 2) throw new SessionError("MALFORMED_SESSION", "Session token is malformed.");
    const [body, supplied] = parts;
    const expected = signature(key, body);
    if (!signatureMatches(supplied, expected)) {
      throw new SessionError("INVALID_SESSION_SIGNATURE", "Session signature is invalid.");
    }
    let payload;
    try {
      payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    } catch {
      throw new SessionError("MALFORMED_SESSION", "Session payload is not valid JSON.");
    }
    if (!payload || payload.v !== VERSION) {
      throw new SessionError("UNSUPPORTED_SESSION", "Session version is not supported.");
    }
    const nowSeconds = Math.floor(now() / 1000);
    if (!Number.isFinite(payload.exp) || payload.exp < nowSeconds - clockSkewSeconds) {
      throw new SessionError("SESSION_EXPIRED", "Session has expired.");
    }
    if (!Number.isFinite(payload.iat) || payload.iat > nowSeconds + clockSkewSeconds) {
      throw new SessionError("INVALID_SESSION_TIME", "Session issue time is invalid.");
    }
    const claims = normalizeClaims(payload);
    return Object.freeze({
      claims,
      sid: payload.sid,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    });
  }

  return Object.freeze({
    cookieName,
    ttlSeconds,
    issue,
    read,
    cookie,
    clearCookie,
  });
}
