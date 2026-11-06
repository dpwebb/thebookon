export class ClaimsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ClaimsError";
    this.code = code;
  }
}

function stringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

function authTime(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : null;
}

export function normalizeClaims(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ClaimsError("INVALID_CLAIMS", "Claims payload must be an object.");
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new ClaimsError("MISSING_SUB", "Claims must contain a non-empty subject.");
  }
  return Object.freeze({
    sub: payload.sub,
    email: typeof payload.email === "string" ? payload.email : null,
    emailVerified: payload.email_verified === true,
    groups: Object.freeze(stringArray(payload.groups)),
    acr: typeof payload.acr === "string" ? payload.acr : null,
    amr: Object.freeze(stringArray(payload.amr)),
    authTime: authTime(payload.auth_time),
    nonce: typeof payload.nonce === "string" ? payload.nonce : null,
  });
}

export function isPortfolioAdmin(claims, { adminSubject, adminGroup }) {
  return Boolean(
    claims &&
      typeof adminSubject === "string" &&
      typeof adminGroup === "string" &&
      claims.sub === adminSubject &&
      Array.isArray(claims.groups) &&
      claims.groups.includes(adminGroup),
  );
}

export function requirePortfolioAdmin(claims, config) {
  if (!isPortfolioAdmin(claims, config)) {
    throw new ClaimsError(
      "PORTFOLIO_ADMIN_REQUIRED",
      "The subject is not the portfolio administrator with the required admin group.",
    );
  }
  return true;
}

export function assertAuthTime(claims, maxAgeSeconds, { nowSeconds = Math.floor(Date.now() / 1000), clockSkewSeconds = 60 } = {}) {
  if (maxAgeSeconds === undefined || maxAgeSeconds === null) return true;
  if (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new ClaimsError("INVALID_MAX_AGE", "maxAgeSeconds must be a non-negative number.");
  }
  if (!claims || claims.authTime === null) {
    throw new ClaimsError("MISSING_AUTH_TIME", "Fresh authentication was requested but auth_time is absent.");
  }
  const age = nowSeconds - claims.authTime;
  if (age > maxAgeSeconds + clockSkewSeconds) {
    throw new ClaimsError("STALE_AUTHENTICATION", "The authentication is older than the allowed max age.");
  }
  return true;
}
