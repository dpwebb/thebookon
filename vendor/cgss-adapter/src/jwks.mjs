import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { normalizeClaims } from "./claims.mjs";

const ALGORITHMS = Object.freeze({
  RS256: { hash: "sha256", family: "rsa" },
  RS384: { hash: "sha384", family: "rsa" },
  RS512: { hash: "sha512", family: "rsa" },
  ES256: { hash: "sha256", family: "ec" },
  ES384: { hash: "sha384", family: "ec" },
});

export class JwtError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "JwtError";
    this.code = code;
  }
}

function decodeSegment(segment, name) {
  if (typeof segment !== "string" || segment.length === 0) {
    throw new JwtError("MALFORMED_JWT", `JWT ${name} segment is missing.`);
  }
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new JwtError("MALFORMED_JWT", `JWT ${name} segment is not valid JSON.`);
  }
}

function decodeSignature(segment) {
  if (typeof segment !== "string" || segment.length === 0) {
    throw new JwtError("MALFORMED_JWT", "JWT signature segment is missing.");
  }
  return Buffer.from(segment, "base64url");
}

function audienceMatches(actual, expected) {
  if (Array.isArray(actual)) return actual.includes(expected);
  return actual === expected;
}

export function createJwksCache({
  jwksUri,
  fetcher = fetch,
  ttlMs = 5 * 60_000,
  staleMs = 60 * 60_000,
  now = Date.now,
} = {}) {
  if (typeof jwksUri !== "string" || jwksUri.length === 0) {
    throw new JwtError("JWKS_URI_REQUIRED", "A JWKS URI is required.");
  }
  if (typeof fetcher !== "function") {
    throw new JwtError("INVALID_FETCHER", "The JWKS fetcher must be a function.");
  }

  let keys = new Map();
  let fetchedAt = 0;
  let inflight = null;

  async function load() {
    const response = await fetcher(jwksUri, {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    if (!response || !response.ok) {
      throw new JwtError("JWKS_FETCH_FAILED", `JWKS request failed with status ${response?.status ?? "unknown"}.`);
    }
    const body = await response.json();
    if (!body || !Array.isArray(body.keys)) {
      throw new JwtError("JWKS_INVALID", "JWKS response must contain a keys array.");
    }
    const next = new Map();
    for (const jwk of body.keys) {
      if (!jwk || typeof jwk.kid !== "string" || typeof jwk.kty !== "string") continue;
      if (jwk.use && jwk.use !== "sig") continue;
      if (jwk.alg && !ALGORITHMS[jwk.alg]) continue;
      next.set(jwk.kid, jwk);
    }
    if (next.size === 0) {
      throw new JwtError("JWKS_EMPTY", "JWKS response did not contain a usable signing key.");
    }
    keys = next;
    fetchedAt = now();
  }

  async function refresh() {
    if (!inflight) {
      inflight = load().finally(() => {
        inflight = null;
      });
    }
    return inflight;
  }

  async function get(kid) {
    if (typeof kid !== "string" || kid.length === 0) {
      throw new JwtError("MISSING_KEY_ID", "JWT header must contain a key id.");
    }
    const cached = keys.get(kid);
    const age = now() - fetchedAt;
    if (cached && age < ttlMs) return cached;

    try {
      await refresh();
    } catch (error) {
      if (cached && age < staleMs) return cached;
      throw error;
    }

    const refreshed = keys.get(kid);
    if (!refreshed) {
      throw new JwtError("UNKNOWN_KEY_ID", "JWT key id was not found in the JWKS.");
    }
    return refreshed;
  }

  return {
    get,
    refresh,
    get size() {
      return keys.size;
    },
  };
}

export async function verifyJwt(
  token,
  {
    keys,
    issuer,
    audience,
    algorithms = ["RS256", "ES256"],
    clockSkewSeconds = 60,
    nowSeconds = Math.floor(Date.now() / 1000),
  } = {},
) {
  if (!keys || typeof keys.get !== "function") {
    throw new JwtError("KEYS_REQUIRED", "A JWKS cache is required.");
  }
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new JwtError("ISSUER_REQUIRED", "An expected issuer is required.");
  }
  if (typeof audience !== "string" || audience.length === 0) {
    throw new JwtError("AUDIENCE_REQUIRED", "An expected audience is required.");
  }
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new JwtError("ALGORITHMS_REQUIRED", "At least one JWT algorithm is required.");
  }
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new JwtError("INVALID_CLOCK_SKEW", "Clock skew must be a non-negative number.");
  }

  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) {
    throw new JwtError("MALFORMED_JWT", "JWT must contain exactly three segments.");
  }

  const header = decodeSegment(parts[0], "header");
  const payload = decodeSegment(parts[1], "payload");

  if (typeof header.alg !== "string" || !algorithms.includes(header.alg)) {
    throw new JwtError("ALGORITHM_NOT_ALLOWED", "JWT algorithm is not allowed.");
  }
  const spec = ALGORITHMS[header.alg];
  if (!spec) {
    throw new JwtError("ALGORITHM_NOT_SUPPORTED", "JWT algorithm is not supported.");
  }
  const signature = decodeSignature(parts[2]);

  const jwk = await keys.get(header.kid);
  let publicKey;
  try {
    publicKey = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new JwtError("INVALID_PUBLIC_KEY", "JWKS key could not be converted to a public key.");
  }
  if (publicKey.asymmetricKeyType !== spec.family) {
    throw new JwtError("KEY_ALGORITHM_MISMATCH", "JWKS key type does not match the JWT algorithm.");
  }

  const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, "utf8");
  const signatureValid = header.alg.startsWith("ES")
    ? cryptoVerify(spec.hash, signingInput, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)
    : cryptoVerify(spec.hash, signingInput, publicKey, signature);
  if (!signatureValid) {
    throw new JwtError("INVALID_SIGNATURE", "JWT signature verification failed.");
  }

  if (payload.iss !== issuer) {
    throw new JwtError("INVALID_ISSUER", "JWT issuer does not match.");
  }
  if (!audienceMatches(payload.aud, audience)) {
    throw new JwtError("INVALID_AUDIENCE", "JWT audience does not match.");
  }
  if (!Number.isFinite(payload.exp) || payload.exp < nowSeconds - clockSkewSeconds) {
    throw new JwtError("TOKEN_EXPIRED", "JWT has expired.");
  }
  if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > nowSeconds + clockSkewSeconds)) {
    throw new JwtError("TOKEN_NOT_YET_VALID", "JWT is not valid yet.");
  }
  if (payload.iat !== undefined && (!Number.isFinite(payload.iat) || payload.iat > nowSeconds + clockSkewSeconds)) {
    throw new JwtError("INVALID_ISSUED_AT", "JWT issued-at time is invalid.");
  }

  return Object.freeze({
    header,
    payload,
    claims: normalizeClaims(payload),
  });
}

