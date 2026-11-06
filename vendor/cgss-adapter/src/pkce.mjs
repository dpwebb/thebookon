import { createHash, randomBytes } from "node:crypto";

export function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function randomToken(bytes = 32) {
  return base64url(randomBytes(bytes));
}

export function pkceChallenge(verifier) {
  return base64url(createHash("sha256").update(verifier).digest());
}

export function isValidPkceVerifier(verifier) {
  return typeof verifier === "string" && /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

export function createPkcePair() {
  const verifier = randomToken(48);
  return {
    verifier,
    challenge: pkceChallenge(verifier),
    method: "S256",
  };
}
