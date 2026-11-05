"use strict";

const crypto = require("crypto");

/**
 * RFC 6238 TOTP helpers for The Book On. Secrets are 160-bit random values
 * encoded as unpadded base32. Codes are SHA-1 / 6 digits / 30 seconds with one
 * step of clock skew and replay protection.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;
const CLOCK_SKEW_STEPS = 1;
const MAX_ATTEMPTS = 5;

function base32Encode(bytes) {
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  return (bits.match(/.{1,5}/g) || [])
    .map((group) => ALPHABET[parseInt(group.padEnd(5, "0"), 2)])
    .join("");
}

function base32Decode(secret) {
  const normalized = String(secret).trim().toUpperCase().replace(/=+$/, "");
  if (!/^[A-Z2-7]{1,1024}$/.test(normalized)) throw new Error("Invalid base32 secret.");
  let bits = "";
  for (const character of normalized) {
    bits += ALPHABET.indexOf(character).toString(2).padStart(5, "0");
  }
  const bytes = [];
  const whole = bits.slice(0, bits.length - (bits.length % 8));
  for (let index = 0; index < whole.length; index += 8) {
    bytes.push(parseInt(whole.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpCode(secret, step, digits = DIGITS) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 10 ** digits).padStart(digits, "0");
}

function matchTotp(secret, code, lastUsedStep, now = Date.now()) {
  if (!new RegExp(`^\\d{${DIGITS}}$`).test(String(code))) return null;
  const currentStep = Math.floor(now / (STEP_SECONDS * 1000));
  for (let offset = -CLOCK_SKEW_STEPS; offset <= CLOCK_SKEW_STEPS; offset += 1) {
    const candidate = currentStep + offset;
    if (candidate <= Number(lastUsedStep ?? -1)) continue;
    const expected = Buffer.from(totpCode(secret, candidate));
    const supplied = Buffer.from(String(code));
    if (expected.length === supplied.length && crypto.timingSafeEqual(expected, supplied)) {
      return candidate;
    }
  }
  return null;
}

function buildOtpAuthUrl({ issuer, accountName, secret }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  const parameters = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS)
  });
  return `otpauth://totp/${label}?${parameters.toString()}`;
}

function encryptionKey(sessionSecret) {
  const explicit = (process.env.MFA_ENCRYPTION_KEY || "").trim();
  if (explicit) {
    if (!/^[a-f0-9]{64}$/i.test(explicit)) {
      throw new Error("MFA_ENCRYPTION_KEY must be 32 bytes encoded as 64 hexadecimal characters.");
    }
    return Buffer.from(explicit, "hex");
  }
  if (!sessionSecret || Buffer.byteLength(sessionSecret, "utf8") < 32) {
    throw new Error("MFA secret encryption requires MFA_ENCRYPTION_KEY or a session secret of at least 32 bytes.");
  }
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(sessionSecret, "utf8"),
      Buffer.from("thebookon-mfa", "utf8"),
      Buffer.from("mfa-secret-encryption-v1", "utf8"),
      32
    )
  );
}

function encryptSecret(value, sessionSecret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(sessionSecret), iv);
  const ciphertext = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return ["v1", iv.toString("hex"), cipher.getAuthTag().toString("hex"), ciphertext.toString("hex")].join(".");
}

function decryptSecret(value, sessionSecret) {
  const [version, ivHex, tagHex, ciphertextHex] = String(value).split(".");
  if (version !== "v1" || !ivHex || !tagHex || !ciphertextHex) {
    throw new Error("Stored MFA secret is malformed.");
  }
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(sessionSecret),
    Buffer.from(ivHex, "hex")
  );
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, "hex")),
    decipher.final()
  ]).toString("utf8");
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function newChallengeToken() {
  const token = crypto.randomBytes(32).toString("base64url");
  return { token, hash: sha256Hex(token) };
}

function normalizeBackupCode(value) {
  return String(value).trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function backupCodeHash(userId, value) {
  return sha256Hex(`tbo-mfa-backup:${userId}:${normalizeBackupCode(value)}`);
}

function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () =>
    crypto.randomBytes(8).toString("hex").toUpperCase().match(/.{4}/g).join("-")
  );
}

module.exports = {
  MAX_ATTEMPTS,
  base32Encode,
  base32Decode,
  buildOtpAuthUrl,
  decryptSecret,
  encryptSecret,
  generateBackupCodes,
  generateSecret,
  matchTotp,
  newChallengeToken,
  normalizeBackupCode,
  backupCodeHash,
  sha256Hex,
  totpCode
};
