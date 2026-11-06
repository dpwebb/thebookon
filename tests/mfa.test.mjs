import assert from "node:assert/strict";
import { describe, it } from "node:test";
import mfa from "../helpers/mfa.js";

const rfcSecret = mfa.base32Encode(Buffer.from("12345678901234567890", "ascii"));

describe("RFC 6238 TOTP", () => {
  it("matches the published SHA-1 vectors", () => {
    const vectors = [
      [59, "94287082"],
      [1111111109, "07081804"],
      [1111111111, "14050471"],
      [1234567890, "89005924"],
      [2000000000, "69279037"],
      [20000000000, "65353130"]
    ];
    for (const [seconds, expected] of vectors) {
      assert.equal(mfa.totpCode(rfcSecret, Math.floor(seconds / 30), 8), expected);
    }
  });

  it("rejects replayed codes and malformed input", () => {
    const secret = mfa.generateSecret();
    const now = 1_700_000_000_000;
    const code = mfa.totpCode(secret, Math.floor(now / 30_000));
    const step = mfa.matchTotp(secret, code, -1, now);
    assert.ok(step !== null);
    assert.equal(mfa.matchTotp(secret, code, step, now), null);
    assert.equal(mfa.matchTotp(secret, "12345", -1, now), null);
    assert.equal(mfa.matchTotp(secret, "abcdef", -1, now), null);
  });

  it("accepts one step of clock skew in either direction", () => {
    const secret = mfa.generateSecret();
    const now = 1_700_000_000_000;
    const current = Math.floor(now / 30_000);
    assert.equal(mfa.matchTotp(secret, mfa.totpCode(secret, current - 1), -1, now), current - 1);
    assert.equal(mfa.matchTotp(secret, mfa.totpCode(secret, current + 1), -1, now), current + 1);
    assert.equal(mfa.matchTotp(secret, mfa.totpCode(secret, current - 2), -1, now), null);
  });
});

describe("authenticator enrollment material", () => {
  it("builds an otpauth URI with interoperable parameters", () => {
    const url = mfa.buildOtpAuthUrl({
      issuer: "The Book On Publishing",
      accountName: "author@example.test",
      secret: rfcSecret
    });
    const parsed = new URL(url);
    assert.equal(parsed.protocol, "otpauth:");
    assert.equal(parsed.host, "totp");
    assert.equal(parsed.searchParams.get("secret"), rfcSecret);
    assert.equal(parsed.searchParams.get("algorithm"), "SHA1");
    assert.equal(parsed.searchParams.get("digits"), "6");
    assert.equal(parsed.searchParams.get("period"), "30");
  });
});

describe("MFA secret encryption at rest", () => {
  const sessionSecret = "s".repeat(40);

  it("round-trips and never stores plaintext", () => {
    const ciphertext = mfa.encryptSecret("JBSWY3DPEHPK3PXP", sessionSecret);
    assert.ok(!ciphertext.includes("JBSWY3DPEHPK3PXP"));
    assert.ok(ciphertext.startsWith("v1."));
    assert.equal(mfa.decryptSecret(ciphertext, sessionSecret), "JBSWY3DPEHPK3PXP");
  });

  it("rejects tampering and a different session secret", () => {
    const ciphertext = mfa.encryptSecret("JBSWY3DPEHPK3PXP", sessionSecret);
    const parts = ciphertext.split(".");
    const last = parts[3].slice(-1);
    const tampered = [
      parts[0],
      parts[1],
      parts[2],
      parts[3].slice(0, -1) + (last === "0" ? "1" : "0")
    ].join(".");
    assert.throws(() => mfa.decryptSecret(tampered, sessionSecret));
    assert.throws(() => mfa.decryptSecret(ciphertext, "t".repeat(40)));
  });
});

describe("backup codes", () => {
  it("generates unique shaped codes and hashes normalized values", () => {
    const codes = mfa.generateBackupCodes();
    assert.equal(codes.length, 10);
    assert.equal(new Set(codes).size, 10);
    for (const code of codes) assert.match(code, /^[A-F0-9]{4}(-[A-F0-9]{4}){3}$/);
    assert.equal(mfa.normalizeBackupCode(" abcd-ef01-2345-6789 "), "ABCDEF0123456789");
    assert.equal(
      mfa.backupCodeHash(7, "abcd-ef01-2345-6789"),
      mfa.backupCodeHash(7, "ABCD EF01 2345 6789")
    );
    assert.notEqual(mfa.backupCodeHash(7, codes[0]), mfa.backupCodeHash(8, codes[0]));
  });
});
