const { createHmac } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

async function main() {
  const [id, verified, ...extra] = process.argv.slice(2);
  if (!/^ms_[a-z0-9]+_[a-f0-9]{10}$/.test(id || "") ||
      verified !== "--verified-pre-agreement" || extra.length) {
    throw new Error("Usage: node scripts/editorial-withdrawal.cjs <reference> --verified-pre-agreement");
  }
  const data = process.env.DATA_DIR || join(__dirname, "..", "data");
  const secret = process.env.SESSION_SECRET || readFileSync(join(data, "session-secret.txt"), "utf8").trim();
  const key = createHmac("sha256", secret).update("thebookon:editorial-withdrawal:v1").digest("base64url");
  const response = await fetch("http://127.0.0.1:" + (process.env.PORT || 3000) + "/internal/editorial/withdrawal", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Editorial-Key": key },
    body: JSON.stringify({ id, preAgreementVerified: true }),
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error("Editorial action returned HTTP " + response.status);
  console.log(await response.text());
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
