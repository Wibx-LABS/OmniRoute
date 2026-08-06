import test from "node:test";
import assert from "node:assert/strict";

/**
 * Wibx-LABS fork hardening: encrypt() must not silently store plaintext when
 * STORAGE_ENCRYPTION_KEY is unset. See security-audit-OmniRoute-2026-08-06.md,
 * finding "[HIGH] Provider credentials are stored in plaintext by default".
 *
 * The module caches the derived key in a closure, so each case re-imports with
 * a cache-busting query string rather than trying to reset module state.
 */
async function loadEncryption(suffix: string) {
  return import(`../../src/lib/db/encryption.ts?fail-closed-${suffix}`);
}

test("encrypt throws when STORAGE_ENCRYPTION_KEY is unset", async () => {
  delete process.env.STORAGE_ENCRYPTION_KEY;
  delete process.env.STORAGE_ENCRYPTION_OPTOUT;
  const { encrypt } = await loadEncryption("throws");

  assert.throws(() => encrypt("sk-ant-super-secret-value"), /STORAGE_ENCRYPTION_KEY is not set/);
});

test("encrypt passes through only with an explicit opt-out", async () => {
  delete process.env.STORAGE_ENCRYPTION_KEY;
  process.env.STORAGE_ENCRYPTION_OPTOUT = "1";
  const { encrypt } = await loadEncryption("optout");

  assert.equal(encrypt("sk-ant-super-secret-value"), "sk-ant-super-secret-value");
  delete process.env.STORAGE_ENCRYPTION_OPTOUT;
});

test("encrypt round-trips and never emits plaintext when a key is set", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "unit-test-key-not-a-real-secret";
  delete process.env.STORAGE_ENCRYPTION_OPTOUT;
  const { encrypt, decrypt } = await loadEncryption("roundtrip");

  const secret = "sk-ant-super-secret-value";
  const ciphertext = encrypt(secret);
  assert.ok(ciphertext.startsWith("enc:v1:"), `expected enc:v1: prefix, got ${ciphertext}`);
  assert.ok(!ciphertext.includes(secret), "ciphertext must not contain the plaintext");
  assert.equal(decrypt(ciphertext), secret);

  delete process.env.STORAGE_ENCRYPTION_KEY;
});
