import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ORIGINAL_STORAGE_KEY = process.env.STORAGE_ENCRYPTION_KEY;

async function importFresh(modulePath) {
  const url = pathToFileURL(path.resolve(modulePath)).href;
  return import(`${url}?test=${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

function encryptWithLegacyDynamicSalt(secret: string, plaintext: string): string {
  const key = scryptSync(secret, createHash("sha256").update(secret).digest().slice(0, 16), 32);
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return `enc:v1:${iv.toString("hex")}:${encrypted}:${authTag}`;
}

test.after(() => {
  if (ORIGINAL_STORAGE_KEY === undefined) {
    delete process.env.STORAGE_ENCRYPTION_KEY;
  } else {
    process.env.STORAGE_ENCRYPTION_KEY = ORIGINAL_STORAGE_KEY;
  }
});

// Wibx-LABS fork-local: upstream's version of this test asserted that encrypt()
// stayed in passthrough mode with no key configured. Our fail-closed patch
// deliberately inverted that — an operator who never set STORAGE_ENCRYPTION_KEY
// (the default) was silently storing every provider key and OAuth refresh token
// as plaintext. The test now pins the behaviour we actually want.
test("encrypt refuses to store plaintext when no storage key is configured", async () => {
  delete process.env.STORAGE_ENCRYPTION_KEY;
  delete process.env.STORAGE_ENCRYPTION_OPTOUT;
  const encryption = await importFresh("src/lib/db/encryption.ts");

  assert.equal(encryption.isEncryptionEnabled(), false);
  assert.throws(() => encryption.encrypt("plain-text"), /STORAGE_ENCRYPTION_KEY is not set/);

  // Falsy inputs return early, before the guard — there is no credential in an
  // empty string, and callers rely on the passthrough.
  assert.equal(encryption.encrypt(""), "");
  assert.equal(encryption.encrypt(null), null);
  assert.equal(encryption.encrypt(undefined), undefined);

  // decrypt() is deliberately untouched: databases written in the old passthrough
  // mode must stay readable, and reading is not what leaks.
  assert.equal(encryption.decrypt("plain-text"), "plain-text");
  assert.equal(encryption.decrypt(null), null);
  assert.equal(encryption.decrypt(undefined), undefined);

  assert.equal("validateEncryptionConfig" in encryption, false);
});

test("STORAGE_ENCRYPTION_OPTOUT=1 restores passthrough, loudly", async () => {
  delete process.env.STORAGE_ENCRYPTION_KEY;
  process.env.STORAGE_ENCRYPTION_OPTOUT = "1";
  const encryption = await importFresh("src/lib/db/encryption.ts");

  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (...args: unknown[]) => void warnings.push(args.join(" "));
  try {
    assert.equal(encryption.encrypt("plain-text"), "plain-text");
  } finally {
    console.warn = originalWarn;
    delete process.env.STORAGE_ENCRYPTION_OPTOUT;
  }

  assert.equal(warnings.length, 1, "the escape hatch must not be silent");
  assert.match(warnings[0], /STORAGE_ENCRYPTION_OPTOUT=1/);
});

test("encrypt/decrypt round-trip uses the expected serialized format", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "task-304-secret-a";
  const encryption = await importFresh("src/lib/db/encryption.ts");

  const encrypted = encryption.encrypt("hello world");
  const decrypted = encryption.decrypt(encrypted);

  assert.equal(encryption.isEncryptionEnabled(), true);
  assert.match(encrypted, /^enc:v1:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
  assert.equal(decrypted, "hello world");
  assert.equal(encryption.encrypt(encrypted), encrypted);
});

test("decrypt rejects a truncated GCM authentication tag (authTagLength pinned to 16 bytes)", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "task-304-secret-authtag";
  const encryption = await importFresh("src/lib/db/encryption.ts");

  const encrypted = encryption.encrypt("forge-me");
  assert.equal(encryption.decrypt(encrypted), "forge-me");

  // Truncate the trailing auth tag to 1 byte (2 hex chars). With authTagLength
  // pinned to 16 bytes on createDecipheriv, Node rejects the short tag instead
  // of verifying a weakened tag, so decrypt must fail closed (null).
  const [prefix, version, ivHex, encryptedHex] = encrypted.split(":");
  const truncated = `${prefix}:${version}:${ivHex}:${encryptedHex}:ab`;
  assert.equal(encryption.decrypt(truncated), null);
});

test("connection field helpers encrypt and decrypt all supported credential fields", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "task-304-secret-b";
  const encryption = await importFresh("src/lib/db/encryption.ts");

  const connection = {
    apiKey: "sk-123",
    accessToken: "access-123",
    refreshToken: "refresh-123",
    idToken: "id-123",
    untouched: "keep-me",
  };

  const encrypted = encryption.encryptConnectionFields({ ...connection });
  const decrypted = encryption.decryptConnectionFields(encrypted);

  assert.notEqual(encrypted.apiKey, connection.apiKey);
  assert.match(encrypted.apiKey, /^enc:v1:/);
  assert.match(encrypted.accessToken, /^enc:v1:/);
  assert.match(encrypted.refreshToken, /^enc:v1:/);
  assert.match(encrypted.idToken, /^enc:v1:/);
  assert.deepEqual(decrypted, connection);
});

test("decrypt returns null when the value is malformed or the key is wrong", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "task-304-secret-c";
  const firstModule = await importFresh("src/lib/db/encryption.ts");
  const encrypted = firstModule.encrypt("top-secret");

  process.env.STORAGE_ENCRYPTION_KEY = "task-304-secret-d";
  const secondModule = await importFresh("src/lib/db/encryption.ts");

  // When decryption fails with wrong key, return null (not encrypted ciphertext)
  // This prevents sending encrypted tokens to APIs
  assert.equal(secondModule.decrypt(encrypted), null);
  assert.equal(secondModule.decrypt("enc:v1:not-valid"), null);
});

test("legacy encryption migration parses ciphertext in canonical payload order", async () => {
  process.env.STORAGE_ENCRYPTION_KEY = "task-304-legacy-secret";
  const encryption = await importFresh("src/lib/db/encryption.ts");
  const legacyCiphertext = encryptWithLegacyDynamicSalt(
    process.env.STORAGE_ENCRYPTION_KEY,
    "legacy-provider-token"
  );

  assert.equal(encryption.decrypt(legacyCiphertext), null);

  const migrated = encryption.migrateLegacyEncryptedString(legacyCiphertext);

  assert.equal(migrated.updated, true);
  assert.match(migrated.value, /^enc:v1:/);
  assert.equal(encryption.decrypt(migrated.value), "legacy-provider-token");
});
