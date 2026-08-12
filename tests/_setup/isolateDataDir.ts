// Test-only DATA_DIR isolation.
//
// Loaded via `node --import ./tests/_setup/isolateDataDir.ts` from the test/mutation
// invocations (package.json test scripts, stryker.conf.json tap.nodeArgs, the
// quality.yml TIA step, and the CI test jobs) — NEVER from production. It MUST stay
// out of open-sse/utils/setupPolyfill.ts, which is also imported by production
// (bin/omniroute.mjs, proxyFetch.ts, proxyDispatcher.ts) where redirecting DATA_DIR
// would point the live SQLite DB at a throwaway temp dir.
//
// Why: node:test spawns a process per test file and Stryker spawns one per sandbox,
// but every process resolves DATA_DIR to the SAME default (~/.omniroute) when the env
// var is unset (see src/lib/dataPaths.ts::resolveDataDir). Concurrent processes then
// open the SAME on-disk storage.sqlite, causing cross-file state races: SQLite lock
// contention that hangs `test:unit` under high `--test-concurrency`, and the
// non-deterministic baseline that forced Stryker to `concurrency: 1`.
//
// Giving each process its own DATA_DIR under the OS temp dir removes the shared file,
// so concurrent test processes never collide. Tests that set DATA_DIR explicitly keep
// winning — this only fills in an isolated default when none was chosen.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// File logger worker threads can outlive a test's temporary DATA_DIR cleanup and then
// raise ENOENT/ENOTEMPTY after the test has already passed. Keep the global test default
// console-only; tests that cover file logging explicitly set APP_LOG_TO_FILE themselves.
process.env.APP_LOG_TO_FILE ||= "false";

if (!process.env.DATA_DIR) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omniroute-test-"));
  process.env.DATA_DIR = dir;

  // Best-effort cleanup so a long suite run does not leak hundreds of temp DBs.
  process.on("exit", () => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore — the OS reaps its temp dir eventually.
    }
  });
}

// System-trust guard: the suite must NEVER mutate the OS trust store. On a
// persistent self-hosted runner the cert-flow integration test installed a fake
// 105-byte PEM into /usr/local/share/ca-certificates and update-ca-certificates
// baked it into the bundle, breaking ALL system TLS on the VM (2026-07-05).
// installCert/uninstallCert/installTproxyCa/uninstallTproxyCa no-op under this.
process.env.OMNIROUTE_SKIP_SYSTEM_TRUST = "1";

// DNS-write guard: the suite must NEVER mutate /etc/hosts. Tests that exercise
// the real MITM path call addDNSEntries(); this env var makes it a no-op.
process.env.OMNIROUTE_SKIP_DNS_WRITE = "1";

// Wibx-LABS fork-local. Our encrypt() fails closed when STORAGE_ENCRYPTION_KEY is
// unset, which is right in production and wrong for a suite that stores hundreds
// of throwaway credentials with no key configured — it broke the API-key store,
// the Obsidian per-key config and the embed proxy tests, none of which are about
// encryption at all.
//
// Opting out rather than setting a key on purpose: the opt-out restores exactly
// the upstream passthrough behaviour these tests were written against, so nothing
// that passed before changes. Setting a real key would switch encryption ON for
// the whole suite and silently alter what every stored value looks like.
//
// The guard itself is covered by tests/unit/db-encryption.test.ts, which clears
// this variable before asserting the throw.
process.env.STORAGE_ENCRYPTION_OPTOUT = "1";

// Wibx-LABS fork-local. Our fork blocks every no-auth (keyless) provider by
// default — upstream ships them behind an empty blocklist, so a fresh install
// answered `auto` by sending prompts to third parties nobody configured.
//
// The suite is written against the upstream default: catalog, model-discovery
// and connection-selection tests all assert that keyless providers are visible
// and selectable (#2798, #3047, #3061, #3611, #5183). Allowing them here
// restores exactly that, so nothing that passed before changes, while production
// keeps denying by default.
//
// The guard itself stays covered by tests/unit/security/noauth-fail-closed.ts,
// which sets and clears this variable per case.
process.env.OMNIROUTE_ALLOW_NOAUTH = [
  "opencode", "oc",
  "duckduckgo-web", "ddgw",
  "felo-web", "felo",
  "theoldllm", "tllm",
  "chipotle", "pepper",
  "veoaifree-web", "veo-free",
  "mimocode", "mcode",
  "auggie", "aug",
  "aihorde", "horde",
].join(",");
