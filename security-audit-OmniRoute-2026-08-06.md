# Security Audit — OmniRoute

- **Target**: `diegosouzapw/OmniRoute` @ `v3.8.49` (`c9d4a45f1883d7daf150bbff631f3e83b41aa5b4`, 2026-07-29)
- **Date**: 2026-08-06
- **Method**: shallow read-only clone (`--depth 1`) into a scratchpad; `security-audit` skill scans
  00–05, 07, 08; then manual deep-dive. **Nothing was installed, built, or executed.** No
  `node_modules/` was created.
- **Scope caveat**: `--depth 1` means gitleaks' history pass had only one commit to scan. History
  was not audited for previously-committed secrets.
- **Intent audited for**: study / fork only. Not a deployment review.

---

## Headline answer: does it send your data anywhere?

**No evidence of exfiltration to the author or any third party.**

- `omniroute.online` appears in shipped code only as: a docs link (`src/app/docs/page.tsx:14`), the
  Electron `homepage`/support e-mail (`electron/package.json:8,11`), and a `connect-src` entry in
  the Electron CSP (`electron/main.js:317`). It is **not** a request target in any server path.
- "Telemetry" is entirely local: `bin/cli/commands/telemetry.mjs` calls `/api/telemetry/summary` on
  **your own** instance. No PostHog, Sentry, Segment, Umami, Plausible, or any analytics SDK is
  present in the dependency tree.
- Every outbound hostname in `src/`, `open-sse/`, `bin/`, `electron/`, `@omniroute/` is either an
  AI-provider API, `registry.npmjs.org` (version check / auto-update), `github.com`, a
  user-configured webhook sink (`hooks.slack.com`, `discord.com`), or a docs placeholder.
- Auto-update is not silent: `POST /api/system/version` requires authentication
  (`src/app/api/system/version/route.ts:96`) before it shells out to install a new version.

The risks below are all about **what OmniRoute does to your machine and your provider accounts if
you run it** — not about it calling home.

---

## Findings

### [HIGH] MITM stack installs a root CA and rewrites `/etc/hosts`; the gate is app-level auth that can be turned off

- **Category**: Code Patterns / Auto-Execution
- **File**:
  - `src/mitm/cert/install.ts:141-145,268,273,337-347` — `security add-trusted-cert -d -r trustRoot
    -k /Library/Keychains/System.keychain`, `certutil -addstore -f Root`, Linux trust anchors in
    `/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`,
    `/etc/pki/trust/anchors`, plus Firefox/NSS DBs via `certutil -d sql:$db -A -t "C,,"`.
  - `src/mitm/dns/provision.ts:142-144` — writes `/etc/hosts` entries redirecting provider domains
    to localhost.
  - `src/mitm/sudoGate.ts:11-31` — the sudo password arrives in the **HTTP request body** and is
    resolved against an in-process cache.
  - `src/app/api/settings/mitm/route.ts:44` (`sudoPassword` in the zod schema), `:163,189,245`.
- **Evidence**: the route's only gate is `requireManagementAuth(request)`, and that function
  returns `null` (allow) immediately when `isAuthRequired()` is false —
  `src/lib/api/requireManagementAuth.ts:41-42`. `isAuthRequired` returns `false` outright when
  `settings.requireLogin === false` (`src/shared/utils/apiAuth.ts:333`), and also for loopback
  requests before setup is complete (`:356`).
- **Risk**: a system-wide trusted root CA plus DNS redirection is complete TLS interception of the
  host. Any process that can reach the dashboard port while `requireLogin` is off can submit a sudo
  password and install it. The MITM private key living on disk means anyone who reads it can forge
  certificates for any site the host trusts — permanently, until the CA is manually removed.
- **Action**: do not enable MITM. Never run this bound beyond loopback, and never with
  `requireLogin: false`. If it is ever run, audit `/Library/Keychains/System.keychain` and
  `/etc/hosts` afterwards.

### [HIGH] Provider credentials are stored in plaintext by default

- **Category**: Secrets
- **File**: `src/lib/db/encryption.ts:1-8`
- **Evidence**: "If `STORAGE_ENCRYPTION_KEY` is not set, operates in passthrough mode (stores
  plaintext for development convenience)."
- **Risk**: the SQLite DB holds provider API keys and OAuth tokens for 13 providers (Claude, Codex,
  GitHub, Cursor, Gemini, Kimi, Cline, Windsurf, GitLab Duo…). Unset the env var — the default —
  and every one of them sits unencrypted in a file. Any local process, backup, or synced folder
  picks them up. AES-256-GCM is implemented and correct; it is simply off unless opted in.
- **Action**: if ever run, set `STORAGE_ENCRYPTION_KEY` **before** adding the first credential.

### [HIGH] Deliberate circumvention of provider protections — account-ban risk

- **Category**: Code Patterns
- **File**: `open-sse/executors/` (`chatgpt-web`, `grok-web`, `deepseek-web`, `muse-spark-web`,
  `duckduckgo-web`), `open-sse/config/defaultThinkingSignature.ts:3,6`
- **Evidence**: runtime deps `tls-client-node` and `wreq-js` exist to spoof browser TLS
  fingerprints (`scripts/build/postinstall.mjs` header names them for
  "chatgpt-web/claude-web/grok-web/lmarena/perplexity-web"). `defaultThinkingSignature.ts` hardcodes
  captured Anthropic and Gemini **extended-thinking signatures** and replays them as defaults.
  `open-sse/executors/duckduckgo-web/challenge.ts` implements anti-bot challenge solving. The
  project's own README flags 15 providers as ToS-problematic.
- **Risk**: routing your real Claude / ChatGPT / Gemini accounts through impersonated browser
  sessions with replayed signed reasoning blocks is exactly the pattern providers ban for. This is
  a risk to **your accounts**, not to your machine.
- **Action**: never point it at a first-party account you care about.

### [HIGH] 9 known-vulnerable dependencies, 6 high, some in runtime (not dev) deps

- **Category**: Dependencies
- **File**: `package-lock.json`
- **Evidence** (osv-scanner + `npm audit`): `ip-address@10.2.0` — three separate SSRF /
  trust-boundary bypasses (GHSA-mwp4-54f8-5fhr CVSS 7.7, GHSA-4xrf-jv44-h6hh, GHSA-22jq-vg5j-6vgg);
  `fast-uri@3.1.4` host confusion (GHSA-7p8r-x3mc-p8w7); `hono@4.12.31` CORS ReDoS. Dev-only:
  `brace-expansion`, `undici`, `socket.io-parser`, `protobufjs`, `tar`.
- **Risk**: `ip-address` is what SSRF guards use to decide whether a target is private. Three
  bypasses in the exact library a proxy relies on to not be turned into an internal-network relay
  is the worst possible placement for this class of bug in this class of app.
- **Action**: any future use must start from a dependency bump, not from this lock file.

### [MEDIUM] Unpinned GitHub Actions across the workflow suite

- **Category**: CI/CD
- **File**: `.github/workflows/docker-publish.yml`, `electron-release.yml`,
  `build-rinseaid-image.yml`, `opencode-provider-ci.yml`, `nightly-*.yml` (~40 occurrences)
- **Evidence**: `uses: actions/checkout@v7`, `docker/login-action@v4`, `anchore/sbom-action@v0` —
  mutable tags rather than commit SHAs. `build-rinseaid-image.yml` additionally requests broad
  write permissions.
- **Risk**: a compromised action tag reaches the workflows that publish the Docker image, the npm
  package, and the Electron binaries. This is upstream's CI, not ours — it matters because it is
  the integrity chain behind every artifact they ship.
- **Action**: informational for a fork. Our own `devkit/fork-gate` runs `zizmor` on workflow deltas.

### [LOW] Auto-update executes a shell script that installs from npm

- **Category**: Code Patterns
- **File**: `src/lib/system/autoUpdate.ts:261-299,386`
- **Evidence**: `buildNpmUpdateScript` produces `npm install -g omniroute@<latest>
  --include=optional --ignore-scripts --legacy-peer-deps`, launched via `spawn("sh", ["-lc",
  script])`.
- **Risk**: standard self-update. Mitigating factors: authenticated POST only, `--ignore-scripts`
  is set, version comes from the npm registry. Recorded because "app that can `npm install -g`
  itself" is worth knowing about.

### [INFO] Stray 1-byte file `AMIT` at repo root

Harmless, but it is committed junk at the tree root. Noted for hygiene.

### [INFO] `.fakebin-9475/npm` is a legitimate test fixture

A 4-line bash stub that fakes `npm view` / `npm install`. Referenced only from
`tests/unit/cli-update-shadow-install-9475.test.ts` and siblings. Not on `PATH`, not shipped.
Present on the default branch; absent at `v3.8.49`.

### [INFO] `RTK` and `Caveman` are independent reimplementations with no attribution

`open-sse/services/compression/engines/rtk/**` and `open-sse/services/compression/caveman.ts` are
original TypeScript, not copies of the Rust/shell upstreams we fork. There is no `NOTICE`,
`CREDITS`, or attribution line naming `rtk-ai/rtk` or `JuliusBrussee/caveman`;
`docs/compression/RTK_COMPRESSION.md` uses both names as if they were generic techniques. No
license violation is established by this audit — reimplementing an idea is not copying code — but
the naming is borrowed without credit.

### [LLM-ANALYSIS] Agent-instruction surface is clean

`AGENTS.md` (600 lines), `CLAUDE.md` (564), `GEMINI.md` (50), `.vscode/settings.json`, and ~30
`skills/*` directories were checked for instructions that would direct an agent to exfiltrate data,
run installers, or weaken permissions. **Nothing of the kind.** They are ordinary project
conventions; `.vscode/settings.json` contains only file-exclusion globs — no tasks, no terminal
autorun, no interpreter override. No git hooks are installed in the clone, and `.husky` hooks
(lint-staged + doc checks) only ever run via `npm run prepare`.

### [FALSE POSITIVES] resolved during deep-dive

- `03-code-patterns.sh` `[CRITICAL] EXFILTRATION` hits on `/etc/passwd`, `/etc/shadow`,
  `.aws/credentials`, `.npmrc` — **all** are path-traversal test fixtures, a VS Code context
  *sanitizer* (`src/app/api/v1/vscode/contextSanitizer.ts:50`), or comments. None reads those paths.
- `03` `[HIGH] OBFUSCATION` — ANSI/control-character strip regexes and provider doc IDs.
- `01` `[MEDIUM] .npmrc registry override` — the grep matched the word "registry" inside a comment.
  `.npmrc` sets only `legacy-peer-deps` and fetch-retry tuning. No custom registry, no auth token.
- `07` secret-pattern hits — every one is a masked test fixture (`"sk-a***"`) or an i18n string.
  gitleaks itself reported **zero** findings.

---

## SUMMARY

```
  CRITICAL: 0
  HIGH:     4
  MEDIUM:   1
  LOW:      1
  INFO:     4
  VERDICT:  DO NOT RUN
```

**Reading of the verdict.** `DO NOT RUN` is the rubric's mechanical output for "any HIGH". It is
the right label, and it is also not the same statement as "this is malware". Nothing in this audit
suggests hostile code, a backdoor, or data flowing to the author. All four HIGHs describe what
happens when you *operate* it: it can install a root CA, it stores credentials in plaintext unless
told otherwise, it deliberately evades provider defenses, and it ships a lock file with SSRF
bypasses in its own SSRF guard.

For the stated purpose — **read it, fork it, do not run it** — none of the four is triggered.
Reading the source is safe: no install hooks fire on clone, no editor autorun, no agent-instruction
traps.

---

## Fork hardening applied in `Wibx-LABS/OmniRoute`

Findings 1 and 2 are **fixed in this tree**. Both are offered upstream.

| Finding | Commit | Change |
| --- | --- | --- |
| 1 — MITM auth bypass | `fix(security): require auth on privileged MITM routes` | `requireCliToolsAuth` accepts `alwaysRequireAuth`; the 6 privileged call sites in `src/app/api/settings/mitm/route.ts` and `src/app/api/cli-tools/antigravity-mitm/route.ts` pass it, so `requireLogin: false` can no longer reach root-CA install, `/etc/hosts` writes, or sudo-password submission. The other 30 `cli-tools` routes are untouched. |
| 2 — plaintext credentials | `fix(security): fail closed when STORAGE_ENCRYPTION_KEY is unset` | `encrypt()` throws instead of returning plaintext. `STORAGE_ENCRYPTION_OPTOUT=1` is the explicit escape hatch. `decrypt()` is unchanged so existing passthrough-mode databases stay readable. Covered by `tests/unit/encryption-fail-closed.test.ts` (3 tests, passing). |

**Not fixed, by decision:**

- **Finding 3 (ToS circumvention)** is not a bug — TLS impersonation and replayed thinking
  signatures are how the free-provider pool works. Mitigation is operational: do not point this at
  a first-party account you care about.
- **Finding 4 (vulnerable deps)** is left to upstream's dependabot, which already has open PRs for
  these. A fork-local lock pin would conflict on every weekly sync for no benefit while we are not
  running the code. Re-checked at each sync by `devkit/fork-gate`.
