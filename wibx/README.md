# Wibx-LABS deployment rules

This fork is run under a bounded policy: **🟢 API-key providers only**. Everything
here exists to keep that true after the person who decided it has stopped
looking.

Host wiring — which machine, which network, how it is reached — is deliberately
not in this repo.

## What decides your risk

Not the deployment. Not the network. **Which providers you connect.**

OmniRoute ships 90 executors in three classes, and the class decides both the
legal exposure and where the prompts go.

| Class | What it is | Ban risk | Prompt confidentiality |
|---|---|---|---|
| 🟢 **API key** | Documented endpoint, key you signed up for. Groq, Gemini, DeepSeek, Mistral, SiliconFlow, Cerebras, Cloudflare, Vertex, Kimi, GLM, OpenRouter | None — this is the supported use | Provider's published data policy |
| 🟡 **First-party subscription** | OAuth into a Claude / Codex / Copilot plan you pay for | **Real.** Requests carry a CLI user-agent and, with `CLI_COMPAT_*` on, reordered headers matching the official client signature | Your own account |
| 🔴 **Web session** | 31 `*-web` executors driving a logged-in browser session from DevTools cookies | **High.** TLS-fingerprint spoofing, anti-bot challenge solving, replayed thinking signatures. Several are labeled `Unofficial/Experimental` in their own source | Your own account, via a path the provider did not sanction |

Green is the whole approved surface, and a genuinely useful one — those free
tiers are real and documented. What it will not do is produce the README's
~1.53B tokens/month; that number needs amber and red.

**Amber and red are refused in code**
([#5](https://github.com/Wibx-LABS/OmniRoute/pull/5)), not left to nobody
clicking them. Connecting one fails at the point credentials are persisted, and
an already-stored connection cannot route. Amber has an escape hatch —
`OMNIROUTE_ALLOW_SUBSCRIPTION`, because the decision was "revisit later". Red has
none, because the decision was "never".

This matters most for whoever runs an instance that is not theirs to set policy
for: the ban lands on the account whose credentials were connected, so the
control belongs somewhere they cannot un-click it.

### Two risks, routinely conflated

**Account ban** is amber and red only, and lands on whichever account is
connected.

**Prompt confidentiality** applies to *every* free provider, green included.
Upstream ships nine keyless providers needing no credential at all, behind a
blocklist that is empty on a fresh install — so an unpatched build answers
`auto` on day one by sending prompts to a third party nobody configured. Some
are worse than a free API: `aihorde` dispatches to volunteer-run GPUs,
`felo-web` and `chipotle` are reverse-engineered public endpoints, `theoldllm`
mints tokens through an embedded browser.

Fixed in code — [#3](https://github.com/Wibx-LABS/OmniRoute/pull/3) inverts that
default, and only `OMNIROUTE_ALLOW_NOAUTH` opens one. Still decide explicitly
what may go to a free tier before pointing a real repository at this.

## Bringing it up

```bash
cp wibx/env.template                  .env     # fill the secrets, chmod 600
cp wibx/docker-compose.override.yml   .
docker compose -f docker-compose.prod.yml -f docker-compose.override.yml up -d --build
./wibx/verify.sh
```

**The override is not optional.** Upstream's prod compose has two defaults not
to inherit:

- **It targets `runner-cli`, not `runner-base`**, despite its own header comment
  describing the base flavor. `runner-cli` apt-installs `docker.io` and
  `docker-compose` into the container and globally npm-installs `@openai/codex`,
  `@anthropic-ai/claude-code`, `droid` and `openclaw@latest` — an unpinned tag
  re-resolved on every build. A gateway that routes API calls needs none of it.
  `runner-base` is the same runtime without it. **Never build `runner-web`.**

  One correction to a claim this document used to make: `runner-base` does *not*
  exclude Playwright. Next's standalone tracing pulls `playwright` and
  `playwright-core` (~25 MB) into every flavor, verified on a real image
  2026-08-12. What `runner-web` adds is the **browser binary** (~800 MB), and
  without it `browserType.launch()` throws — so a web-cookie provider still
  cannot drive a session. The protection is real, but it is the missing browser,
  not a missing library. `verify.sh` checks for the binary accordingly; testing
  for the module was a permanent false FAIL.
- **It publishes ports with no bind address**, i.e. `0.0.0.0` — dashboard, API
  and live-WS on every interface the host has. The override pins all three to
  loopback. Compose merges `ports` by default, so the override uses `!override`
  to replace the list rather than append to it.

Docker also contains the MITM stack: the root-CA install and `/etc/hosts`
rewrite can only affect the container, never a developer's host keychain. This
fork additionally requires authentication on those routes regardless of the
`requireLogin` setting.

## Build requirements — read before picking a host

Building this image is the expensive part, and it is easy to pick a host that
cannot do it. Two attempts on an 8 GiB laptop both failed:

| Attempt | Elapsed | Failure |
|---|---|---|
| 1 | 33 min | `npm error code ECONNRESET` during `npm ci` — network gave out under load |
| 2 | ~30 min | `ResourceExhausted: cannot allocate memory` on the same layer |

What the build actually wants:

- **`npm ci` plus a node-gyp rebuild of `better-sqlite3`**, compiled in parallel
  across every core. This is what exhausts memory, and it runs *before* any
  heap-ceiling environment variable applies.
- **`next build` with `--max-old-space-size=4096`**, hardcoded as
  `ARG OMNIROUTE_BUILD_MEMORY_MB=4096` in the builder stage, because the webpack
  production pass needs more than V8's ~2 GB default at this size (upstream
  #4076).

Treat **8 GiB of free RAM** as the floor for a build host, not the target.

**The build depends on GitHub's API.** The builder stage runs
`tls-client-node/scripts/postinstall.js` and hard-fails the whole build if the
native binary is missing — upstream's own error text names the cause: "GitHub
API fetch likely rate-limited or failed" (#7802). So a rebuild can fail for
reasons unrelated to the code or the network, which matters for unattended
rebuilds. It also means the TLS-impersonation library is a **mandatory build
dependency in every flavor** — green-only means it is never invoked, not that it
is absent from the tree.

## Hard rules

Security-critical. Not preferences.

- **`requireLogin` stays `true`.** Never `false`. `isAuthRequired()` returns
  `false` outright when it is off, and upstream's management-auth helper reads
  "not required" as "allow". This is a **dashboard setting, not an environment
  variable** — nothing in `.env` pins it, so it has to be confirmed in the UI
  after setup.
- **Set `INITIAL_PASSWORD`.** Not cosmetic: with no password, no OIDC and no
  `INITIAL_PASSWORD`, `isAuthRequired()` returns `false` for loopback requests
  until setup completes. Setting it closes that bootstrap window. The shipped
  default is literally `CHANGEME`.
- **Set `STORAGE_ENCRYPTION_KEY` before the first credential is added.** This
  fork's `encrypt()` fails closed if it is unset, so the rule enforces itself —
  do not reach for `STORAGE_ENCRYPTION_OPTOUT=1` to work around the error.
- **Set `JWT_SECRET` and `API_KEY_SECRET`.**
- **Do not enable MITM**, and do not set `INSPECTOR_TLS_INTERCEPT=true`.
- **Leave every `CLI_COMPAT_*` unset.** They are off by default. Upstream
  describes them as "reducing account flagging risk" — they exist to evade
  detection. Turning one on is a deliberate choice to impersonate a client.
- **Never connect a first-party account anything depends on.** If the amber
  class is ever enabled, use an account whose loss is survivable.
- **Never expose this to the public internet.** No tunnel, no funnel, no
  reverse proxy with a public hostname.

## Verifying

`wibx/verify.sh` asserts the rules above against a running container and exits
non-zero on any violation. **Run it after every deploy and after every sync
merge — not once.**

It checks image flavor (no Docker CLI, no Playwright, no globally-installed
coding agents), that no published port is bound to `0.0.0.0`, that
unauthenticated `/api/settings` returns 401/403 rather than 200, that all four
secrets are set and none is still `CHANGEME`, that no `CLI_COMPAT_*` or TLS
interception is enabled, and that the keyless-provider guard is present in the
deployed image with `OMNIROUTE_ALLOW_NOAUTH` unset. Section `[7]` does the same
for the amber/red guard and `OMNIROUTE_ALLOW_SUBSCRIPTION`.

One rule it cannot check, because it lives in the database rather than the
environment: that `requireLogin` is on. That stays a dashboard check.

## Sync

This fork tracks upstream release tags (`upstream_track: release` — upstream's
default branch rotates every release). The code is run, not just read, so treat
sync PRs as real upgrades: re-audit the diff before merging, and expect
conflicts in `src/lib/api/requireCliToolsAuth.ts`, `src/lib/db/encryption.ts`,
`src/shared/utils/noAuthProviders.ts`,
`src/sse/services/noAuthProviderSettings.ts`, and the dependency pins.

Resolve every one of them in favour of the fail-closed side.

Upstream is read-only: no commits, PRs, issues or advisories are ever sent
there.
