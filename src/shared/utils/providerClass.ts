/**
 * Wibx-LABS fork-local: the 🟢/🟡/🔴 provider policy, enforced in code.
 *
 * The bounded-run decision (2026-08-06) is green-only: 🟢 API-key providers are
 * the approved surface, 🟡 first-party subscriptions may be revisited later, 🔴
 * web-session executors never. Leaving that to "do not click those" is not a
 * control — the dashboard offers every provider upstream ships, and the account
 * that gets banned belongs to whoever connected it.
 *
 * The two classes map exactly onto two provider catalogs, so membership is the
 * test rather than a hand-maintained id list that upstream additions would slip
 * past:
 *
 *   🟡 amber = OAUTH_PROVIDERS (23) — claude, codex, github/copilot, cursor,
 *      zed, windsurf, amazon-q, kimi-coding… OAuth into a subscription someone
 *      pays for. Requests carry a CLI user-agent; with CLI_COMPAT_* on, headers
 *      reordered to match the official client. Ban risk lands on that account.
 *
 *   🔴 red = WEB_COOKIE_PROVIDERS (31) — the *-web executors driving a logged-in
 *      browser session from DevTools cookies. TLS-fingerprint spoofing, anti-bot
 *      challenge solving, replayed thinking signatures.
 *
 * No approved green provider is in either map: Groq, Gemini, DeepSeek, Mistral,
 * SiliconFlow, Cerebras, Cloudflare, Vertex, Kimi, GLM and OpenRouter all live
 * in APIKEY_PROVIDERS. (Green "Kimi" is the API-key `kimi`, not the amber
 * `kimi-coding`.) `subscriptionRisk` is NOT used as the discriminator — upstream
 * sets it on only 17 of 23 amber and 21 of 31 red entries.
 *
 * Amber has an escape hatch because the policy says "revisit later"; red has
 * none, because the policy says never.
 */
import { OAUTH_PROVIDERS, WEB_COOKIE_PROVIDERS, resolveProviderId } from "@/shared/constants/providers";

export type ProviderClass = "amber" | "red";

const AMBER_ALLOW_ENV = "OMNIROUTE_ALLOW_SUBSCRIPTION";

function idAndAlias(map: Record<string, { id: string; alias?: string }>): Set<string> {
  const keys = new Set<string>();
  for (const provider of Object.values(map)) {
    keys.add(provider.id);
    if (typeof provider.alias === "string") keys.add(provider.alias);
  }
  return keys;
}

const AMBER_KEYS = idAndAlias(OAUTH_PROVIDERS as Record<string, { id: string; alias?: string }>);
const RED_KEYS = idAndAlias(WEB_COOKIE_PROVIDERS as Record<string, { id: string; alias?: string }>);

/**
 * Every key a provider answers to → its catalog entry, so the allowlist matches
 * in both directions: naming the alias opens the canonical id and vice versa.
 * Comparing only the requested key against the allowlist silently failed that.
 */
const AMBER_ENTRY_BY_KEY = new Map<string, { id: string; alias?: string }>();
for (const provider of Object.values(
  OAUTH_PROVIDERS as Record<string, { id: string; alias?: string }>
)) {
  AMBER_ENTRY_BY_KEY.set(provider.id, provider);
  if (typeof provider.alias === "string") AMBER_ENTRY_BY_KEY.set(provider.alias, provider);
}

/** Which restricted class a provider belongs to, or null for 🟢 and everything else. */
export function providerRestrictedClass(providerId: string): ProviderClass | null {
  const candidates = [providerId, resolveProviderId(providerId)];
  if (candidates.some((key) => RED_KEYS.has(key))) return "red";
  if (candidates.some((key) => AMBER_KEYS.has(key))) return "amber";
  return null;
}

/**
 * Read per call rather than cached at module load, so a restarted worker and the
 * tests observe the current environment.
 */
function amberExplicitlyAllowed(providerId: string): boolean {
  const allowed = new Set(
    (process.env[AMBER_ALLOW_ENV] ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
  );
  if (allowed.size === 0) return false;

  const entry =
    AMBER_ENTRY_BY_KEY.get(providerId) ?? AMBER_ENTRY_BY_KEY.get(resolveProviderId(providerId));
  if (entry === undefined) return false;

  return allowed.has(entry.id) || (typeof entry.alias === "string" && allowed.has(entry.alias));
}

/** True when policy forbids this provider being connected or routed to. */
export function isProviderBlockedByPolicy(providerId: string): boolean {
  const restrictedClass = providerRestrictedClass(providerId);
  if (restrictedClass === null) return false;
  if (restrictedClass === "red") return true;
  return !amberExplicitlyAllowed(providerId);
}

/** Operator-facing reason, used as the thrown message on the creation path. */
export function providerPolicyReason(providerId: string): string {
  const restrictedClass = providerRestrictedClass(providerId);
  if (restrictedClass === "red") {
    return `Provider "${providerId}" is a web-session executor (🔴). Wibx-LABS policy: never enabled. It drives a logged-in browser session with TLS-fingerprint spoofing and anti-bot evasion, and the ban lands on the account whose cookies you paste.`;
  }
  if (restrictedClass === "amber") {
    return `Provider "${providerId}" is a first-party subscription (🟡). Wibx-LABS policy: green-only — API-key providers. Amber impersonates an official CLI, so the ban lands on the subscription account. If this was decided otherwise, set ${AMBER_ALLOW_ENV}.`;
  }
  return `Provider "${providerId}" is not blocked by policy.`;
}
