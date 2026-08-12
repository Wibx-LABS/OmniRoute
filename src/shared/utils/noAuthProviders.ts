import { NOAUTH_PROVIDERS, getProviderById } from "@/shared/constants/providers";

type ProviderWithAlias = { alias?: string };
type NoAuthProviderEntry = { id: string; alias?: string };

const noAuthProviderEntries = Object.values(NOAUTH_PROVIDERS) as NoAuthProviderEntry[];

/**
 * Wibx-LABS fork-local: providers the operator has deliberately opted into,
 * from OMNIROUTE_ALLOW_NOAUTH (comma-separated ids or aliases).
 *
 * Read per call rather than cached at module load so tests and a restarted
 * worker observe the current environment. The callers already hit the settings
 * DB, so a split on a short string is not the cost here.
 */
function explicitlyAllowedNoAuthProviders(): Set<string> {
  return new Set(
    (process.env.OMNIROUTE_ALLOW_NOAUTH ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
  );
}

/**
 * Wibx-LABS fork-local: no-auth providers are blocked by DEFAULT.
 *
 * Upstream models this as an opt-out blocklist that is empty on a fresh install
 * (`blockedProviders` is optional in settingsSchemas.ts), so a new deployment
 * routes to every keyless provider on day one — each of which sees the prompt,
 * and some of which are volunteer-run (aihorde) or reverse-engineered public
 * endpoints (felo-web, chipotle). Wibx-LABS runs green-only: API-key providers
 * are the approved surface.
 *
 * Inverting here rather than seeding the DB default is deliberate. A seeded
 * default survives only until the first settings write from the dashboard; an
 * environment-driven allowlist is immune to DB state, and denies keyless
 * providers that upstream adds later without anyone editing this file.
 *
 * Enforcement is server-side (sse/services/auth.ts, the models routes). The
 * dashboard renders blocked entries with a "Disabled" badge, so they stay
 * visible and restorable rather than silently vanishing.
 */
export function normalizeBlockedProviderSet(blockedProviders: unknown): Set<string> {
  const entries = blockedProviders instanceof Set ? Array.from(blockedProviders) : blockedProviders;
  const blockedProviderSet = new Set(
    Array.isArray(entries)
      ? entries.filter(
          (provider): provider is string => typeof provider === "string" && provider.length > 0
        )
      : []
  );

  const allowed = explicitlyAllowedNoAuthProviders();
  for (const provider of noAuthProviderEntries) {
    const alias = typeof provider.alias === "string" ? provider.alias : null;
    if (allowed.has(provider.id) || (alias !== null && allowed.has(alias))) continue;
    blockedProviderSet.add(provider.id);
    if (alias !== null) blockedProviderSet.add(alias);
  }

  return blockedProviderSet;
}

export function isProviderBlockedByIdOrAlias(
  providerId: string,
  blockedProviders: unknown
): boolean {
  const blockedProviderSet = normalizeBlockedProviderSet(blockedProviders);
  const provider = getProviderById(providerId) as ProviderWithAlias | undefined;
  return (
    blockedProviderSet.has(providerId) ||
    (typeof provider?.alias === "string" && blockedProviderSet.has(provider.alias))
  );
}

export function isNoAuthProviderKey(...keys: Array<string | null | undefined>): boolean {
  return noAuthProviderEntries.some((provider) =>
    keys.some((key) => key === provider.id || key === provider.alias)
  );
}

export function isNoAuthProviderBlocked(
  blockedProviders: unknown,
  ...keys: Array<string | null | undefined>
): boolean {
  const blockedProviderSet = normalizeBlockedProviderSet(blockedProviders);
  return noAuthProviderEntries.some(
    (provider) =>
      keys.some((key) => key === provider.id || key === provider.alias) &&
      (blockedProviderSet.has(provider.id) ||
        (typeof provider.alias === "string" && blockedProviderSet.has(provider.alias)))
  );
}

/**
 * Partition a list of no-auth provider entries into the ones that are visible
 * (not blocked) and the ones currently in `blockedProviders`, matched by either
 * the provider id or its alias. Blocked entries are RETURNED (in `blocked`),
 * never discarded — the dashboard surfaces them with a "Disabled" badge + an
 * Enable button instead of silently hiding them (#5166/#5183: a disabled no-auth
 * provider used to vanish from the All Providers page with no in-place restore).
 * Order within each bucket is preserved.
 */
export function partitionNoAuthEntriesByBlocked<
  T extends { providerId: string; provider: { alias?: string } },
>(entries: T[], blockedProviders: unknown): { visible: T[]; blocked: T[] } {
  const blockedProviderSet = normalizeBlockedProviderSet(blockedProviders);
  const visible: T[] = [];
  const blocked: T[] = [];
  for (const entry of entries) {
    const alias = typeof entry.provider.alias === "string" ? entry.provider.alias : null;
    const isBlocked =
      blockedProviderSet.has(entry.providerId) || (alias !== null && blockedProviderSet.has(alias));
    (isBlocked ? blocked : visible).push(entry);
  }
  return { visible, blocked };
}

export function isNoAuthRawProviderPrefix(providerId: string, prefix: string): boolean {
  const provider = noAuthProviderEntries.find((entry) => entry.id === providerId);
  return (
    typeof provider?.alias === "string" && provider.alias !== providerId && prefix === providerId
  );
}
