/**
 * Wibx-LABS fork-local regression: no-auth (keyless) providers are blocked by
 * default, and only OMNIROUTE_ALLOW_NOAUTH opens one.
 *
 * Upstream ships `blockedProviders` as an optional, empty-by-default opt-out
 * list, so a fresh deployment routes prompts to every keyless provider on day
 * one. This asserts the inversion holds at the single chokepoint every consumer
 * goes through (normalizeBlockedProviderSet), including the alias forms.
 *
 * See security-audit-OmniRoute-2026-08-06.md.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { NOAUTH_PROVIDERS } from "../../../src/shared/constants/providers.ts";
import {
  isProviderBlockedByIdOrAlias,
  normalizeBlockedProviderSet,
  partitionNoAuthEntriesByBlocked,
} from "../../../src/shared/utils/noAuthProviders.ts";

const ALLOW_ENV = "OMNIROUTE_ALLOW_NOAUTH";
const noAuthEntries = Object.values(NOAUTH_PROVIDERS) as Array<{ id: string; alias?: string }>;

afterEach(() => {
  delete process.env[ALLOW_ENV];
});

test("every no-auth provider id and alias is blocked with no settings at all", () => {
  delete process.env[ALLOW_ENV];
  const blocked = normalizeBlockedProviderSet(undefined);

  assert.ok(noAuthEntries.length > 0, "provider catalog should not be empty");
  for (const provider of noAuthEntries) {
    assert.ok(blocked.has(provider.id), `${provider.id} should be blocked by default`);
    if (typeof provider.alias === "string") {
      assert.ok(blocked.has(provider.alias), `alias ${provider.alias} should be blocked by default`);
    }
  }
});

test("an explicitly empty blocklist does not re-open them", () => {
  delete process.env[ALLOW_ENV];
  // The dashboard writes back a concrete array once settings are saved; a
  // DB-seeded default would be erased by exactly this.
  const blocked = normalizeBlockedProviderSet([]);
  assert.ok(blocked.has("opencode"));
  assert.ok(blocked.has("felo-web"));
  assert.ok(blocked.has("aihorde"));
});

test("isProviderBlockedByIdOrAlias blocks by id and by alias", () => {
  delete process.env[ALLOW_ENV];
  assert.equal(isProviderBlockedByIdOrAlias("opencode", []), true);
  assert.equal(isProviderBlockedByIdOrAlias("oc", []), true);
  assert.equal(isProviderBlockedByIdOrAlias("felo-web", undefined), true);
});

test("OMNIROUTE_ALLOW_NOAUTH opens only the named provider", () => {
  process.env[ALLOW_ENV] = "opencode";
  const blocked = normalizeBlockedProviderSet([]);

  assert.equal(blocked.has("opencode"), false, "explicitly allowed id stays open");
  assert.equal(blocked.has("oc"), false, "its alias stays open too");
  assert.equal(blocked.has("felo-web"), true, "everything else stays blocked");
});

test("the allowlist accepts aliases and tolerates whitespace", () => {
  process.env[ALLOW_ENV] = " oc , felo ";
  const blocked = normalizeBlockedProviderSet([]);

  assert.equal(blocked.has("opencode"), false);
  assert.equal(blocked.has("felo-web"), false);
  assert.equal(blocked.has("aihorde"), true);
});

test("operator entries in blockedProviders are preserved, not replaced", () => {
  process.env[ALLOW_ENV] = "opencode";
  const blocked = normalizeBlockedProviderSet(["some-api-key-provider"]);

  assert.ok(blocked.has("some-api-key-provider"), "explicit blocks survive the merge");
  assert.equal(blocked.has("opencode"), false);
});

test("the dashboard partitions every no-auth entry as blocked by default", () => {
  delete process.env[ALLOW_ENV];
  const entries = noAuthEntries.map((provider) => ({
    providerId: provider.id,
    provider: { alias: provider.alias },
  }));

  const { visible, blocked } = partitionNoAuthEntriesByBlocked(entries, []);
  assert.equal(visible.length, 0, "nothing keyless is offered as available");
  assert.equal(blocked.length, entries.length, "they stay listed as Disabled, not hidden");
});
