/**
 * Wibx-LABS fork-local regression: the 🟢/🟡/🔴 policy is enforced in code, not
 * left to nobody clicking the wrong provider.
 *
 * 🔴 web-session executors are refused unconditionally. 🟡 first-party
 * subscriptions are refused unless OMNIROUTE_ALLOW_SUBSCRIPTION names them,
 * because the policy says "revisit later" rather than "never". 🟢 API-key
 * providers are untouched — the point of the whole exercise.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  OAUTH_PROVIDERS,
  WEB_COOKIE_PROVIDERS,
} from "../../../src/shared/constants/providers.ts";
import {
  isProviderBlockedByPolicy,
  providerRestrictedClass,
  providerPolicyReason,
} from "../../../src/shared/utils/providerClass.ts";

const ALLOW_ENV = "OMNIROUTE_ALLOW_SUBSCRIPTION";

// The approved green surface, per the bounded-run decision.
const GREEN = [
  "groq",
  "gemini",
  "deepseek",
  "mistral",
  "siliconflow",
  "cerebras",
  "vertex",
  "kimi",
  "openrouter",
];

afterEach(() => {
  delete process.env[ALLOW_ENV];
});

test("every web-session provider is classified red and blocked", () => {
  delete process.env[ALLOW_ENV];
  const ids = Object.keys(WEB_COOKIE_PROVIDERS);
  assert.ok(ids.length > 0, "web-cookie catalog should not be empty");

  for (const id of ids) {
    assert.equal(providerRestrictedClass(id), "red", `${id} should classify as red`);
    assert.equal(isProviderBlockedByPolicy(id), true, `${id} should be blocked`);
  }
});

test("red cannot be opened by the amber escape hatch", () => {
  const someRed = Object.keys(WEB_COOKIE_PROVIDERS)[0];
  process.env[ALLOW_ENV] = someRed;
  assert.equal(
    isProviderBlockedByPolicy(someRed),
    true,
    "policy says never for red — no environment variable overrides that"
  );
});

test("every OAuth subscription provider is classified amber and blocked by default", () => {
  delete process.env[ALLOW_ENV];
  const ids = Object.keys(OAUTH_PROVIDERS);
  assert.ok(ids.length > 0, "oauth catalog should not be empty");

  for (const id of ids) {
    assert.equal(providerRestrictedClass(id), "amber", `${id} should classify as amber`);
    assert.equal(isProviderBlockedByPolicy(id), true, `${id} should be blocked by default`);
  }
});

test("OMNIROUTE_ALLOW_SUBSCRIPTION opens only the named amber provider", () => {
  process.env[ALLOW_ENV] = "claude";
  assert.equal(isProviderBlockedByPolicy("claude"), false);
  assert.equal(isProviderBlockedByPolicy("codex"), true, "everything else stays blocked");
});

test("the amber allowlist matches in both directions, id and alias", () => {
  // Regression: comparing only the requested key against the allowlist meant
  // naming the alias did not open the canonical id.
  const amber = Object.values(OAUTH_PROVIDERS as Record<string, { id: string; alias?: string }>);
  const withAlias = amber.find((provider) => typeof provider.alias === "string");
  assert.ok(withAlias, "expected at least one amber provider to carry an alias");

  process.env[ALLOW_ENV] = withAlias.alias as string;
  assert.equal(isProviderBlockedByPolicy(withAlias.id), false, "alias in env opens the id");

  process.env[ALLOW_ENV] = withAlias.id;
  assert.equal(
    isProviderBlockedByPolicy(withAlias.alias as string),
    false,
    "id in env opens the alias"
  );
});

test("approved green providers are never blocked", () => {
  delete process.env[ALLOW_ENV];
  for (const id of GREEN) {
    assert.equal(providerRestrictedClass(id), null, `${id} must not be classified restricted`);
    assert.equal(isProviderBlockedByPolicy(id), false, `${id} must stay usable`);
  }
});

test("green Kimi is not confused with amber kimi-coding", () => {
  delete process.env[ALLOW_ENV];
  assert.equal(isProviderBlockedByPolicy("kimi"), false);
  assert.equal(isProviderBlockedByPolicy("kimi-coding"), true);
});

test("the refusal message names the class and the policy", () => {
  const red = providerPolicyReason(Object.keys(WEB_COOKIE_PROVIDERS)[0]);
  assert.match(red, /🔴|web-session/);
  assert.match(red, /never/);

  const amber = providerPolicyReason("claude");
  assert.match(amber, /🟡|first-party subscription/);
  assert.match(amber, new RegExp(ALLOW_ENV));
});
