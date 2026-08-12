import { getSettings } from "@/lib/localDb";
import { isProviderBlockedByIdOrAlias } from "@/shared/utils/noAuthProviders";
import * as log from "../utils/logger";

export async function isNoAuthProviderBlockedBySettings(providerId: string): Promise<boolean> {
  try {
    const settings = await getSettings();
    return isProviderBlockedByIdOrAlias(providerId, settings.blockedProviders);
  } catch (error) {
    log.warn(
      "AUTH",
      `Could not read blocked provider settings for ${providerId}: ${
        error instanceof Error ? error.message : String(error)
      } — treating it as blocked`
    );
    // Wibx-LABS fork-local: fail closed. Upstream returned false here, so an
    // unreadable settings DB let every no-auth provider through — the one moment
    // we have least reason to trust the gate is the moment it opened.
    return true;
  }
}
