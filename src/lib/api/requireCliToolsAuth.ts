import { requireManagementAuth } from "@/lib/api/requireManagementAuth";

type RequireCliToolsAuthOptions = {
  /**
   * Refuse to fall through to the unauthenticated path that
   * `requireManagementAuth` takes when `isAuthRequired()` is false — i.e. when
   * the operator set `requireLogin: false`, or before setup completes.
   *
   * Set this on any route that can mutate the host: installing a trusted root
   * CA, writing /etc/hosts, or accepting a sudo password. Convenience defaults
   * are fine for reading tool status; they are not fine for privileged steps.
   */
  alwaysRequireAuth?: boolean;
};

export async function requireCliToolsAuth(
  request: Request,
  options: RequireCliToolsAuthOptions = {}
): Promise<Response | null> {
  return requireManagementAuth(request, options);
}
