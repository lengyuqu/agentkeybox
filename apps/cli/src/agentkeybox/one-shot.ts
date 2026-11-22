import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";

import * as lockfile from "proper-lockfile";

import type { ServiceContainer } from "../service-container/service-container";

import { fileAudit } from "./audit";
import { runNativeHelper } from "./native-helper";
import { loadPolicy, noSessionLimits } from "./policy";
import { AkbError, Request, VAULT_ACCESS } from "./protocol";
import { requireActiveScreen, screenState } from "./screen";
import {
  removeSessionState,
  sessionExpired,
  startSessionState,
  touchSessionState,
} from "./session-state";
import { isSessionKey, storedSession } from "./session-store";
import { profileDirectory } from "./transport";

async function windowsProfileDirectory(dir: string): Promise<string> {
  const profiles = dirname(dir);
  const vault = join(dir, "bw");
  const { status } = await runNativeHelper([
    "check-profile",
    dirname(profiles),
    profiles,
    dir,
    vault,
    join(vault, "data.json"),
  ]);
  if (status === 4 || status === 5) {
    requireActiveScreen(status === 4 ? "locked" : "unavailable");
  }
  if (status !== 0) {
    throw new AkbError(
      "UNSAFE_DIRECTORY",
      "Use an AKB_HOME folder owned by your Windows user with private permissions.",
      7,
    );
  }
  return realpathSync.native(dir);
}

/** Run one command without a socket or a resident session process. */
export async function runForegroundCommand(profile: string, request: Request): Promise<unknown> {
  delete process.env.BW_SESSION;
  const initialScreen = await screenState();
  const operation = request.operation;
  if (operation === "status" && initialScreen !== "unlocked") {
    return {
      status: "locked",
      screen_state: initialScreen,
      lock_reason: initialScreen === "locked" ? "screen_locked" : "screen_state_unavailable",
    };
  }
  requireActiveScreen(initialScreen);
  const windows = process.platform === "win32";
  if (!windows) {
    process.umask(0o077);
  }
  const profileDir = profileDirectory(profile);
  const dir = windows ? await windowsProfileDirectory(profileDir) : profileDir;

  // Lowdb stores the whole profile in one file. Use the same lock as older AKB
  // services so parallel commands cannot overwrite each other or race a migration.
  let release: () => Promise<void>;
  try {
    release = await lockfile.lock(dir, {
      realpath: false,
      stale: 10_000,
      // A command ahead of us may be waiting on a vault sync over a slow link.
      retries: { retries: 300, minTimeout: 100, maxTimeout: 100 },
    });
  } catch {
    throw new AkbError(
      "PROFILE_BUSY",
      "Another AKB command or an older background service owns this profile.",
      8,
    );
  }

  let services: ServiceContainer | undefined;
  let expired = false;
  try {
    requireActiveScreen(await screenState());
    if (operation === "status" || VAULT_ACCESS.includes(operation)) {
      if (sessionExpired(dir, loadPolicy(dir, noSessionLimits))) {
        // The limit the user set has passed: forget the session, so the vault needs an unlock.
        await storedSession(dir, "remove");
        removeSessionState(dir);
        expired = true;
      } else {
        const session = await storedSession(dir, "read");
        if (session !== undefined) {
          process.env.BW_SESSION = session;
        }
      }
    } else if (operation === "lock" || operation === "logout") {
      await storedSession(dir, "remove");
      removeSessionState(dir);
    }
    process.env.BW_NOINTERACTION = "true";
    process.env.BW_QUIET = "true";
    delete process.env.BITWARDENCLI_DEBUG;

    const [{ ServiceContainer }, { Backend }] = await Promise.all([
      import("../service-container/service-container"),
      import("./backend"),
    ]);
    services = new ServiceContainer({ dataDirectory: join(dir, "bw") });
    for (const level of ["debug", "info", "warning", "error"] as const) {
      services.logService[level] = () => {};
    }
    requireActiveScreen(await screenState());
    await services.init({ connectToDesktop: false });
    const backend = new Backend(services, null, null);
    backend.setAudit(fileAudit(dir));
    const result = await backend.dispatch(request);

    if (operation === "login" || operation === "unlock") {
      const session = process.env.BW_SESSION;
      if (session === undefined || !isSessionKey(session)) {
        throw new AkbError(
          "SESSION_UNAVAILABLE",
          "Bitwarden did not establish a local session.",
          4,
        );
      }
      await storedSession(dir, "save", session);
      startSessionState(dir);
    } else if (VAULT_ACCESS.includes(operation)) {
      touchSessionState(dir);
    }
    if (expired && operation === "status" && result && typeof result === "object") {
      return { ...result, lock_reason: "session_expired" };
    }
    return result;
  } finally {
    delete process.env.BW_SESSION;
    try {
      services?.dispose();
    } finally {
      await release();
    }
  }
}
