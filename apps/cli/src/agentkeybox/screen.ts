import { execFile } from "node:child_process";

import { runNativeHelper } from "./native-helper";
import { AkbError } from "./protocol";

export type ScreenState = "unlocked" | "locked" | "unavailable" | "not_applicable";

function readSystemFile(executable: string, args: string[], input?: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      executable,
      args,
      // The daemon's environment can contain BW_SESSION. System probes need none of it.
      { env: {}, encoding: "buffer", timeout: 2000, maxBuffer: 2 * 1024 * 1024 },
      (error, stdout) => (error ? reject(error) : resolve(stdout)),
    );
    child.stdin?.on("error", reject);
    child.stdin?.end(input);
  });
}

/** IOConsoleUsers describes the active physical console even outside a GUI process. */
export function consoleScreenState(sessions: unknown, uid: number): ScreenState {
  if (
    !Array.isArray(sessions) ||
    sessions.some((session) => !session || typeof session !== "object")
  ) {
    return "unavailable";
  }
  const active = sessions.filter((session) => session.kCGSSessionOnConsoleKey === true);
  if (active.length === 0) {
    return "locked";
  }
  if (active.length !== 1) {
    return "unavailable";
  }
  const session = active[0];
  if (session.kCGSSessionUserIDKey !== uid || session.kCGSessionLoginDoneKey !== true) {
    return "locked";
  }

  // macOS omits this field in an unlocked console session on some versions.
  const locked = session.CGSSessionScreenIsLocked;
  if (locked === true) {
    return "locked";
  }
  return locked === undefined || locked === false ? "unlocked" : "unavailable";
}

export async function screenState(): Promise<ScreenState> {
  if (process.platform === "win32") {
    const { status } = await runNativeHelper(["screen"]);
    return status === 0 ? "unlocked" : status === 4 ? "locked" : "unavailable";
  }
  if (process.platform !== "darwin") {
    return "not_applicable";
  }
  try {
    const registry = await readSystemFile("/usr/sbin/ioreg", ["-a", "-r", "-n", "Root", "-d", "1"]);
    const sessions = await readSystemFile(
      "/usr/bin/plutil",
      ["-extract", "0.IOConsoleUsers", "json", "-o", "-", "-"],
      registry,
    );
    return consoleScreenState(JSON.parse(sessions.toString("utf8")), process.getuid());
  } catch {
    return "unavailable";
  }
}

export function requireActiveScreen(state: ScreenState): void {
  if (state === "locked") {
    throw new AkbError("SCREEN_LOCKED", "Unlock the desktop session to use AgentKeybox.", 4);
  }
  if (state === "unavailable") {
    throw new AkbError(
      "SCREEN_STATE_UNAVAILABLE",
      "AgentKeybox could not verify an active desktop session.",
      4,
    );
  }
}
