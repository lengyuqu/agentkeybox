import { createHash } from "node:crypto";

import { runNativeHelper } from "./native-helper";
import { AkbError } from "./protocol";
import { requireActiveScreen } from "./screen";

export function isSessionKey(key: string): boolean {
  return /^[A-Za-z0-9+/]{86}==$/.test(key);
}

/** The session key is passed through a private pipe only. */
export async function storedSession(
  dir: string,
  operation: "read" | "save" | "remove",
  key?: string,
): Promise<string | undefined> {
  const account = createHash("sha256").update(dir).digest("hex");
  const { status, stdout } = await runNativeHelper([operation, account], key);
  if (operation === "read" && status === 44) {
    return undefined;
  }
  if (status === 4 || status === 5) {
    requireActiveScreen(status === 4 ? "locked" : "unavailable");
  }
  if (status !== 0 || (operation === "read" && !isSessionKey(stdout))) {
    const windows = process.platform === "win32";
    throw new AkbError(
      windows ? "CREDENTIAL_STORE_UNAVAILABLE" : "KEYCHAIN_UNAVAILABLE",
      windows
        ? "AKB could not access its session in Windows Credential Manager."
        : "AKB could not access its session in macOS Keychain.",
      4,
    );
  }
  return operation === "read" ? stdout : undefined;
}
