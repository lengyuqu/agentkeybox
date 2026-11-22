import * as fs from "node:fs";
import * as path from "node:path";

import { deadline, SessionPolicy } from "./policy";

/**
 * When the unlocked session started and was last used. A foreground command has no resident
 * process to keep time, so the clock lives in a small file next to the profile. It holds two
 * timestamps and nothing secret; the session key itself stays in the system credential store.
 */
export interface SessionState {
  unlocked_at: number;
  accessed_at: number;
}

const FILE = "session-state.json";

export function loadSessionState(dir: string): SessionState | undefined {
  try {
    const value = JSON.parse(fs.readFileSync(path.join(dir, FILE), "utf8"));
    return Number.isSafeInteger(value?.unlocked_at) && Number.isSafeInteger(value?.accessed_at)
      ? { unlocked_at: value.unlocked_at, accessed_at: value.accessed_at }
      : undefined;
  } catch {
    return undefined;
  }
}

export function saveSessionState(dir: string, state: SessionState) {
  const temp = path.join(dir, `.session-state-${process.pid}.tmp`);
  try {
    fs.writeFileSync(temp, JSON.stringify(state) + "\n", { mode: 0o600, flag: "wx" });
    fs.renameSync(temp, path.join(dir, FILE));
  } finally {
    fs.rmSync(temp, { force: true });
  }
}

export function removeSessionState(dir: string) {
  fs.rmSync(path.join(dir, FILE), { force: true });
}

/** A session has just started: both clocks begin now. */
export function startSessionState(dir: string, now = Date.now()) {
  saveSessionState(dir, { unlocked_at: now, accessed_at: now });
}

/** The session was used: only the idle clock moves. A missing clock is not invented. */
export function touchSessionState(dir: string, now = Date.now()) {
  const state = loadSessionState(dir);
  if (state) {
    saveSessionState(dir, { ...state, accessed_at: now });
  }
}

/**
 * Whether the policy has ended the session. With no limits it never has. With a limit and no
 * readable clock, for example a session that began before the limit was set, it is treated as
 * ended: it is safer to ask for one more unlock than to guess a start time.
 */
export function sessionExpired(dir: string, policy: SessionPolicy, now = Date.now()): boolean {
  if (policy.idle_ms === null && policy.max_ms === null) {
    return false;
  }
  const state = loadSessionState(dir);
  if (!state) {
    return true;
  }
  const end = deadline(state.unlocked_at, state.accessed_at, policy);
  return end !== null && now >= end;
}
