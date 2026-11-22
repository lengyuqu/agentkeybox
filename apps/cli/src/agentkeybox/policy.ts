import * as fs from "node:fs";
import * as path from "node:path";

import { AkbError } from "./protocol";

export interface SessionPolicy {
  idle_ms: number | null;
  max_ms: number | null;
}
export const defaultPolicy: SessionPolicy =
  process.platform === "darwin"
    ? { idle_ms: null, max_ms: null }
    : { idle_ms: 1_800_000, max_ms: 43_200_000 };

/** Windows and macOS keep a session until the desktop locks, unless the user sets a limit. */
export const noSessionLimits: SessionPolicy = { idle_ms: null, max_ms: null };

export function parseDuration(value: string): number | null {
  if (value === "never") {
    return null;
  }
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(value);
  const units: Record<string, number> = { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 };
  const result = match && Number(match[1]) * units[match[2]];
  if (!Number.isSafeInteger(result) || result <= 0) {
    throw new AkbError(
      "INVALID_DURATION",
      "Use never or a positive duration such as 30m or 12h.",
      2,
    );
  }
  return result;
}

export function loadPolicy(dir: string, fallback = defaultPolicy): SessionPolicy {
  const file = path.join(dir, "session-policy.json");
  if (!fs.existsSync(file)) {
    return { ...fallback };
  }
  let value: SessionPolicy;
  try {
    value = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new AkbError("INVALID_POLICY", "Session policy file is invalid.", 2);
  }
  if (
    !value ||
    ![value.idle_ms, value.max_ms].every((v) => v === null || (Number.isSafeInteger(v) && v > 0))
  ) {
    throw new AkbError(
      "INVALID_POLICY",
      "Session policy values must be null or positive milliseconds.",
      2,
    );
  }
  return { idle_ms: value.idle_ms, max_ms: value.max_ms };
}

export function savePolicy(dir: string, policy: SessionPolicy) {
  const temp = path.join(dir, `.session-policy-${process.pid}.tmp`);
  try {
    fs.writeFileSync(temp, JSON.stringify(policy) + "\n", { mode: 0o600, flag: "wx" });
    fs.renameSync(temp, path.join(dir, "session-policy.json"));
  } finally {
    fs.rmSync(temp, { force: true });
  }
}

export function deadline(
  unlockedAt: number,
  accessedAt: number,
  policy: SessionPolicy,
): number | null {
  if (!unlockedAt) {
    return null;
  }
  const dates = [
    policy.idle_ms === null ? Infinity : accessedAt + policy.idle_ms,
    policy.max_ms === null ? Infinity : unlockedAt + policy.max_ms,
  ];
  const value = Math.min(...dates);
  return Number.isFinite(value) ? value : null;
}
