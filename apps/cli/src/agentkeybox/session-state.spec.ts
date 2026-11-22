import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { noSessionLimits, SessionPolicy } from "./policy";
import {
  loadSessionState,
  removeSessionState,
  sessionExpired,
  startSessionState,
  touchSessionState,
} from "./session-state";

const MINUTE = 60_000;
/** A real start time: the clock treats 0 as "never unlocked". */
const T0 = 1_700_000_000_000;

describe("session state", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "akb-state-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("starts both clocks at once, and use only moves the idle one", () => {
    startSessionState(dir, 1000);
    expect(loadSessionState(dir)).toEqual({ unlocked_at: 1000, accessed_at: 1000 });
    touchSessionState(dir, 5000);
    expect(loadSessionState(dir)).toEqual({ unlocked_at: 1000, accessed_at: 5000 });
  });

  it("does not invent a start time when there is none", () => {
    touchSessionState(dir, 5000);
    expect(loadSessionState(dir)).toBeUndefined();
    expect(readdirSync(dir)).toEqual([]);
  });

  it("holds nothing but two timestamps", () => {
    startSessionState(dir, 1000);
    expect(Object.keys(JSON.parse(readFileSync(join(dir, "session-state.json"), "utf8")))).toEqual([
      "unlocked_at",
      "accessed_at",
    ]);
    expect(readdirSync(dir)).toEqual(["session-state.json"]);
  });

  it("forgets the clock on request, and treats a damaged file as no clock", () => {
    startSessionState(dir, 1000);
    removeSessionState(dir);
    expect(loadSessionState(dir)).toBeUndefined();
    for (const bad of ["not json", "{}", '{"unlocked_at":"1","accessed_at":2}', "null"]) {
      writeFileSync(join(dir, "session-state.json"), bad);
      expect(loadSessionState(dir)).toBeUndefined();
    }
  });
});

describe("sessionExpired", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "akb-state-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("never ends a session that has no limits, with or without a clock", () => {
    expect(sessionExpired(dir, noSessionLimits, T0 + 10 ** 12)).toBe(false);
    startSessionState(dir, T0);
    expect(sessionExpired(dir, noSessionLimits, T0 + 10 ** 12)).toBe(false);
  });

  it("ends an idle session when the idle limit passes, and use extends it", () => {
    const policy: SessionPolicy = { idle_ms: 30 * MINUTE, max_ms: null };
    startSessionState(dir, T0);
    expect(sessionExpired(dir, policy, T0 + 29 * MINUTE)).toBe(false);
    expect(sessionExpired(dir, policy, T0 + 30 * MINUTE)).toBe(true);
    touchSessionState(dir, T0 + 29 * MINUTE);
    expect(sessionExpired(dir, policy, T0 + 58 * MINUTE)).toBe(false);
    expect(sessionExpired(dir, policy, T0 + 59 * MINUTE)).toBe(true);
  });

  it("ends an old session at the maximum however much it is used", () => {
    const policy: SessionPolicy = { idle_ms: null, max_ms: 60 * MINUTE };
    startSessionState(dir, T0);
    touchSessionState(dir, T0 + 59 * MINUTE);
    expect(sessionExpired(dir, policy, T0 + 59 * MINUTE)).toBe(false);
    expect(sessionExpired(dir, policy, T0 + 60 * MINUTE)).toBe(true);
  });

  it("uses whichever limit comes first", () => {
    const policy: SessionPolicy = { idle_ms: 10 * MINUTE, max_ms: 60 * MINUTE };
    startSessionState(dir, T0);
    touchSessionState(dir, T0 + 55 * MINUTE);
    expect(sessionExpired(dir, policy, T0 + 59 * MINUTE)).toBe(false);
    expect(sessionExpired(dir, policy, T0 + 60 * MINUTE)).toBe(true);
  });

  it("asks for another unlock when a limit is set but no clock exists", () => {
    expect(sessionExpired(dir, { idle_ms: MINUTE, max_ms: null }, T0)).toBe(true);
    expect(sessionExpired(dir, { idle_ms: null, max_ms: MINUTE }, T0)).toBe(true);
  });
});
