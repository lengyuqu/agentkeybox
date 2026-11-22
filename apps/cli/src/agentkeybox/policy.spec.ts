import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { deadline, loadPolicy, parseDuration, savePolicy } from "./policy";

describe("session policy", () => {
  it("supports no expiry and independent idle/maximum limits", () => {
    expect(deadline(100, 200, { idle_ms: null, max_ms: null })).toBeNull();
    expect(deadline(100, 200, { idle_ms: 50, max_ms: null })).toBe(250);
    expect(deadline(100, 200, { idle_ms: null, max_ms: 50 })).toBe(150);
    expect(deadline(0, 0, { idle_ms: 50, max_ms: 50 })).toBeNull();
  });
  it("validates duration inputs", () => {
    expect(parseDuration("never")).toBeNull();
    expect(parseDuration("30m")).toBe(1800000);
    for (const value of ["0m", "Infinity", "-1s", "abc", "9999999999999999999999d"]) {
      expect(() => parseDuration(value)).toThrow();
    }
  });
  it("persists never as JSON null with private permissions", () => {
    const dir = mkdtempSync(join(tmpdir(), "akb-policy-"));
    try {
      savePolicy(dir, { idle_ms: null, max_ms: null });
      expect(loadPolicy(dir)).toEqual({ idle_ms: null, max_ms: null });
      expect(statSync(join(dir, "session-policy.json")).mode & 0o777).toBe(0o600);
      expect(readFileSync(join(dir, "session-policy.json"), "utf8")).toContain("null");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
