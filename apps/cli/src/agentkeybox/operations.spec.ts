import { Writable } from "node:stream";

import { AuditRecord } from "./audit";
import { runCommand, serialized } from "./operations";
import { AkbError } from "./protocol";

describe("serialized", () => {
  it("never overlaps two operations, and keeps going after a failure", async () => {
    const log: string[] = [];
    let active = 0;
    const slow = serialized(async (operation) => {
      active++;
      log.push(`start ${operation} (${active} active)`);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active--;
      if (operation === "bad") {
        throw new Error("failed");
      }
      return operation;
    });
    const results = await Promise.allSettled([slow("a"), slow("bad"), slow("c")]);
    expect(results.map((r) => r.status)).toEqual(["fulfilled", "rejected", "fulfilled"]);
    expect(log).toEqual(["start a (1 active)", "start bad (1 active)", "start c (1 active)"]);
  });
});

describe("runCommand", () => {
  const specs = [{ name: "TOKEN", ref: "ref:github/ci", field: "password" }];
  const node = process.execPath;

  it("resolves first, injects the values and records the run", async () => {
    const records: AuditRecord[] = [];
    const perform = jest.fn().mockResolvedValue({ values: { TOKEN: "abc123xyz" } });
    const out: string[] = [];
    const code = await runCommand(
      perform,
      (record) => records.push(record),
      () => {},
      [node, "-e", "console.log(process.env.TOKEN); process.exit(4)"],
      specs,
      {
        out: new Writable({
          write(chunk: Buffer, _e: string, done: () => void) {
            out.push(chunk.toString());
            done();
          },
        }),
        err: process.stderr,
      },
      { stdin: "ignore" },
    );
    expect(code).toBe(4);
    expect(perform).toHaveBeenCalledWith("resolve", { specs: JSON.stringify(specs) });
    expect(out.join("")).toBe("[REDACTED:TOKEN]\n");
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ op: "run", outcome: "ok", exit_code: 4 });
    expect(records[0].command).toMatch(/^node(\.exe)?$/i);
    expect(JSON.stringify(records)).not.toContain("abc123xyz");
  });

  it("starts nothing when a reference does not resolve", async () => {
    const perform = jest.fn().mockRejectedValue(new AkbError("NOT_FOUND", "Account not found.", 5));
    const audit = jest.fn();
    await expect(
      runCommand(perform, audit, () => {}, [node, "-e", "1"], specs),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(audit).not.toHaveBeenCalled();
  });

  it("records a command that could not start, and warns when the record fails", async () => {
    const perform = jest.fn().mockResolvedValue({ values: { TOKEN: "abc123xyz" } });
    const audit = jest.fn().mockImplementation(() => {
      throw new Error("disk full");
    });
    const warn = jest.fn();
    await expect(
      runCommand(perform, audit, warn, ["definitely-not-a-command-akb"], specs),
    ).rejects.toMatchObject({ code: "RUN_FAILED" });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "error", code: "RUN_FAILED" }),
    );
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("audit log"));
  });
});
