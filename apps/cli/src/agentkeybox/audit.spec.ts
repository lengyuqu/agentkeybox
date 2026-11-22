import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { of } from "rxjs";

import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";

import type { ServiceContainer } from "../service-container/service-container";

import {
  AUDIT_FILE,
  AuditRecord,
  auditCommand,
  auditEnabled,
  auditField,
  auditSelector,
  fileAudit,
} from "./audit";
import { Backend } from "./backend";

jest.mock("../auth/commands/lock.command", () => ({ LockCommand: jest.fn() }));
jest.mock("../auth/commands/login.command", () => ({ LoginCommand: jest.fn() }));
jest.mock("../key-management/commands/unlock.command", () => ({ UnlockCommand: jest.fn() }));
jest.mock("../platform/commands/config.command", () => ({ ConfigCommand: jest.fn() }));
jest.mock("@bitwarden/common/vault/models/domain/cipher", () => ({
  Cipher: jest.fn().mockImplementation((data) => ({ ...data })),
}));

describe("audit helpers", () => {
  it("keeps only text shaped like a reference", () => {
    expect(auditSelector("ref:github/ci")).toBe("ref:github/ci");
    expect(auditSelector("id:3f2a-44")).toBe("id:3f2a-44");
    for (const bad of [undefined, "", "github", "ref:", "ref:a\nb", `ref:${"x".repeat(201)}`]) {
      expect(auditSelector(bad)).toBeUndefined();
    }
  });

  it("keeps only known field names", () => {
    for (const ok of ["password", "totp", "custom:api key"]) {
      expect(auditField(ok)).toBe(ok);
    }
    for (const bad of [undefined, "name", "custom:", "custom:a\nb"]) {
      expect(auditField(bad)).toBeUndefined();
    }
  });

  it("reduces a command to its file name", () => {
    expect(auditCommand("/usr/bin/gh")).toBe("gh");
    expect(auditCommand("C:\\tools\\gh.exe")).toBe("gh.exe");
    expect(auditCommand("gh")).toBe("gh");
    expect(auditCommand("")).toBeUndefined();
  });

  it("can be switched off", () => {
    expect(auditEnabled({})).toBe(true);
    expect(auditEnabled({ AKB_AUDIT: "OFF" })).toBe(false);
  });
});

describe("fileAudit", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "akb-audit-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env.AKB_AUDIT;
  });

  it("appends one JSON line per record with a timestamp", () => {
    const audit = fileAudit(dir, () => new Date("2026-01-02T03:04:05.000Z"));
    audit({ op: "get", outcome: "ok", targets: [{ ref: "ref:a", id: "1", field: "password" }] });
    audit({ op: "get", outcome: "error", code: "NOT_FOUND" });
    const lines = readFileSync(join(dir, AUDIT_FILE), "utf8").trim().split("\n");
    expect(lines.map((line) => JSON.parse(line))).toEqual([
      {
        ts: "2026-01-02T03:04:05.000Z",
        op: "get",
        outcome: "ok",
        targets: [{ ref: "ref:a", id: "1", field: "password" }],
      },
      { ts: "2026-01-02T03:04:05.000Z", op: "get", outcome: "error", code: "NOT_FOUND" },
    ]);
  });

  it("writes nothing when switched off", () => {
    process.env.AKB_AUDIT = "off";
    fileAudit(dir)({ op: "get", outcome: "ok" });
    expect(existsSync(join(dir, AUDIT_FILE))).toBe(false);
  });

  it("keeps one older file once the log is large", () => {
    writeFileSync(join(dir, AUDIT_FILE), "x".repeat(5 * 1024 * 1024));
    fileAudit(dir)({ op: "set", outcome: "ok" });
    expect(readFileSync(join(dir, `${AUDIT_FILE}.1`), "utf8")).toHaveLength(5 * 1024 * 1024);
    expect(readFileSync(join(dir, AUDIT_FILE), "utf8").trim().split("\n")).toHaveLength(1);
  });
});

const SECRET = "s3cr3t-value-123";

function fixture() {
  const item = {
    id: "item-1",
    name: "GitHub",
    type: 1,
    login: { username: "me", password: SECRET },
    fields: [{ name: "agentkeybox.ref", value: "github/ci", type: 0 }],
  };
  const services = {
    authService: { getAuthStatus: jest.fn().mockResolvedValue(AuthenticationStatus.Unlocked) },
    accountService: { activeAccount$: of({ id: "test" }) },
    environmentService: { environment$: of({ getUrls: () => ({}) }) },
    syncService: { fullSync: jest.fn().mockResolvedValue(true), getLastSync: jest.fn() },
    stateProvider: { getUser: () => ({ state$: of({ [item.id]: { deletedDate: null } }) }) },
    cipherService: {
      decrypt: jest.fn().mockResolvedValue(item),
      softDeleteWithServer: jest.fn().mockResolvedValue(undefined),
    },
  } as unknown as ServiceContainer;
  const records: AuditRecord[] = [];
  const backend = new Backend(services, null, null, jest.fn().mockResolvedValue("unlocked"));
  backend.setAudit((record) => records.push(record));
  return { backend, records, item, services };
}

describe("Backend audit", () => {
  it("records a credential read without its value", async () => {
    const { backend, records } = fixture();
    await backend.dispatch({ operation: "get", args: { ref: "ref:github/ci", field: "password" } });
    expect(records).toEqual([
      {
        op: "get",
        outcome: "ok",
        targets: [{ ref: "ref:github/ci", id: "item-1", field: "password" }],
      },
    ]);
    expect(JSON.stringify(records)).not.toContain(SECRET);
  });

  it("records every secret a run asks for, by variable name", async () => {
    const { backend, records } = fixture();
    const specs = [{ name: "GH_TOKEN", ref: "ref:github/ci", field: "password" }];
    await backend.dispatch({ operation: "resolve", args: { specs: JSON.stringify(specs) } });
    expect(records[0]).toMatchObject({
      op: "resolve",
      outcome: "ok",
      targets: [{ env: "GH_TOKEN", ref: "ref:github/ci", id: "item-1", field: "password" }],
    });
    expect(JSON.stringify(records)).not.toContain(SECRET);
  });

  it("records a failed attempt with its error code", async () => {
    const { backend, records } = fixture();
    await expect(
      backend.dispatch({ operation: "get", args: { ref: "ref:missing", field: "password" } }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(records).toEqual([
      {
        op: "get",
        outcome: "error",
        code: "NOT_FOUND",
        targets: [{ ref: "ref:missing", field: "password" }],
      },
    ]);
  });

  it("moves an item to the trash, and records it", async () => {
    const { backend, records, services } = fixture();
    const reply = await backend.dispatch({ operation: "delete", args: { ref: "ref:github/ci" } });
    expect(services.cipherService.softDeleteWithServer).toHaveBeenCalledWith("item-1", "test");
    expect(reply).toMatchObject({ id: "item-1", ref: "github/ci", deleted: true });
    expect(JSON.stringify(reply)).not.toContain(SECRET);
    expect(records).toEqual([
      { op: "delete", outcome: "ok", targets: [{ ref: "ref:github/ci", id: "item-1" }] },
    ]);
  });

  it("deletes nothing that is read-only, missing or not exactly named", async () => {
    const { backend, records, services, item } = fixture();
    await expect(
      backend.dispatch({ operation: "delete", args: { ref: "github" } }),
    ).rejects.toMatchObject({ code: "INVALID_REFERENCE" });
    await expect(
      backend.dispatch({ operation: "delete", args: { ref: "ref:missing" } }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    Object.assign(item, { edit: false });
    await expect(
      backend.dispatch({ operation: "delete", args: { ref: "ref:github/ci" } }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    expect(services.cipherService.softDeleteWithServer).not.toHaveBeenCalled();
    expect(records.map((record) => record.code)).toEqual([
      "INVALID_REFERENCE",
      "NOT_FOUND",
      "PERMISSION_DENIED",
    ]);
  });

  it("reports a rejected delete without the server's words", async () => {
    const { backend, services } = fixture();
    (services.cipherService.softDeleteWithServer as jest.Mock).mockRejectedValue(
      new Error("500 secret-token"),
    );
    const failed = backend.dispatch({ operation: "delete", args: { ref: "ref:github/ci" } });
    await expect(failed).rejects.toMatchObject({ code: "WRITE_FAILED" });
    await expect(failed).rejects.not.toHaveProperty("message", expect.stringContaining("secret"));
  });

  it("does not record discovery", async () => {
    const { backend, records } = fixture();
    await backend.dispatch({ operation: "list" });
    await backend.dispatch({ operation: "show", args: { ref: "ref:github/ci" } });
    expect(records).toEqual([]);
  });

  it("withholds a value that could not be recorded", async () => {
    const { backend } = fixture();
    backend.setAudit(() => {
      throw new Error("disk full");
    });
    const read = backend.dispatch({
      operation: "get",
      args: { ref: "ref:github/ci", field: "password" },
    });
    await expect(read).rejects.toMatchObject({ code: "AUDIT_FAILED" });
    await expect(read).rejects.not.toHaveProperty("message", expect.stringContaining(SECRET));
  });
});
