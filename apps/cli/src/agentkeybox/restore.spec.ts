import { of } from "rxjs";

import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";

import type { ServiceContainer } from "../service-container/service-container";

import { AuditRecord } from "./audit";
import { Backend } from "./backend";
import { selectItem } from "./protocol";

jest.mock("../auth/commands/lock.command", () => ({ LockCommand: jest.fn() }));
jest.mock("../auth/commands/login.command", () => ({ LoginCommand: jest.fn() }));
jest.mock("../key-management/commands/unlock.command", () => ({ UnlockCommand: jest.fn() }));
jest.mock("../platform/commands/config.command", () => ({ ConfigCommand: jest.fn() }));
jest.mock("@bitwarden/common/vault/models/domain/cipher", () => ({
  Cipher: jest.fn().mockImplementation((data) => ({ ...data })),
}));

const SECRET = "s3cr3t-value-123";
const field = (value: string) => [{ name: "agentkeybox.ref", value, type: 0 }];
const deletedAt = new Date("2026-11-20T10:00:00.000Z");

/** One live login and one deleted login. */
function fixture(options: { reuseRef?: boolean; readOnly?: boolean } = {}) {
  const live = {
    id: "live-1",
    name: "Live",
    type: 1,
    login: { username: "me", password: SECRET },
    fields: field(options.reuseRef ? "old/ref" : "live/ref"),
  };
  const gone = {
    id: "gone-1",
    name: "Gone",
    type: 1,
    deletedDate: deletedAt,
    ...(options.readOnly ? { edit: false } : {}),
    login: { username: "you", password: SECRET },
    fields: field("old/ref"),
  };
  const byId: Record<string, unknown> = { [live.id]: live, [gone.id]: gone };
  const services = {
    authService: { getAuthStatus: jest.fn().mockResolvedValue(AuthenticationStatus.Unlocked) },
    accountService: { activeAccount$: of({ id: "test" }) },
    environmentService: { environment$: of({ getUrls: () => ({}) }) },
    syncService: { fullSync: jest.fn().mockResolvedValue(true), getLastSync: jest.fn() },
    stateProvider: {
      getUser: () => ({
        state$: of({
          [live.id]: { id: live.id, deletedDate: null },
          [gone.id]: { id: gone.id, deletedDate: deletedAt },
        }),
      }),
    },
    cipherService: {
      decrypt: jest.fn().mockImplementation(async (record: { id: string }) => byId[record.id]),
      restoreWithServer: jest.fn().mockResolvedValue(undefined),
    },
  } as unknown as ServiceContainer;
  const records: AuditRecord[] = [];
  const backend = new Backend(services, null, null, jest.fn().mockResolvedValue("unlocked"));
  backend.setAudit((record) => records.push(record));
  return { backend, records, services };
}

describe("selectItem among deleted items", () => {
  const items = [
    { id: "a", fields: field("x") },
    { id: "b", deletedDate: deletedAt, fields: field("x") },
  ];

  it("looks only at live items by default and only at deleted ones when asked", () => {
    expect(selectItem(items, "ref:x").id).toBe("a");
    expect(selectItem(items, "ref:x", true).id).toBe("b");
    expect(() => selectItem(items, "id:b")).toThrow(expect.objectContaining({ code: "NOT_FOUND" }));
    expect(() => selectItem(items, "id:a", true)).toThrow(
      expect.objectContaining({ code: "NOT_FOUND" }),
    );
  });
});

describe("listing the trash", () => {
  it("lists only deleted logins, with when they were deleted and no values", async () => {
    const { backend } = fixture();
    const trashed = await backend.dispatch({ operation: "list", args: { trashed: "1" } });
    expect(trashed).toEqual([
      expect.objectContaining({
        id: "gone-1",
        ref: "old/ref",
        deleted_at: deletedAt.toISOString(),
      }),
    ]);
    expect(JSON.stringify(trashed)).not.toContain(SECRET);
    const live = (await backend.dispatch({ operation: "list" })) as { id: string }[];
    expect(live.map((item) => item.id)).toEqual(["live-1"]);
    expect(live[0]).not.toHaveProperty("deleted_at");
  });

  it("does not combine the trash with an address", async () => {
    const { backend } = fixture();
    await expect(
      backend.dispatch({ operation: "list", args: { trashed: "1", url: "example.com" } }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });
});

describe("restoring a login", () => {
  it("brings it back and records it", async () => {
    const { backend, records, services } = fixture();
    const reply = await backend.dispatch({ operation: "restore", args: { ref: "ref:old/ref" } });
    expect(services.cipherService.restoreWithServer).toHaveBeenCalledWith("gone-1", "test");
    expect(reply).toMatchObject({ id: "gone-1", ref: "old/ref", restored: true });
    expect(JSON.stringify(reply)).not.toContain(SECRET);
    expect(records).toEqual([
      { op: "restore", outcome: "ok", targets: [{ ref: "ref:old/ref", id: "gone-1" }] },
    ]);
  });

  it("does not restore a live login, an unknown one, or a loose name", async () => {
    const { backend, services } = fixture();
    for (const [ref, code] of [
      ["ref:live/ref", "NOT_FOUND"],
      ["ref:nothing", "NOT_FOUND"],
      ["old/ref", "INVALID_REFERENCE"],
    ]) {
      await expect(backend.dispatch({ operation: "restore", args: { ref } })).rejects.toMatchObject(
        {
          code,
        },
      );
    }
    expect(services.cipherService.restoreWithServer).not.toHaveBeenCalled();
  });

  it("refuses when the reference has been used again since", async () => {
    const { backend, services } = fixture({ reuseRef: true });
    await expect(
      backend.dispatch({ operation: "restore", args: { ref: "id:gone-1" } }),
    ).rejects.toMatchObject({ code: "REF_EXISTS" });
    expect(services.cipherService.restoreWithServer).not.toHaveBeenCalled();
  });

  it("refuses a read-only item", async () => {
    const { backend } = fixture({ readOnly: true });
    await expect(
      backend.dispatch({ operation: "restore", args: { ref: "id:gone-1" } }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("reports a rejected restore without the words of the server", async () => {
    const { backend, services } = fixture();
    (services.cipherService.restoreWithServer as jest.Mock).mockRejectedValue(
      new Error("500 secret-token"),
    );
    const failed = backend.dispatch({ operation: "restore", args: { ref: "id:gone-1" } });
    await expect(failed).rejects.toMatchObject({ code: "WRITE_FAILED" });
    await expect(failed).rejects.not.toHaveProperty("message", expect.stringContaining("secret"));
  });
});
