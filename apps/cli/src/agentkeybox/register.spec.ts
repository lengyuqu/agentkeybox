import { randomBytes } from "node:crypto";

import { of } from "rxjs";

import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";
import { CipherRepromptType } from "@bitwarden/common/vault/enums";

import type { ServiceContainer } from "../service-container/service-container";

import { AuditRecord } from "./audit";
import { Backend } from "./backend";

jest.mock("../auth/commands/lock.command", () => ({ LockCommand: jest.fn() }));
jest.mock("../auth/commands/login.command", () => ({ LoginCommand: jest.fn() }));
jest.mock("../key-management/commands/unlock.command", () => ({ UnlockCommand: jest.fn() }));
jest.mock("../platform/commands/config.command", () => ({ ConfigCommand: jest.fn() }));
jest.mock("@bitwarden/common/vault/models/domain/cipher", () => ({
  Cipher: jest.fn().mockImplementation((data) => ({ ...data })),
}));

const challenge = randomBytes(32).toString("base64url");
const request = {
  ref: "ref:site/login",
  origin: "https://example.com",
  challenge,
  user_id: randomBytes(16).toString("base64url"),
  user_name: "alice@example.com",
};

/** A login with no passkey, unless a test says otherwise. */
function fixture(overrides: Record<string, unknown> = {}) {
  const login = {
    id: "login-1",
    name: "Example",
    type: 1,
    login: { username: "alice", password: "pw", fido2Credentials: [] as { rpId: string }[] },
    reprompt: CipherRepromptType.None,
    fields: [{ name: "agentkeybox.ref", value: "site/login", type: 0 }],
    ...overrides,
  };
  const services = {
    authService: { getAuthStatus: jest.fn().mockResolvedValue(AuthenticationStatus.Unlocked) },
    accountService: { activeAccount$: of({ id: "test" }) },
    environmentService: { environment$: of({ getUrls: () => ({}) }) },
    syncService: { fullSync: jest.fn().mockResolvedValue(true), getLastSync: jest.fn() },
    stateProvider: { getUser: () => ({ state$: of({ [login.id]: { deletedDate: null } }) }) },
    cipherService: {
      decrypt: jest.fn().mockResolvedValue(login),
      updateWithServer: jest.fn(),
    },
  } as unknown as ServiceContainer;
  const records: AuditRecord[] = [];
  const backend = new Backend(services, null, null, jest.fn().mockResolvedValue("unlocked"));
  backend.setAudit((record) => records.push(record));
  return { backend, records, services, login };
}

const register = (backend: Backend, args: Record<string, string> = {}) =>
  backend.dispatch({ operation: "register", args: { ...request, ...args } });

const withPasskey = {
  login: { username: "alice", password: "pw", fido2Credentials: [{ rpId: "example.com" }] },
};

describe("registering a passkey: what is refused before anything is created", () => {
  it("never overwrites a login that already has a passkey", async () => {
    const { backend, services } = fixture(withPasskey);
    await expect(register(backend)).rejects.toMatchObject({ code: "PASSKEY_EXISTS", exitCode: 6 });
    expect(services.cipherService.updateWithServer).not.toHaveBeenCalled();
  });

  it("refuses an item that is read-only, asks for the master password, or is not a login", async () => {
    await expect(register(fixture({ edit: false }).backend)).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });
    await expect(
      register(fixture({ reprompt: CipherRepromptType.Password }).backend),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(register(fixture({ type: 2 }).backend)).rejects.toMatchObject({
      code: "UNSUPPORTED_FIELD",
    });
  });

  it("refuses a site id that does not belong to the origin", async () => {
    const { backend } = fixture();
    await expect(register(backend, { rp_id: "other.test" })).rejects.toMatchObject({
      code: "INVALID_ORIGIN",
    });
  });

  it("refuses an unknown login and a malformed request", async () => {
    const { backend } = fixture();
    await expect(register(backend, { ref: "ref:nothing" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(register(backend, { user_id: "not base64url!" })).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
    await expect(register(backend, { origin: "http://example.com" })).rejects.toMatchObject({
      code: "INVALID_ORIGIN",
    });
  });

  it("records each attempt in the audit log, by reference, item and origin", async () => {
    const { backend, records } = fixture(withPasskey);
    await expect(register(backend)).rejects.toBeDefined();
    expect(records).toEqual([
      {
        op: "register",
        outcome: "error",
        code: "PASSKEY_EXISTS",
        targets: [
          { ref: "ref:site/login", id: "login-1", field: "passkey", origin: "https://example.com" },
        ],
      },
    ]);
  });
});
