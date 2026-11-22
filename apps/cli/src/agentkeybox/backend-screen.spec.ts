import { of } from "rxjs";

import { AuthenticationStatus } from "@bitwarden/common/auth/enums/authentication-status";

import type { ServiceContainer } from "../service-container/service-container";

import { Backend } from "./backend";
import type { ScreenState } from "./screen";

jest.mock("../auth/commands/lock.command", () => ({ LockCommand: jest.fn() }));
jest.mock("../auth/commands/login.command", () => ({ LoginCommand: jest.fn() }));
jest.mock("../key-management/commands/unlock.command", () => ({ UnlockCommand: jest.fn() }));
jest.mock("../platform/commands/config.command", () => ({ ConfigCommand: jest.fn() }));

function fixture() {
  const sync = jest.fn().mockResolvedValue(true);
  const status = jest.fn().mockResolvedValue(AuthenticationStatus.Unlocked);
  const services = {
    authService: { getAuthStatus: status },
    accountService: { activeAccount$: of({ id: "test" }) },
    environmentService: { environment$: of({ getUrls: () => ({}) }) },
    syncService: { fullSync: sync, getLastSync: jest.fn() },
    stateProvider: { getUser: () => ({ state$: of({}) }) },
  } as unknown as ServiceContainer;
  const screen = jest.fn<Promise<ScreenState>, []>().mockResolvedValue("unlocked");
  return { backend: new Backend(services, null, null, screen), screen, sync, status };
}

describe("screen-locked vault requests", () => {
  it("blocks a warm vault while locked, then resumes on screen unlock", async () => {
    const { backend, screen, sync } = fixture();
    screen.mockResolvedValue("locked");
    await expect(backend.dispatch({ operation: "status" })).resolves.toMatchObject({
      status: "locked",
      lock_reason: "screen_locked",
    });
    await expect(backend.dispatch({ operation: "get" })).rejects.toMatchObject({
      code: "SCREEN_LOCKED",
    });
    expect(sync).not.toHaveBeenCalled();

    screen.mockResolvedValue("unlocked");
    await expect(backend.dispatch({ operation: "list" })).resolves.toEqual([]);
  });

  it("withholds results if the screen locks during a request", async () => {
    const { backend, screen, sync } = fixture();
    screen
      .mockResolvedValueOnce("unlocked")
      .mockResolvedValueOnce("unlocked")
      .mockResolvedValue("locked");
    await expect(backend.dispatch({ operation: "list" })).rejects.toMatchObject({
      code: "SCREEN_LOCKED",
    });
    expect(sync).toHaveBeenCalled();
  });

  it("still requires vault unlock after a manual lock", async () => {
    const { backend, status } = fixture();
    status.mockResolvedValue(AuthenticationStatus.Locked);
    await expect(backend.dispatch({ operation: "get" })).rejects.toMatchObject({
      code: "VAULT_LOCKED",
    });
  });
});
