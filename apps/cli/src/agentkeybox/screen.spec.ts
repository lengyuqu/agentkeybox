import { runNativeHelper } from "./native-helper";
import { consoleScreenState, requireActiveScreen, screenState } from "./screen";

jest.mock("./native-helper");

const consoleSession = {
  kCGSSessionOnConsoleKey: true,
  kCGSessionLoginDoneKey: true,
  kCGSSessionUserIDKey: 501,
};

describe("macOS credential access", () => {
  it("opens only for the signed-in user's active and unlocked console", () => {
    expect(consoleScreenState([consoleSession], 501)).toBe("unlocked");
    expect(consoleScreenState([{ ...consoleSession, CGSSessionScreenIsLocked: true }], 501)).toBe(
      "locked",
    );
    expect(consoleScreenState([consoleSession], 502)).toBe("locked");
    expect(consoleScreenState([{ ...consoleSession, kCGSessionLoginDoneKey: false }], 501)).toBe(
      "locked",
    );
    expect(consoleScreenState([{ ...consoleSession, kCGSSessionOnConsoleKey: false }], 501)).toBe(
      "locked",
    );
  });

  it("denies access on ambiguous or malformed system state", () => {
    expect(consoleScreenState(null, 501)).toBe("unavailable");
    expect(consoleScreenState([consoleSession, consoleSession], 501)).toBe("unavailable");
    expect(consoleScreenState([{ ...consoleSession, CGSSessionScreenIsLocked: "true" }], 501)).toBe(
      "unavailable",
    );
  });
});

describe("Windows credential access", () => {
  const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");

  beforeEach(() => {
    Object.defineProperty(process, "platform", { value: "win32" });
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", originalPlatform);
    jest.resetAllMocks();
  });

  it.each([
    [4, "SCREEN_LOCKED"],
    [5, "SCREEN_STATE_UNAVAILABLE"],
    [-1, "SCREEN_STATE_UNAVAILABLE"],
  ])("blocks a vault read when the Windows screen helper exits with %s", async (status, code) => {
    jest.mocked(runNativeHelper).mockResolvedValue({ status, stdout: "" });

    await expect(screenState().then(requireActiveScreen)).rejects.toMatchObject({ code });
  });
});
