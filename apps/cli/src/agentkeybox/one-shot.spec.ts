import { runForegroundCommand } from "./one-shot";
import { screenState } from "./screen";
import { storedSession } from "./session-store";
import { profileDirectory } from "./transport";

jest.mock("./session-store");
jest.mock("./screen", () => ({
  ...jest.requireActual("./screen"),
  screenState: jest.fn(),
}));
jest.mock("./transport", () => ({ profileDirectory: jest.fn() }));

it.each([
  ["locked", "SCREEN_LOCKED"],
  ["unavailable", "SCREEN_STATE_UNAVAILABLE"],
] as const)(
  "blocks a vault read before opening the profile when the screen is %s",
  async (state, code) => {
    jest.mocked(screenState).mockResolvedValue(state);

    await expect(runForegroundCommand("test", { operation: "get" })).rejects.toMatchObject({
      code,
    });
    expect(profileDirectory).not.toHaveBeenCalled();
    expect(storedSession).not.toHaveBeenCalled();
  },
);
