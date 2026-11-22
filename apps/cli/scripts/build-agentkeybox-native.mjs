import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../", import.meta.url));
const build = path.join(cli, "build-akb");
const windows = process.argv[2] === "windows-x64" || process.platform === "win32";

if (windows) {
  mkdirSync(build, { recursive: true });
  const source = path.join(cli, "src/agentkeybox/windows-credentials.c");
  const helper = path.join(build, "akb-credentials.exe");
  if (process.platform === "win32" && !process.env.AKB_WINDOWS_CC) {
    // Use an x64 Visual Studio developer shell for native Windows builds.
    execFileSync(
      "cl.exe",
      [
        "/nologo",
        "/std:c17",
        "/O2",
        "/W4",
        "/MT",
        source,
        "/Fo" + path.join(build, "credentials.obj"),
        "/Fe" + helper,
        "/link",
        "/MACHINE:X64",
        "advapi32.lib",
        "wtsapi32.lib",
        "user32.lib",
      ],
      { stdio: "inherit" },
    );
  } else {
    execFileSync(
      process.env.AKB_WINDOWS_CC || "x86_64-w64-mingw32-gcc",
      [
        "-municode",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        source,
        "-ladvapi32",
        "-lwtsapi32",
        "-luser32",
        "-o",
        helper,
      ],
      { stdio: "inherit" },
    );
  }
} else if (process.platform === "darwin") {
  mkdirSync(build, { recursive: true });
  const helper = path.join(build, "akb-keychain");
  const arch = process.arch === "x64" ? "x86_64" : "arm64";
  execFileSync(
    "/usr/bin/xcrun",
    [
      "swiftc",
      "-O",
      "-target",
      `${arch}-apple-macos12.0`,
      "-module-name",
      "AgentKeyboxKeychain",
      "-o",
      helper,
      path.join(cli, "src/agentkeybox/keychain.swift"),
    ],
    { stdio: "inherit" },
  );
  execFileSync(
    "/usr/bin/codesign",
    ["--force", "--sign", "-", "--identifier", "dev.agentkeybox.keychain", helper],
    { stdio: "inherit" },
  );
}
