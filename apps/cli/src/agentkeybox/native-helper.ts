import { execFile } from "node:child_process";
import { dirname, join } from "node:path";

export function runNativeHelper(args: string[], input?: string) {
  const packaged = !!(process as NodeJS.Process & { pkg?: unknown }).pkg;
  const windows = process.platform === "win32";
  const helper = join(
    packaged ? dirname(process.execPath) : __dirname,
    windows ? "akb-credentials.exe" : "akb-keychain",
  );
  return new Promise<{ status: number; stdout: string }>((resolve) => {
    try {
      const child = execFile(
        helper,
        args,
        {
          env: windows ? { SystemRoot: process.env.SystemRoot } : {},
          windowsHide: true,
          maxBuffer: 4096,
          timeout: 5000,
        },
        (error, stdout) => {
          const status = error ? (typeof error.code === "number" ? error.code : -1) : 0;
          resolve({ status, stdout: status === 0 ? stdout : "" });
        },
      );
      // A helper that rejects access can exit before reading its input.
      child.stdin?.on("error", () => {});
      child.stdin?.end(input);
    } catch {
      resolve({ status: -1, stdout: "" });
    }
  });
}
