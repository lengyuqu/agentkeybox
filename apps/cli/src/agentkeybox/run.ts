import { spawn } from "node:child_process";
import { constants } from "node:os";
import type { Writable } from "node:stream";

import { AkbError } from "./protocol";
import { Redactor } from "./redact";

export interface RunSinks {
  out: Writable;
  err: Writable;
}

// Variables AKB sets for its own vault access. A child process has no use for them.
const INTERNAL_ENVIRONMENT = ["BW_SESSION", "BW_NOINTERACTION", "BW_QUIET"];

export interface RunOptions {
  /** The default passes the caller's standard input through. A service must not. */
  stdin?: "inherit" | "ignore";
  /** Stop the command after this long. It then reports exit code 124. */
  timeoutMs?: number;
}

/** What the timeout reports, as GNU timeout does. */
export const TIMEOUT_EXIT_CODE = 124;
/** How long a stopped command may keep its output open before it is cut off. */
const KILL_GRACE_MS = 2000;

/**
 * Run `command` with `secrets` in its environment and forward its output with the secret
 * values redacted. Resolves with the exit code to report. The command is started directly,
 * never through a shell, so nothing in its arguments is interpreted or expanded.
 */
export function runWithSecrets(
  command: string[],
  secrets: Record<string, string>,
  sinks: RunSinks = { out: process.stdout, err: process.stderr },
  options: RunOptions = {},
): Promise<number> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of INTERNAL_ENVIRONMENT) {
    delete env[name];
  }
  Object.assign(env, secrets);

  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      env,
      shell: false,
      windowsHide: true,
      // stdin stays attached for commands that read it; output goes through the filter.
      stdio: [options.stdin ?? "inherit", "pipe", "pipe"],
    });
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    let cutoff: NodeJS.Timeout | undefined;
    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill();
        // A grandchild can hold the output pipes open after the command is gone.
        cutoff = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
        }, KILL_GRACE_MS);
      }, options.timeoutMs);
    }
    const clearTimers = () => {
      clearTimeout(timer);
      clearTimeout(cutoff);
    };

    const streams: [NodeJS.ReadableStream, Writable][] = [
      [child.stdout, sinks.out],
      [child.stderr, sinks.err],
    ];
    const redactors = streams.map(([source, sink]) => {
      const redactor = new Redactor(secrets);
      source.on("data", (chunk: Buffer) => {
        // Respect backpressure so a chatty command cannot grow memory without bound.
        if (!sink.write(redactor.write(chunk))) {
          source.pause();
          sink.once("drain", () => source.resume());
        }
      });
      return { redactor, sink };
    });

    const forward = (signal: NodeJS.Signals) => () => child.kill(signal);
    const handlers = (["SIGINT", "SIGTERM", "SIGHUP"] as const).map(
      (signal) => [signal, forward(signal)] as const,
    );
    handlers.forEach(([signal, handler]) => process.on(signal, handler));
    const detach = () => handlers.forEach(([signal, handler]) => process.off(signal, handler));

    child.once("error", (error: NodeJS.ErrnoException) => {
      detach();
      clearTimers();
      // Only the error code is reported: the message can contain the command line.
      reject(
        new AkbError(
          "RUN_FAILED",
          error.code === "ENOENT"
            ? "Command not found."
            : error.code === "EINVAL"
              ? "Command cannot be started directly; on Windows run scripts through their interpreter."
              : "Could not start the command.",
          9,
        ),
      );
    });
    // "close" fires after both output streams have ended, so nothing is left unread.
    child.once("close", (code, signal) => {
      detach();
      clearTimers();
      for (const { redactor, sink } of redactors) {
        sink.write(redactor.end());
      }
      resolve(
        timedOut
          ? TIMEOUT_EXIT_CODE
          : (code ?? 128 + (signal ? (constants.signals[signal] ?? 1) : 1)),
      );
    });
  });
}
