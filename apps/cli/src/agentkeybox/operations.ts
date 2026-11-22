import { AuditRecord, auditCommand, auditField, auditSelector, AuditSink } from "./audit";
import { runForegroundCommand } from "./one-shot";
import { AkbError, SecretSpec, VAULT_ACCESS } from "./protocol";
import { runWithSecrets, RunOptions, RunSinks } from "./run";
import { requireActiveScreen, screenState } from "./screen";
import { call, connect } from "./transport";

/** Windows and macOS run each command in the foreground. Linux keeps a small local service. */
export const foreground = process.platform === "win32" || process.platform === "darwin";

/** Perform one vault operation and return its data. Failures are thrown as AkbError. */
export type Perform = (operation: string, args?: Record<string, string>) => Promise<unknown>;

export function performer(profile: string): Perform {
  return async (operation, args = {}) => {
    if (foreground && operation !== "stop") {
      const data = await runForegroundCommand(profile, { operation, args });
      if (VAULT_ACCESS.includes(operation)) {
        requireActiveScreen(await screenState());
      }
      return data;
    }
    const socket = await connect(profile, operation !== "stop");
    const reply = await call(socket, { operation, args });
    if (!reply.ok) {
      throw new AkbError(reply.error.code, reply.error.message, reply.error.exit_code);
    }
    return reply.data;
  };
}

/**
 * Run operations one at a time. A foreground operation keeps the session key in this
 * process's environment while it works, so two at once in one process would take it from
 * each other. A long-lived server that handles calls side by side must serialize them.
 */
export function serialized(perform: Perform): Perform {
  let tail: Promise<unknown> = Promise.resolve();
  return (operation, args) => {
    const result = tail.then(() => perform(operation, args));
    tail = result.catch(() => {});
    return result;
  };
}

/**
 * Resolve every secret, run the command with them, and record the run. The values stay inside
 * this call: they go to the child's environment and are removed from its output.
 */
export async function runCommand(
  perform: Perform,
  audit: AuditSink,
  warn: (message: string) => void,
  command: string[],
  specs: SecretSpec[],
  sinks?: RunSinks,
  options?: RunOptions,
): Promise<number> {
  const data = (await perform("resolve", { specs: JSON.stringify(specs) })) as {
    values: Record<string, string>;
  };
  const record = (entry: Partial<AuditRecord>) => {
    try {
      audit({
        op: "run",
        outcome: "ok",
        command: auditCommand(command[0]),
        targets: specs.map((spec) => ({
          env: spec.name,
          ref: auditSelector(spec.ref),
          field: auditField(spec.field),
        })),
        ...entry,
      });
    } catch {
      // The command has already run, so there is nothing left to withhold.
      warn("AKB: the run could not be recorded in the audit log.");
    }
  };
  let exitCode: number;
  try {
    exitCode = await runWithSecrets(command, data.values, sinks, options);
  } catch (error) {
    record({ outcome: "error", code: error instanceof AkbError ? error.code : "RUN_FAILED" });
    throw error;
  }
  record({ exit_code: exitCode });
  return exitCode;
}
