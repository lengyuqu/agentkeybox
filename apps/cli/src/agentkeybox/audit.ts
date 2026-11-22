import { appendFileSync, mkdirSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";

/** One line per access to a credential. Values, passwords and command arguments never appear. */
export interface AuditTarget {
  /** The reference the caller asked for, as `ref:<name>` or `id:<uuid>`. */
  ref?: string;
  /** The vault item that answered it. */
  id?: string;
  field?: string;
  /** For `assert`: the site the sign-in was for, reduced to its origin. */
  origin?: string;
  /** For `run`: the environment variable the value was given to. */
  env?: string;
}

export interface AuditRecord {
  op: string;
  outcome: "ok" | "error";
  code?: string;
  targets?: AuditTarget[];
  /** For `run`: the program's file name only. Arguments can carry secrets. */
  command?: string;
  exit_code?: number;
}

export type AuditSink = (record: AuditRecord) => void;

export const AUDIT_FILE = "audit.log";
const MAX_BYTES = 5 * 1024 * 1024;
// eslint-disable-next-line no-control-regex
const SELECTOR = /^(id:[0-9A-Za-z-]{1,64}|ref:[^\u0000-\u001f]{1,200})$/;

export const noAudit: AuditSink = () => {};

/** Keep what the caller typed only when it has the shape of a reference. */
export function auditSelector(text: string | undefined): string | undefined {
  return text !== undefined && SELECTOR.test(text) ? text : undefined;
}

const FIELD =
  // eslint-disable-next-line no-control-regex
  /^(password|username|notes|private_key|public_key|totp|passkey|custom:[^\u0000-\u001f]{1,200})$/;

/** Keep the field name only when it is one the vault understands. */
export function auditField(text: string | undefined): string | undefined {
  return text !== undefined && FIELD.test(text) ? text : undefined;
}

/** `C:\tools\gh.exe` and `/usr/bin/gh` are both recorded as `gh`. */
export function auditCommand(command: string | undefined): string | undefined {
  const name = command?.split(/[\\/]/).pop();
  // eslint-disable-next-line no-control-regex
  return name && name.length <= 100 && !/[\u0000-\u001f]/.test(name) ? name : undefined;
}

export function auditEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AKB_AUDIT?.toLowerCase() !== "off";
}

/**
 * Append records to `<profile>/audit.log`. The log is rotated once at 5 MiB, keeping one
 * older file. Throws when the record cannot be written, so callers can decide what to do.
 */
export function fileAudit(dir: string, now: () => Date = () => new Date()): AuditSink {
  const file = join(dir, AUDIT_FILE);
  return (record) => {
    if (!auditEnabled()) {
      return;
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    try {
      if (statSync(file).size >= MAX_BYTES) {
        renameSync(file, `${file}.1`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }
    appendFileSync(file, JSON.stringify({ ts: now().toISOString(), ...record }) + "\n", {
      mode: 0o600,
    });
  };
}
