/**
 * Best-effort redaction of injected secrets from a child process's output.
 *
 * The real guarantee of `akb run` is that values never reach the caller's context unless the
 * command itself prints them. This filter catches the accidental case: a tool that echoes its
 * environment, a verbose HTTP client, an error message. It cannot recognise a value that the
 * command has transformed in some other way.
 *
 * Text is handled as raw bytes (latin1), so the child's output encoding does not matter and
 * non-UTF-8 output passes through unchanged.
 */

const MIN_REDACTED_LENGTH = 4;

function bytes(value: string): string {
  return Buffer.from(value, "utf8").toString("latin1");
}

/** The plain value plus the encodings that commonly appear in logs and error messages. */
function variants(secret: string): string[] {
  const raw = Buffer.from(secret, "utf8");
  const base64 = raw.toString("base64");
  const found = [
    bytes(secret),
    bytes(JSON.stringify(secret).slice(1, -1)),
    encodeURIComponent(secret),
    base64,
    base64.replace(/=+$/, ""),
    raw.toString("base64url"),
    raw.toString("hex"),
  ];
  return found.filter((text) => text.length >= MIN_REDACTED_LENGTH);
}

export class Redactor {
  private readonly pattern: RegExp | undefined;
  private readonly labels = new Map<string, string>();
  private readonly hold: number;
  private pending = "";

  /** @param secrets environment variable name to secret value */
  constructor(secrets: Record<string, string>) {
    for (const [name, value] of Object.entries(secrets)) {
      for (const text of variants(value)) {
        if (!this.labels.has(text)) {
          this.labels.set(text, `[REDACTED:${name}]`);
        }
      }
    }
    // Longest first, so a value that contains a shorter one is replaced as a whole.
    const texts = [...this.labels.keys()].sort((a, b) => b.length - a.length);
    this.hold = texts.length ? texts[0].length - 1 : 0;
    this.pattern = texts.length
      ? new RegExp(texts.map((text) => text.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")).join("|"), "g")
      : undefined;
  }

  /** Feed one chunk of child output and get back what is safe to forward now. */
  write(chunk: Buffer): Buffer {
    return this.scan(this.pending + chunk.toString("latin1"), false);
  }

  /** Call once the stream has ended to release the held-back tail. */
  end(): Buffer {
    return this.scan(this.pending, true);
  }

  private scan(buffer: string, final: boolean): Buffer {
    if (!this.pattern) {
      return Buffer.from(buffer, "latin1");
    }
    // A match that starts before this index is entirely inside the buffer. A match starting
    // later could continue into the next chunk, so that tail is held back and rescanned.
    const limit = final ? buffer.length : Math.max(0, buffer.length - this.hold);
    let output = "";
    let cursor = 0;
    this.pattern.lastIndex = 0;
    for (let match = this.pattern.exec(buffer); match; match = this.pattern.exec(buffer)) {
      if (match.index >= limit) {
        break;
      }
      output += buffer.slice(cursor, match.index) + this.labels.get(match[0]);
      cursor = match.index + match[0].length;
    }
    if (cursor < limit) {
      output += buffer.slice(cursor, limit);
      cursor = limit;
    }
    // The tail is kept as original, unredacted text, so a label is never rescanned.
    this.pending = buffer.slice(cursor);
    return Buffer.from(output, "latin1");
  }
}
