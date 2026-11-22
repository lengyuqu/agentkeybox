import { Writable } from "node:stream";

import { parseSecretSpec, parseSecretSpecs, parseSecretSpecsPayload } from "./protocol";
import { runWithSecrets, TIMEOUT_EXIT_CODE } from "./run";

function collector() {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  return { stream, text: () => Buffer.concat(chunks).toString("utf8") };
}

async function run(script: string, secrets: Record<string, string>) {
  const out = collector();
  const err = collector();
  const code = await runWithSecrets([process.execPath, "-e", script], secrets, {
    out: out.stream,
    err: err.stream,
  });
  return { code, out: out.text(), err: err.text() };
}

describe("runWithSecrets", () => {
  const secret = "tok-9f2c1d7e8a";

  it("redacts a command that echoes the injected value", async () => {
    const result = await run("console.log('token=' + process.env.TOKEN)", { TOKEN: secret });
    expect(result.out).toBe("token=[REDACTED:TOKEN]\n");
    expect(result.out).not.toContain(secret);
  });

  it("proves the injected value is exact without printing it", async () => {
    const result = await run(
      `process.stdout.write(String(process.env.TOKEN === ${JSON.stringify(secret)}))`,
      { TOKEN: secret },
    );
    expect(result.out).toBe("true");
  });

  it("redacts standard error as well", async () => {
    const result = await run("console.error('leak ' + process.env.TOKEN)", { TOKEN: secret });
    expect(result.err).toBe("leak [REDACTED:TOKEN]\n");
  });

  it("passes the command's exit code through", async () => {
    expect((await run("process.exit(7)", { TOKEN: secret })).code).toBe(7);
    expect((await run("process.exit(0)", { TOKEN: secret })).code).toBe(0);
  });

  it("does not hand AKB's internal variables to the command", async () => {
    process.env.BW_SESSION = "should-not-leak";
    try {
      const result = await run("process.stdout.write(String(process.env.BW_SESSION ?? 'unset'))", {
        TOKEN: secret,
      });
      expect(result.out).toBe("unset");
    } finally {
      delete process.env.BW_SESSION;
    }
  });

  it("does not interpret arguments through a shell", async () => {
    const out = collector();
    const err = collector();
    await runWithSecrets(
      [process.execPath, "-e", "console.log(process.argv[1])", "a && b; $X"],
      {},
      {
        out: out.stream,
        err: err.stream,
      },
    );
    expect(out.text()).toBe("a && b; $X\n");
  });

  it("reports a missing command without echoing it", async () => {
    await expect(
      runWithSecrets(["akb-command-that-does-not-exist-9f2c"], { TOKEN: secret }),
    ).rejects.toMatchObject({ code: "RUN_FAILED", exitCode: 9, message: "Command not found." });
  });

  it("keeps large output intact", async () => {
    const result = await run("process.stdout.write('x'.repeat(1_000_000))", { TOKEN: secret });
    expect(result.out).toHaveLength(1_000_000);
  });
});

describe("secret specifications", () => {
  it("defaults to the password field", () => {
    expect(parseSecretSpec("TOKEN=ref:github/ci")).toEqual({
      name: "TOKEN",
      ref: "ref:github/ci",
      field: "password",
    });
  });

  it("accepts built-in and custom fields after #", () => {
    expect(parseSecretSpec("U=id:abc#username").field).toBe("username");
    expect(parseSecretSpec("K=ref:ssh/prod#private_key").field).toBe("private_key");
    expect(parseSecretSpec("X=ref:db/prod#custom:api key")).toMatchObject({
      ref: "ref:db/prod",
      field: "custom:api key",
    });
  });

  it("keeps a # that is not followed by a field name as part of the reference", () => {
    expect(parseSecretSpec("X=ref:issue#42")).toMatchObject({
      ref: "ref:issue#42",
      field: "password",
    });
  });

  it("rejects malformed specifications without echoing them", () => {
    for (const bad of ["", "NOEQUALS", "=ref:x", "1BAD=ref:x", "A-B=ref:x", "A=", "A B=ref:x"]) {
      expect(() => parseSecretSpec(bad)).toThrow("Use NAME=");
    }
    try {
      parseSecretSpec("secret-looking-value");
    } catch (error) {
      expect((error as Error).message).not.toContain("secret-looking-value");
    }
  });

  it("requires at least one and rejects duplicate names, ignoring case", () => {
    expect(() => parseSecretSpecs([])).toThrow("at least one");
    expect(() => parseSecretSpecs(["A=ref:x", "a=ref:y"])).toThrow("once");
  });

  it("validates specifications received over the service socket", () => {
    const good = JSON.stringify([{ name: "A", ref: "ref:x", field: "password" }]);
    expect(parseSecretSpecsPayload(good)).toEqual([{ name: "A", ref: "ref:x", field: "password" }]);
    expect(() => parseSecretSpecsPayload(undefined)).toThrow("Invalid secret");
    expect(() => parseSecretSpecsPayload("{}")).toThrow("Invalid secret");
    expect(() => parseSecretSpecsPayload("[]")).toThrow("at least one");
    expect(() =>
      parseSecretSpecsPayload(JSON.stringify([{ name: "A", ref: "ref:x", field: "everything" }])),
    ).toThrow("Invalid secret");
  });

  it("drops unexpected properties from socket payloads", () => {
    const payload = JSON.stringify([{ name: "A", ref: "ref:x", field: "password", extra: "y" }]);
    expect(parseSecretSpecsPayload(payload)[0]).toEqual({
      name: "A",
      ref: "ref:x",
      field: "password",
    });
  });
});

describe("runWithSecrets options", () => {
  it("stops a command that outlives its timeout and reports 124", async () => {
    const out = collector();
    const started = Date.now();
    const code = await runWithSecrets(
      [process.execPath, "-e", "console.log('begin'); setInterval(() => {}, 1000)"],
      { TOKEN: "tok-9f2c1d7e8a" },
      { out: out.stream, err: collector().stream },
      { stdin: "ignore", timeoutMs: 700 },
    );
    expect(code).toBe(TIMEOUT_EXIT_CODE);
    expect(out.text()).toBe("begin\n");
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("gives the command no standard input when asked", async () => {
    const out = collector();
    const code = await runWithSecrets(
      [
        process.execPath,
        "-e",
        "process.stdin.on('data', () => {}).on('end', () => console.log('eof'))",
      ],
      {},
      { out: out.stream, err: collector().stream },
      { stdin: "ignore" },
    );
    expect(code).toBe(0);
    expect(out.text()).toBe("eof\n");
  });
});
