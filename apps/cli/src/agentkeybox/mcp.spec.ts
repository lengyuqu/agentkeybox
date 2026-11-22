import { PassThrough, Writable } from "node:stream";

import { handleMessage, McpDeps, serveMcp, toolNames } from "./mcp";
import { AkbError } from "./protocol";

const SECRET = "s3cr3t-value-123";

function deps(overrides: Partial<McpDeps> = {}): McpDeps & {
  perform: jest.Mock;
  run: jest.Mock;
} {
  return {
    perform: jest.fn().mockResolvedValue({ ok: true }),
    run: jest.fn().mockImplementation(async (_command, _specs, sinks) => {
      sinks.out.write(Buffer.from("hello [REDACTED:TOKEN]\n"));
      sinks.err.write(Buffer.from("warn\n"));
      return 0;
    }),
    readOnly: false,
    version: "test",
    ...overrides,
  } as never;
}

const call = (name: string, args: unknown) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name, arguments: args },
});

async function result(d: McpDeps, name: string, args: unknown) {
  const response = (await handleMessage(call(name, args), d)) as {
    result: { isError?: boolean; content: { text: string }[] };
  };
  return {
    isError: response.result.isError === true,
    body: JSON.parse(response.result.content[0].text),
  };
}

describe("MCP handshake", () => {
  it("answers initialize with a supported version and the tools capability", async () => {
    const response = (await handleMessage(
      { jsonrpc: "2.0", id: 7, method: "initialize", params: { protocolVersion: "2025-03-26" } },
      deps(),
    )) as { id: number; result: { protocolVersion: string; capabilities: object } };
    expect(response.id).toBe(7);
    expect(response.result.protocolVersion).toBe("2025-03-26");
    expect(response.result.capabilities).toEqual({ tools: {} });
  });

  it("offers its newest version when the client asks for one it does not know", async () => {
    const response = (await handleMessage(
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "1999-01-01" } },
      deps(),
    )) as { result: { protocolVersion: string } };
    expect(response.result.protocolVersion).toBe("2025-06-18");
  });

  it("stays silent on notifications and refuses unknown methods", async () => {
    expect(
      await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }, deps()),
    ).toBeUndefined();
    expect(await handleMessage({ jsonrpc: "2.0", id: 1, method: "nope" }, deps())).toMatchObject({
      error: { code: -32601 },
    });
    expect(await handleMessage([], deps())).toMatchObject({ error: { code: -32600 } });
  });
});

describe("MCP tools", () => {
  it("lists tools, and leaves out the writing ones when read-only", async () => {
    const all = (await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" }, deps())) as {
      result: { tools: { name: string }[] };
    };
    expect(all.result.tools.map((tool) => tool.name)).toEqual(toolNames(false));
    expect(toolNames(false)).toEqual(
      expect.arrayContaining([
        "akb_run",
        "akb_passkey_create",
        "akb_create",
        "akb_rotate",
        "akb_restore",
        "akb_delete",
      ]),
    );
    expect(toolNames(true)).toEqual([
      "akb_status",
      "akb_find",
      "akb_show",
      "akb_run",
      "akb_passkey_assert",
    ]);
    const refused = await handleMessage(
      call("akb_delete", { ref: "ref:x" }),
      deps({ readOnly: true }),
    );
    expect(refused).toMatchObject({ error: { code: -32602 } });
  });

  it("has no tool that returns a credential value", () => {
    for (const name of toolNames(false)) {
      expect(name).not.toMatch(/get|reveal|password|secret|totp/);
    }
  });

  it("finds and shows logins through discovery operations", async () => {
    const d = deps();
    await result(d, "akb_find", { url: "github.com", search: "ci" });
    expect(d.perform).toHaveBeenLastCalledWith("list", { url: "github.com", search: "ci" });
    await result(d, "akb_show", { ref: "ref:github/ci" });
    expect(d.perform).toHaveBeenLastCalledWith("show", { ref: "ref:github/ci" });
  });

  it("creates a passkey only from what a site sends, and is a writing tool", async () => {
    const d = deps();
    await result(d, "akb_passkey_create", {
      ref: "ref:site/login",
      origin: "https://example.com",
      challenge: "c".repeat(43),
      user_id: "dXNlcg",
      user_name: "alice",
      rp_name: "Example",
    });
    expect(d.perform).toHaveBeenLastCalledWith("register", {
      ref: "ref:site/login",
      origin: "https://example.com",
      challenge: "c".repeat(43),
      user_id: "dXNlcg",
      user_name: "alice",
      rp_name: "Example",
    });
    expect((await result(d, "akb_passkey_create", { ref: "ref:x" })).isError).toBe(true);
    const refused = await handleMessage(
      call("akb_passkey_create", { ref: "ref:x" }),
      deps({ readOnly: true }),
    );
    expect(refused).toMatchObject({ error: { code: -32602 } });
  });

  it("creates and rotates only with generated passwords", async () => {
    const d = deps();
    await result(d, "akb_create", { name: "GH", ref: "gh", urls: ["github.com"], length: 32 });
    expect(d.perform).toHaveBeenLastCalledWith("create", {
      name: "GH",
      ref: "gh",
      urls: '["github.com"]',
      generate: "1",
      length: "32",
    });
    await result(d, "akb_rotate", { ref: "ref:gh" });
    expect(d.perform).toHaveBeenLastCalledWith("set", {
      ref: "ref:gh",
      field: "password",
      generate: "1",
    });
    // A password offered in the call is not an input: it is ignored, never stored.
    await result(d, "akb_create", { name: "GH", ref: "gh2", password: SECRET });
    expect(JSON.stringify(d.perform.mock.calls)).not.toContain(SECRET);
    await result(d, "akb_delete", { ref: "ref:gh" });
    expect(d.perform).toHaveBeenLastCalledWith("delete", { ref: "ref:gh" });
    await result(d, "akb_restore", { ref: "ref:gh" });
    expect(d.perform).toHaveBeenLastCalledWith("restore", { ref: "ref:gh" });
    await result(d, "akb_find", { trashed: true, search: "gh" });
    expect(d.perform).toHaveBeenLastCalledWith("list", { search: "gh", trashed: "1" });
    expect((await result(d, "akb_find", { trashed: "yes" })).isError).toBe(true);
  });

  it("reports failures as tool errors with only the fixed message", async () => {
    const d = deps({
      perform: jest.fn().mockRejectedValue(new AkbError("NOT_FOUND", "Account not found.", 5)),
    });
    expect(await result(d, "akb_show", { ref: "ref:x" })).toEqual({
      isError: true,
      body: { code: "NOT_FOUND", message: "Account not found." },
    });
    const broken = deps({ perform: jest.fn().mockRejectedValue(new Error(`boom ${SECRET}`)) });
    const failed = await result(broken, "akb_show", { ref: "ref:x" });
    expect(failed.body.code).toBe("INTERNAL_ERROR");
    expect(JSON.stringify(failed)).not.toContain(SECRET);
  });

  it("rejects malformed arguments before doing anything", async () => {
    const d = deps();
    for (const [name, args] of [
      ["akb_show", {}],
      ["akb_show", { ref: 5 }],
      ["akb_find", { url: "" }],
      ["akb_create", { name: "x", ref: "r", urls: "not a list" }],
      ["akb_create", { name: "x", ref: "r", length: "32" }],
      ["akb_run", { env: [], command: ["x"] }],
      ["akb_run", { env: [{ name: "A", ref: "ref:x" }], command: [] }],
      ["akb_run", { env: [{ name: "A", ref: "ref:x" }], command: [1] }],
      ["akb_run", { env: [{ name: "bad name", ref: "ref:x" }], command: ["x"] }],
      ["akb_run", { env: [{ name: "A", ref: "ref:x" }], command: ["x"], timeout_seconds: 0 }],
      ["akb_run", { env: [{ name: "A", ref: "ref:x" }], command: ["x"], timeout_seconds: 601 }],
      ["akb_show", [] as unknown],
    ] as [string, unknown][]) {
      expect((await result(d, name, args)).isError).toBe(true);
    }
    expect(d.perform).not.toHaveBeenCalled();
    expect(d.run).not.toHaveBeenCalled();
  });
});

describe("akb_run", () => {
  it("runs the command with the named credentials and returns filtered output", async () => {
    const d = deps();
    const outcome = await result(d, "akb_run", {
      env: [
        { name: "TOKEN", ref: "ref:github/ci" },
        { name: "OTP", ref: "ref:github/ci", field: "totp" },
      ],
      command: ["gh", "pr", "list"],
      timeout_seconds: 30,
    });
    expect(outcome.body).toEqual({
      exit_code: 0,
      timed_out: false,
      stdout: "hello [REDACTED:TOKEN]\n",
      stderr: "warn\n",
    });
    expect(d.run).toHaveBeenCalledWith(
      ["gh", "pr", "list"],
      [
        { name: "TOKEN", ref: "ref:github/ci", field: "password" },
        { name: "OTP", ref: "ref:github/ci", field: "totp" },
      ],
      expect.anything(),
      30_000,
    );
  });

  it("reports a timeout, and cuts very long output", async () => {
    const d = deps({
      run: jest.fn().mockImplementation(async (_c, _s, sinks) => {
        sinks.out.write(Buffer.from("x".repeat(100_000)));
        return 124;
      }),
    });
    const outcome = await result(d, "akb_run", {
      env: [{ name: "A", ref: "ref:x" }],
      command: ["slow"],
    });
    expect(outcome.body.timed_out).toBe(true);
    expect(outcome.body.stdout).toHaveLength(64 * 1024);
    expect(outcome.body.truncated).toContain("cut");
  });

  it("passes a start failure on as a tool error", async () => {
    const d = deps({
      run: jest.fn().mockRejectedValue(new AkbError("RUN_FAILED", "Command not found.", 9)),
    });
    expect(
      await result(d, "akb_run", { env: [{ name: "A", ref: "ref:x" }], command: ["nope"] }),
    ).toEqual({ isError: true, body: { code: "RUN_FAILED", message: "Command not found." } });
  });
});

describe("serveMcp", () => {
  function session(d: McpDeps) {
    const input = new PassThrough();
    const lines: string[] = [];
    const output = new Writable({
      write(chunk, _encoding, done) {
        lines.push(...chunk.toString().split("\n").filter(Boolean));
        done();
      },
    });
    return { input, lines, finished: serveMcp(input, output, d) };
  }

  it("answers newline-delimited requests, including ones split across chunks", async () => {
    const { input, lines, finished } = session(deps());
    const ping = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });
    input.write(ping.slice(0, 10));
    input.write(ping.slice(10) + "\n");
    input.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    input.write("not json\n");
    input.end(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }));
    await finished;
    const replies = lines.map((line) => JSON.parse(line));
    expect(replies).toEqual(
      expect.arrayContaining([
        { jsonrpc: "2.0", id: 1, result: {} },
        { jsonrpc: "2.0", id: 2, result: {} },
        expect.objectContaining({ error: expect.objectContaining({ code: -32700 }) }),
      ]),
    );
    expect(replies).toHaveLength(3);
  });

  it("finishes the call in progress before it ends", async () => {
    let release: () => void = () => {};
    const slow = deps({
      perform: jest
        .fn()
        .mockImplementation(
          () => new Promise((resolve) => (release = () => resolve({ done: true }))),
        ),
    });
    const { input, lines, finished } = session(slow);
    input.end(JSON.stringify(call("akb_status", {})) + "\n");
    await new Promise((resolve) => setImmediate(resolve));
    expect(lines).toHaveLength(0);
    release();
    await finished;
    expect(lines).toHaveLength(1);
  });
});
