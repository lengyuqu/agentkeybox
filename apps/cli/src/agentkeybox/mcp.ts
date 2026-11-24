import { Writable } from "node:stream";

import { AkbError, parseSecretSpecsPayload, SecretSpec } from "./protocol";
import { TIMEOUT_EXIT_CODE } from "./run";

/**
 * A small MCP server over standard input and output, written against the protocol directly:
 * a secrets tool should not pull a general SDK and its dependencies into its bundle.
 *
 * What it offers is chosen by what a model's context must never receive. No tool returns a
 * password, a token, a TOTP code or any other credential value. Values are only ever used
 * inside `akb_run`, whose output is filtered. Writes accept no values either: a value in a
 * tool call is already in the conversation, so passwords can only be generated.
 */

const SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_MESSAGE_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_SECONDS = 120;
const MAX_TIMEOUT_SECONDS = 600;

type Json = Record<string, unknown>;

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface McpDeps {
  perform: (operation: string, args?: Record<string, string>) => Promise<unknown>;
  /** Run a command with secrets injected. The sinks receive output that is already filtered. */
  run: (
    command: string[],
    specs: SecretSpec[],
    sinks: { out: Writable; err: Writable },
    timeoutMs: number,
  ) => Promise<number>;
  readOnly: boolean;
  version: string;
}

interface Tool {
  name: string;
  description: string;
  inputSchema: Json;
  write?: boolean;
  call: (input: Json, deps: McpDeps) => Promise<unknown>;
}

const REF = {
  type: "string",
  description: "Exact reference: ref:<name> or id:<uuid>.",
} as const;

function invalid(message: string): AkbError {
  return new AkbError("INVALID_ARGUMENT", message, 2);
}

function text(input: Json, key: string, required = false): string | undefined {
  const value = input[key];
  if (value === undefined && !required) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw invalid(`Provide ${key} as a non-empty string.`);
  }
  return value;
}

function whole(input: Json, key: string): string | undefined {
  const value = input[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw invalid(`Provide ${key} as a whole number.`);
  }
  return String(value);
}

/** A sink that keeps the start of the output and counts what it had to drop. */
function capture() {
  const chunks: Buffer[] = [];
  let kept = 0;
  let dropped = 0;
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      const room = Math.max(0, MAX_OUTPUT_BYTES - kept);
      chunks.push(chunk.subarray(0, room));
      kept += Math.min(room, chunk.length);
      dropped += Math.max(0, chunk.length - room);
      done();
    },
  });
  return {
    sink,
    result: () => ({
      // The redactor passes bytes through unchanged, so this is the command's own text.
      text: Buffer.concat(chunks).toString("utf8"),
      dropped,
    }),
  };
}

const TOOLS: Tool[] = [
  {
    name: "akb_status",
    description:
      "Whether the vault is unlocked. If it is locked, ask the user to run `akb auth unlock` in their own terminal; never ask for the master password.",
    inputSchema: { type: "object", properties: {} },
    call: (_input, deps) => deps.perform("status"),
  },
  {
    name: "akb_find",
    description:
      "Find logins without seeing their credentials. Give a url (a domain or address) to get the logins for that site, and/or a search text matching name, reference or username. Each result lists the credential fields it has.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "A domain or address, for example github.com." },
        search: { type: "string", description: "Matches name, reference or username." },
        trashed: {
          type: "boolean",
          description: "List deleted logins instead (with search, not url), to restore one.",
        },
      },
    },
    call: (input, deps) => {
      const url = text(input, "url");
      const search = text(input, "search");
      if (input.trashed !== undefined && typeof input.trashed !== "boolean") {
        throw invalid("Provide trashed as true or false.");
      }
      return deps.perform("list", {
        ...(url === undefined ? {} : { url }),
        ...(search === undefined ? {} : { search }),
        ...(input.trashed === true ? { trashed: "1" } : {}),
      });
    },
  },
  {
    name: "akb_show",
    description: "Describe one login: its fields and addresses, never their values.",
    inputSchema: { type: "object", properties: { ref: REF }, required: ["ref"] },
    call: (input, deps) => deps.perform("show", { ref: text(input, "ref", true) as string }),
  },
  {
    name: "akb_run",
    description:
      "Run a command with credentials in its environment. This is the only way to use a credential: you name the logins, AgentKeybox puts their values into environment variables for that command, and anything the command prints that contains a value is replaced with [REDACTED:NAME]. The command runs without a shell and without standard input. Pass the program and its arguments as separate items in `command`, and refer to values as environment variables.",
    inputSchema: {
      type: "object",
      properties: {
        env: {
          type: "array",
          minItems: 1,
          maxItems: 64,
          description: "Credentials to inject.",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "Environment variable name, e.g. GH_TOKEN." },
              ref: REF,
              field: {
                type: "string",
                description:
                  "password (default), username, notes, totp, private_key or public_key (SSH key items), or custom:<name>. totp injects the current code.",
              },
            },
            required: ["name", "ref"],
          },
        },
        command: {
          type: "array",
          minItems: 1,
          items: { type: "string" },
          description: "The program, then its arguments.",
        },
        timeout_seconds: {
          type: "integer",
          minimum: 1,
          maximum: MAX_TIMEOUT_SECONDS,
          description: `Default ${DEFAULT_TIMEOUT_SECONDS}.`,
        },
      },
      required: ["env", "command"],
    },
    call: async (input, deps) => {
      const env = input.env;
      const command = input.command;
      if (!Array.isArray(env) || !Array.isArray(command) || command.length === 0) {
        throw invalid("Provide env and command as lists.");
      }
      if (command.some((part) => typeof part !== "string" || part.length > 8192)) {
        throw invalid("Each command item must be a string.");
      }
      const specs = parseSecretSpecsPayload(
        JSON.stringify(
          env.map((entry: Json) => ({
            name: entry?.name,
            ref: entry?.ref,
            field: entry?.field ?? "password",
          })),
        ),
      );
      const seconds = Number(whole(input, "timeout_seconds") ?? DEFAULT_TIMEOUT_SECONDS);
      if (seconds < 1 || seconds > MAX_TIMEOUT_SECONDS) {
        throw invalid(`timeout_seconds must be from 1 to ${MAX_TIMEOUT_SECONDS}.`);
      }
      const out = capture();
      const err = capture();
      const exitCode = await deps.run(
        command as string[],
        specs,
        { out: out.sink, err: err.sink },
        seconds * 1000,
      );
      const stdout = out.result();
      const stderr = err.result();
      return {
        exit_code: exitCode,
        timed_out: exitCode === TIMEOUT_EXIT_CODE,
        stdout: stdout.text,
        stderr: stderr.text,
        ...(stdout.dropped + stderr.dropped > 0
          ? { truncated: `Output was cut after ${MAX_OUTPUT_BYTES} bytes per stream.` }
          : {}),
      };
    },
  },
  {
    name: "akb_passkey_assert",
    description:
      "Sign in to a site with a passkey stored in the vault. Give the login and the site's origin and challenge; you get back the signed response (credential id, client data, authenticator data, signature) to hand to the site. The private key never leaves the vault. It does not claim user verification, so a site that requires it will refuse.",
    inputSchema: {
      type: "object",
      properties: {
        ref: REF,
        origin: {
          type: "string",
          description: "The site's origin, for example https://example.com.",
        },
        challenge: { type: "string", description: "The site's challenge, as base64url text." },
      },
      required: ["ref", "origin", "challenge"],
    },
    call: (input, deps) =>
      deps.perform("assert", {
        ref: text(input, "ref", true) as string,
        origin: text(input, "origin", true) as string,
        challenge: text(input, "challenge", true) as string,
      }),
  },
  {
    name: "akb_passkey_create",
    description:
      "Create a passkey for a site and store it in an existing login that has none (make one with akb_create first). Give the origin, the site's challenge and user id as it sent them, and the user name; you get back the public answer (credential id, client data, attestation object, public key) to hand to the site. The private key never leaves the vault. It does not claim user verification. A login that already has a passkey is never overwritten.",
    write: true,
    inputSchema: {
      type: "object",
      properties: {
        ref: REF,
        origin: {
          type: "string",
          description: "The site's origin, for example https://example.com.",
        },
        challenge: { type: "string", description: "The site's challenge, as base64url text." },
        user_id: { type: "string", description: "The site's user id for this account, base64url." },
        user_name: {
          type: "string",
          description: "The user name the site shows for this account.",
        },
        display_name: { type: "string" },
        rp_id: { type: "string", description: "The site's id; defaults to the origin's host." },
        rp_name: { type: "string", description: "The site's name for itself." },
      },
      required: ["ref", "origin", "challenge", "user_id", "user_name"],
    },
    call: (input, deps) => {
      const optional = (key: string) => {
        const value = text(input, key);
        return value === undefined ? {} : { [key]: value };
      };
      return deps.perform("register", {
        ref: text(input, "ref", true) as string,
        origin: text(input, "origin", true) as string,
        challenge: text(input, "challenge", true) as string,
        user_id: text(input, "user_id", true) as string,
        user_name: text(input, "user_name", true) as string,
        ...optional("display_name"),
        ...optional("rp_id"),
        ...optional("rp_name"),
      });
    },
  },
  {
    name: "akb_create",
    description:
      "Create a login with a generated password, or an SSH key item with a generated Ed25519 key pair (type: ssh). You cannot choose the secret: it is stored without being shown, and you use it through akb_run. The reference must not be used by another item.",
    write: true,
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        ref: { type: "string", description: "New reference name (without the ref: prefix)." },
        type: {
          type: "string",
          enum: ["login", "ssh"],
          description: "Default login. ssh takes no username, urls or length.",
        },
        username: { type: "string" },
        urls: { type: "array", maxItems: 16, items: { type: "string" } },
        length: { type: "integer", minimum: 8, maximum: 128, description: "Default 24." },
      },
      required: ["name", "ref"],
    },
    call: (input, deps) => {
      const type = text(input, "type") ?? "login";
      if (type !== "login" && type !== "ssh") {
        throw invalid("Item type must be login or ssh.");
      }
      const urls = input.urls ?? [];
      if (!Array.isArray(urls) || urls.some((url) => typeof url !== "string")) {
        throw invalid("Provide urls as a list of strings.");
      }
      const username = text(input, "username");
      const length = whole(input, "length");
      if (type === "ssh") {
        if (username !== undefined || urls.length > 0 || length !== undefined) {
          throw invalid("Username, urls and length are for logins.");
        }
        return deps.perform("create", {
          type: "ssh",
          name: text(input, "name", true) as string,
          ref: text(input, "ref", true) as string,
          generate: "1",
        });
      }
      return deps.perform("create", {
        name: text(input, "name", true) as string,
        ref: text(input, "ref", true) as string,
        urls: JSON.stringify(urls),
        generate: "1",
        ...(username === undefined ? {} : { username }),
        ...(length === undefined ? {} : { length }),
      });
    },
  },
  {
    name: "akb_rotate",
    description:
      "Replace a login's password, or an SSH key item's key pair (field: private_key), with a newly generated one. The new value is stored without being shown.",
    write: true,
    inputSchema: {
      type: "object",
      properties: {
        ref: REF,
        field: {
          type: "string",
          enum: ["password", "private_key"],
          description: "Default password. private_key generates a new Ed25519 key pair.",
        },
        length: { type: "integer", minimum: 8, maximum: 128, description: "Default 24." },
      },
      required: ["ref"],
    },
    call: (input, deps) => {
      const field = text(input, "field") ?? "password";
      if (field !== "password" && field !== "private_key") {
        throw invalid("Field must be password or private_key.");
      }
      const length = whole(input, "length");
      if (field === "private_key" && length !== undefined) {
        throw invalid("Length is for passwords.");
      }
      return deps.perform("set", {
        ref: text(input, "ref", true) as string,
        field,
        generate: "1",
        ...(length === undefined ? {} : { length }),
      });
    },
  },
  {
    name: "akb_restore",
    description:
      "Bring a deleted login back from the trash. Find it with akb_find and trashed: true. Fails if its reference has been used again since.",
    write: true,
    inputSchema: { type: "object", properties: { ref: REF }, required: ["ref"] },
    call: (input, deps) => deps.perform("restore", { ref: text(input, "ref", true) as string }),
  },
  {
    name: "akb_delete",
    description:
      "Move a login to the vault's trash. It is not destroyed: its owner can restore it. Needs an exact reference.",
    write: true,
    inputSchema: { type: "object", properties: { ref: REF }, required: ["ref"] },
    call: (input, deps) => deps.perform("delete", { ref: text(input, "ref", true) as string }),
  },
];

export function toolNames(readOnly: boolean): string[] {
  return TOOLS.filter((tool) => !(readOnly && tool.write)).map((tool) => tool.name);
}

function reply(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function fault(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

/** Errors are shown to the model, so they are the fixed messages AKB already returns. */
function toolFailure(error: unknown) {
  const known = error instanceof AkbError;
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify({
          code: known ? error.code : "INTERNAL_ERROR",
          message: known ? error.message : "Operation failed; no upstream payload was logged.",
        }),
      },
    ],
  };
}

/** Handle one JSON-RPC message. Notifications produce no response. */
export async function handleMessage(message: unknown, deps: McpDeps): Promise<Json | undefined> {
  const request = message as Json | null;
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return fault(null, -32600, "Invalid request.");
  }
  const { id, method } = request;
  const notification = id === undefined;
  if (typeof method !== "string") {
    return notification ? undefined : fault(id, -32600, "Invalid request.");
  }
  const params = (request.params ?? {}) as Json;
  switch (method) {
    case "initialize": {
      const wanted = params.protocolVersion;
      return reply(id, {
        protocolVersion: SUPPORTED_VERSIONS.includes(wanted as string)
          ? wanted
          : SUPPORTED_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: "agentkeybox", version: deps.version },
        instructions:
          "AgentKeybox never returns credential values. Find logins with akb_find, and use them through akb_run.",
      });
    }
    case "ping":
      return reply(id, {});
    case "tools/list":
      return reply(id, {
        tools: TOOLS.filter((tool) => !(deps.readOnly && tool.write)).map(
          ({ name, description, inputSchema }) => ({ name, description, inputSchema }),
        ),
      });
    case "tools/call": {
      const tool = TOOLS.find((candidate) => candidate.name === params.name);
      if (!tool || (deps.readOnly && tool.write)) {
        return fault(id, -32602, "Unknown tool.");
      }
      const input = params.arguments ?? {};
      if (!input || typeof input !== "object" || Array.isArray(input)) {
        return reply(id, toolFailure(invalid("Arguments must be an object.")));
      }
      try {
        const data = await tool.call(input as Json, deps);
        return reply(id, { content: [{ type: "text", text: JSON.stringify(data) }] });
      } catch (error) {
        return reply(id, toolFailure(error));
      }
    }
    default:
      // Notifications such as notifications/initialized need no answer.
      return notification ? undefined : fault(id, -32601, "Method not found.");
  }
}

/** Read newline-delimited JSON-RPC from `input` and write responses to `output`. */
export function serveMcp(
  input: NodeJS.ReadableStream,
  output: Writable,
  deps: McpDeps,
): Promise<void> {
  return new Promise((resolve) => {
    let buffer = "";
    let pending = 0;
    let ended = false;
    const finish = () => {
      if (ended && pending === 0) {
        resolve();
      }
    };
    const send = (message: Json) => output.write(JSON.stringify(message) + "\n");
    const handleLine = (line: string) => {
      if (!line.trim()) {
        return;
      }
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        send(fault(null, -32700, "Parse error."));
        return;
      }
      // Calls run side by side; the vault serializes them where it must.
      pending++;
      void handleMessage(message, deps)
        .then((response) => response && send(response))
        .finally(() => {
          pending--;
          finish();
        });
    };
    input.setEncoding?.("utf8");
    input.on("data", (chunk: string) => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > MAX_MESSAGE_BYTES) {
        buffer = "";
        send(fault(null, -32600, "Message too large."));
        return;
      }
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        handleLine(buffer.slice(0, newline));
        buffer = buffer.slice(newline + 1);
      }
    });
    input.on("end", () => {
      handleLine(buffer);
      ended = true;
      finish();
    });
  });
}
