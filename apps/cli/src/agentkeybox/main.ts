import "core-js/proposals/explicit-resource-management";

import { Command, CommanderError } from "commander";
import * as inquirer from "inquirer";

import { fileAudit } from "./audit";
import { serveMcp } from "./mcp";
import { foreground, performer, runCommand, serialized } from "./operations";
import { loadPolicy, noSessionLimits, parseDuration, savePolicy } from "./policy";
import { AkbError, failure, parseSecretSpecs, Reply } from "./protocol";
import { requireActiveScreen, screenState } from "./screen";
import { call, connect, locations, profileDirectory, serve } from "./transport";

const windows = process.platform === "win32";

const program = new Command("akb")
  .description("AgentKeybox: source-based Bitwarden client for Vaultwarden (MVP)")
  .version("0.1.0-dev (Bitwarden cli-v2026.11.0)")
  .option("--profile <name>", "Isolated vault profile", "default")
  .option("--json", "Machine-readable output; never prompt")
  .option("--no-input", "Never prompt")
  .exitOverride();

function print(reply: Reply, raw = false) {
  if (!reply.ok) {
    process.exitCode = reply.error.exit_code;
  }
  if (raw && reply.ok) {
    process.stdout.write((reply.data as { value: string }).value);
  } else if (program.opts().json || reply.ok) {
    process.stdout.write(JSON.stringify(reply) + "\n");
  } else {
    process.stderr.write(`${reply.error.code}: ${reply.error.message}\n`);
  }
}

function request(operation: string, args: Record<string, string> = {}): Promise<unknown> {
  return performer(program.opts().profile)(operation, args);
}

async function send(operation: string, args: Record<string, string> = {}, raw = false) {
  print({ schema_version: 1, ok: true, data: await request(operation, args) }, raw);
}

async function password(fromStdin: boolean): Promise<string> {
  if (foreground) {
    requireActiveScreen(await screenState());
  }
  if (fromStdin) {
    let value = "";
    for await (const chunk of process.stdin) {
      value += chunk.toString();
      if (Buffer.byteLength(value) > 16384) {
        throw new AkbError("INPUT_TOO_LARGE", "Password input exceeds limit.", 2);
      }
    }
    return value.replace(/\r?\n$/, "");
  }
  if (program.opts().json || program.opts().input === false || !process.stdin.isTTY) {
    throw new AkbError(
      "INPUT_REQUIRED",
      "Use --password-stdin or run interactively in your terminal.",
      2,
    );
  }
  const answer = await inquirer.createPromptModule({ output: process.stderr })({
    type: "password",
    name: "password",
    message: "Vault master password:",
  });
  return answer.password;
}

program.command("status").action(() => send("status"));
program.command("sync").action(() => send("sync"));
program
  .command("config")
  .command("server <url>")
  .action((server: string) => send("configure", { server }));
const auth = program.command("auth").description("Login and local unlock session");
auth.command("status").action(() => send("status"));
auth
  .command("login")
  .requiredOption("--email <email>")
  .option("--password-stdin", "Read password from stdin")
  .option("--method <number>", "Bitwarden two-factor provider number")
  .option("--code <code>", "Two-factor code")
  .action(async (options) => {
    const args: Record<string, string> = {
      email: options.email,
      password: await password(options.passwordStdin),
    };
    if (options.method) {
      args.method = options.method;
    }
    if (options.code) {
      args.code = options.code;
    }
    await send("login", args);
  });
auth
  .command("unlock")
  .option("--password-stdin")
  .action(async (options) => send("unlock", { password: await password(options.passwordStdin) }));
auth.command("lock").action(() => send("lock"));
auth.command("logout").action(() => send("logout"));
const account = program
  .command("account")
  .description("Discover accounts without exposing credentials");
account
  .command("list")
  .option("--search <text>", "Match name, reference or username")
  .option("--url <url>", "Only logins that match this address, using the vault's domain rules")
  .option("--trashed", "List deleted logins instead, so one can be restored")
  .action((options) =>
    send("list", {
      ...(options.search ? { search: options.search } : {}),
      ...(options.url === undefined ? {} : { url: options.url }),
      ...(options.trashed ? { trashed: "1" } : {}),
    }),
  );
account.command("show <ref>").action((ref: string) => send("show", { ref }));
program
  .command("credential")
  .command("get <ref>")
  .requiredOption(
    "--field <name>",
    "password, username, notes, private_key, public_key, totp, custom:<name>",
  )
  .option("--raw", "Output only the value, with no trailing newline")
  .action((ref: string, options) => {
    if (options.raw && program.opts().json) {
      throw new AkbError("INVALID_OPTIONS", "--raw and --json are mutually exclusive.", 2);
    }
    return send("get", { ref, field: options.field }, options.raw);
  });
program
  .command("run")
  .description("Run a command with credentials injected as environment variables")
  .usage("--env NAME=<ref>[#field] [--env ...] -- <command> [args...]")
  .requiredOption(
    "--env <NAME=ref>",
    "Inject a credential: NAME=ref:<name> or NAME=id:<uuid>, optional #field (default password)",
    (value: string, previous: string[]) => [...previous, value],
    [],
  )
  .argument("<command...>", "Command to run, after --")
  .action(async (command: string[], options: { env: string[] }) => {
    // Values are never printed by AKB. The command's own output is filtered before it is shown.
    process.exitCode = await runCommand(
      performer(program.opts().profile),
      fileAudit(profileDirectory(program.opts().profile)),
      (message) => process.stderr.write(`${message}\n`),
      command,
      parseSecretSpecs(options.env),
    );
  });
const passkeys = program
  .command("passkey")
  .description("Create passkeys and sign in with them; the private key never leaves the vault");
passkeys
  .command("create <ref>")
  .description(
    "Create a passkey for a site and store it in an existing login that has none. Prints the public answer for the site.",
  )
  .requiredOption("--origin <url>", "The site's origin, for example https://example.com")
  .requiredOption("--challenge <base64url>", "The challenge the site sent, as base64url text")
  .requiredOption("--user-id <base64url>", "The site's user id for this account, as base64url text")
  .requiredOption("--user-name <name>", "The user name the site shows for this account")
  .option("--display-name <name>", "The display name the site shows")
  .option("--rp-id <host>", "The site's id; defaults to the origin's host")
  .option("--rp-name <name>", "The site's name for itself")
  .action(
    (
      ref: string,
      options: {
        origin: string;
        challenge: string;
        userId: string;
        userName: string;
        displayName?: string;
        rpId?: string;
        rpName?: string;
      },
    ) =>
      send("register", {
        ref,
        origin: options.origin,
        challenge: options.challenge,
        user_id: options.userId,
        user_name: options.userName,
        ...(options.displayName === undefined ? {} : { display_name: options.displayName }),
        ...(options.rpId === undefined ? {} : { rp_id: options.rpId }),
        ...(options.rpName === undefined ? {} : { rp_name: options.rpName }),
      }),
  );
passkeys
  .command("assert <ref>")
  .description(
    "Sign a site's challenge with the passkey of a login. Prints the signed response a browser would send.",
  )
  .requiredOption("--origin <url>", "The site's origin, for example https://example.com")
  .requiredOption("--challenge <base64url>", "The challenge the site sent, as base64url text")
  .action((ref: string, options: { origin: string; challenge: string }) =>
    send("assert", { ref, origin: options.origin, challenge: options.challenge }),
  );
program
  .command("mcp")
  .description(
    "Serve AgentKeybox to an AI agent over MCP (standard input and output). No tool returns a credential value.",
  )
  .option("--read-only", "Offer only discovery and run; no create, rotate or delete")
  .action(async (options: { readOnly?: boolean }) => {
    const profile: string = program.opts().profile;
    const audit = fileAudit(profileDirectory(profile));
    const perform = serialized(performer(profile));
    await serveMcp(process.stdin, process.stdout, {
      perform,
      readOnly: options.readOnly === true,
      version: "0.1.0-dev",
      // Standard output belongs to the protocol, and a service has no input to pass on.
      run: (command, specs, sinks, timeoutMs) =>
        runCommand(perform, audit, () => {}, command, specs, sinks, {
          stdin: "ignore",
          timeoutMs,
        }),
    });
  });
/** Read a value from standard input. The value is never taken from a command-line argument. */
async function readValue(): Promise<string> {
  let value = "";
  for await (const chunk of process.stdin) {
    value += chunk.toString();
    if (Buffer.byteLength(value) > 65536) {
      throw new AkbError("INPUT_TOO_LARGE", "Value exceeds the size limit.", 2);
    }
  }
  return value.replace(/\r?\n$/, "");
}

const item = program.command("item").description("Create and change vault items");
item
  .command("create")
  .description(
    "Create a login or SSH key item. Secret values are read from standard input or generated, and are never printed.",
  )
  .requiredOption("--name <name>", "Item name")
  .requiredOption("--ref <name>", "Reference for ref:<name>; must not be used by another item")
  .option("--type <type>", "Item type: login (default) or ssh", "login")
  .option("--username <username>")
  .option(
    "--url <url>",
    "Address the login is for; may be repeated",
    (value: string, previous: string[]) => [...previous, value],
    [],
  )
  .option("--password-stdin", "Read the password from standard input")
  .option("--generate-password", "Generate a password and store it without showing it")
  .option("--length <number>", "Generated password length, 8 to 128 (default 24)")
  .option("--private-key-stdin", "Read an SSH private key from standard input (ssh type)")
  .option(
    "--generate-key",
    "Generate an Ed25519 key pair and store it without showing it (ssh type)",
  )
  .action(async (options) => {
    if (options.type === "ssh") {
      if (
        options.username !== undefined ||
        options.url.length > 0 ||
        options.passwordStdin ||
        options.generatePassword ||
        options.length !== undefined
      ) {
        throw new AkbError(
          "INVALID_OPTIONS",
          "Username, url, password and length options are for logins.",
          2,
        );
      }
      if (options.privateKeyStdin && options.generateKey) {
        throw new AkbError(
          "INVALID_OPTIONS",
          "Use either --private-key-stdin or --generate-key.",
          2,
        );
      }
      await send("create", {
        type: "ssh",
        name: options.name,
        ref: options.ref,
        ...(options.privateKeyStdin ? { privateKey: await readValue() } : {}),
        ...(options.generateKey ? { generate: "1" } : {}),
      });
      return;
    }
    if (options.type !== "login") {
      throw new AkbError("INVALID_ARGUMENT", "Item type must be login or ssh.", 2);
    }
    if (options.privateKeyStdin || options.generateKey) {
      throw new AkbError("INVALID_OPTIONS", "Key options need --type ssh.", 2);
    }
    if (options.passwordStdin && options.generatePassword) {
      throw new AkbError(
        "INVALID_OPTIONS",
        "Use either --password-stdin or --generate-password.",
        2,
      );
    }
    await send("create", {
      name: options.name,
      ref: options.ref,
      urls: JSON.stringify(options.url),
      ...(options.username === undefined ? {} : { username: options.username }),
      ...(options.passwordStdin ? { password: await readValue() } : {}),
      ...(options.generatePassword ? { generate: "1" } : {}),
      ...(options.length === undefined ? {} : { length: options.length }),
    });
  });
item
  .command("set <ref>")
  .description("Change one field of an item and leave the rest of the item as it is")
  .requiredOption("--field <name>", "password, username, notes, totp, private_key, custom:<name>")
  .option("--stdin", "Read the new value from standard input")
  .option("--generate", "Generate a new value (password or private_key field only)")
  .option("--length <number>", "Generated password length, 8 to 128 (default 24)")
  .action(async (ref: string, options) => {
    if (options.stdin && options.generate) {
      throw new AkbError("INVALID_OPTIONS", "Use either --stdin or --generate.", 2);
    }
    await send("set", {
      ref,
      field: options.field,
      ...(options.stdin ? { value: await readValue() } : {}),
      ...(options.generate ? { generate: "1" } : {}),
      ...(options.length === undefined ? {} : { length: options.length }),
    });
  });
item
  .command("restore <ref>")
  .description("Bring a deleted login back from the trash. Needs an exact ref.")
  .action((ref: string) => send("restore", { ref }));
item
  .command("delete <ref>")
  .description("Move a login to the vault's trash, where it can be restored. Needs an exact ref.")
  .action((ref: string) => send("delete", { ref }));
const policy = program
  .command("session")
  .command("policy")
  .description("Persistent per-profile auto-lock policy");
policy.command("show").action(async () => {
  if (foreground) {
    print({
      schema_version: 1,
      ok: true,
      data: {
        ...loadPolicy(profileDirectory(program.opts().profile), noSessionLimits),
        screen_state: await screenState(),
      },
    });
    return;
  }
  const { dir } = locations(program.opts().profile);
  print({ schema_version: 1, ok: true, data: loadPolicy(dir) });
});
policy
  .command("set")
  .option("--idle <duration>", "Idle timeout, e.g. 30m or never")
  .option("--max <duration>", "Maximum unlock lifetime, e.g. 12h or never")
  .action(async (options) => {
    if (!options.idle && !options.max) {
      throw new AkbError("INPUT_REQUIRED", "Specify --idle and/or --max.", 2);
    }
    if (foreground) {
      // Each command reads this file, so there is no service to restart. The desktop lock
      // still ends access; these limits end it sooner.
      const dir = profileDirectory(program.opts().profile);
      const value = loadPolicy(dir, noSessionLimits);
      if (options.idle) {
        value.idle_ms = parseDuration(options.idle);
      }
      if (options.max) {
        value.max_ms = parseDuration(options.max);
      }
      savePolicy(dir, value);
      print({ schema_version: 1, ok: true, data: { policy: value, applied: true } });
      return;
    }
    const profile = program.opts().profile;
    const { dir } = locations(profile);
    const value = loadPolicy(dir);
    if (options.idle) {
      value.idle_ms = parseDuration(options.idle);
    }
    if (options.max) {
      value.max_ms = parseDuration(options.max);
    }
    savePolicy(dir, value);
    const socket = await connect(profile);
    const reply = await call(socket, { operation: "status" });
    if (!reply.ok) {
      print(reply);
      return;
    }
    const applied =
      JSON.stringify((reply.data as { session_policy?: unknown }).session_policy) ===
      JSON.stringify(value);
    print({
      schema_version: 1,
      ok: true,
      data: {
        policy: value,
        applied,
        restart_required: !applied,
        message: applied
          ? "Policy saved and applied to the running service."
          : "Policy saved. Old service requires one restart and unlock; current session was preserved.",
      },
    });
  });
if (!windows) {
  const service = program
    .command("service")
    .description(
      process.platform === "darwin"
        ? "Stop an older AKB background service"
        : "Local session process",
    );
  if (process.platform !== "darwin") {
    service.command("start").action(() => send("status"));
    service.command("status").action(async () => {
      const socket = await connect(program.opts().profile, false);
      print(await call(socket, { operation: "status" }));
    });
    service
      .command("serve")
      .description("Run the session service in the foreground")
      .action(() => serve(program.opts().profile));
  }
  service.command("stop").action(async () => {
    try {
      await send("stop");
    } catch (error) {
      if (
        process.platform !== "darwin" ||
        !(error instanceof AkbError) ||
        error.code !== "SERVICE_STOPPED"
      ) {
        throw error;
      }
      print({ schema_version: 1, ok: true, data: { status: "stopped" } });
    }
  });
}

void program.parseAsync().catch((error: unknown) => {
  if (error instanceof CommanderError) {
    process.exitCode = error.exitCode;
    if (error.exitCode && program.opts().json) {
      print(failure(new AkbError("INVALID_ARGUMENT", "Invalid command arguments; see --help.", 2)));
    }
  } else {
    print(failure(error));
  }
  // A startup failure may leave upstream timers alive; release the profile on exit.
  if (process.argv.includes("service") && process.argv.includes("serve")) {
    process.exit(process.exitCode || 1);
  }
});
