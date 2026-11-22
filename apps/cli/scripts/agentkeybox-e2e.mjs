// Real local Vaultwarden integration. All accounts, secrets and data are disposable.
// The crypto below constructs an independent test fixture only; akb uses upstream crypto.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import {
  createCipheriv,
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
  randomUUID,
  verify,
} from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import * as https from "node:https";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const windows = process.platform === "win32";
const foreground = windows || process.platform === "darwin";
const helperName = windows ? "akb-credentials.exe" : "akb-keychain";
let binary = process.env.AKB_TEST_BINARY && path.resolve(process.env.AKB_TEST_BINARY);
const cli = fileURLToPath(new URL("../build-akb/akb.js", import.meta.url));
const home = mkdtempSync(path.join(tmpdir(), "akb-e2e-"));
const name = `akb-e2e-${process.pid}`;
const tlsDir = path.join(home, "tls");
mkdirSync(tlsDir, { mode: 0o700 });
const certPath = path.join(tlsDir, "cert.pem");
// When this script itself runs inside a container, a published loopback port is not reachable.
// Then Vaultwarden is given a fixed address on a Docker network that the container has joined.
const vaultIp = process.env.AKB_TEST_VAULT_IP;
const vaultNetwork = process.env.AKB_TEST_DOCKER_NETWORK;
if (Boolean(vaultIp) !== Boolean(vaultNetwork)) {
  throw new Error("Set AKB_TEST_VAULT_IP and AKB_TEST_DOCKER_NETWORK together, or neither.");
}
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    path.join(tlsDir, "key.pem"),
    "-out",
    certPath,
    "-subj",
    "/CN=localhost",
    "-addext",
    `subjectAltName=DNS:localhost,IP:127.0.0.1${vaultIp ? `,IP:${vaultIp}` : ""}`,
  ],
  { stdio: "pipe" },
);
const ca = readFileSync(certPath);
function fixtureFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body?.toString();
    const request = https.request(
      url,
      {
        method: options.method || "GET",
        ca,
        headers: {
          ...(body ? { "Content-Length": Buffer.byteLength(body) } : {}),
          ...(options.body instanceof URLSearchParams
            ? { "Content-Type": "application/x-www-form-urlencoded" }
            : {}),
          ...options.headers,
        },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("error", reject);
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            ok: response.statusCode >= 200 && response.statusCode < 300,
            text: async () => text,
            json: async () => JSON.parse(text),
          }),
        );
      },
    );
    request.on("error", reject);
    request.setTimeout(10000, () => request.destroy(new Error("Fixture request timeout")));
    request.end(body);
  });
}
const image =
  "vaultwarden/server@sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f";
const env = {
  ...process.env,
  AKB_HOME: home,
  NODE_EXTRA_CA_CERTS: certPath,
  AKB_IDLE_MS: "300000",
  AKB_MAX_MS: "3600000",
};
delete env.BW_SESSION;
if (binary) {
  const relocated = path.join(home, "standalone with spaces");
  mkdirSync(relocated);
  const cliName = windows ? "akb.exe" : "akb";
  copyFileSync(path.join(path.dirname(binary), helperName), path.join(relocated, helperName));
  copyFileSync(binary, path.join(relocated, cliName));
  binary = path.join(relocated, cliName);
  if (!windows) chmodSync(binary, 0o755);
  delete env.NODE_PATH;
  delete env.NODE_OPTIONS;
  // Only OS utilities are available: the product cannot find node, npm or bw in PATH.
  for (const name of Object.keys(env)) {
    if (name.toLowerCase() === "path") delete env[name];
  }
  env.PATH = windows ? path.join(process.env.SystemRoot, "System32") : "/usr/bin:/bin";
  console.log("Testing standalone binary with Node/npm/bw excluded from PATH");
}
const email = `akb-${randomUUID()}@example.test`;
const password = randomBytes(32).toString("base64");
const secret = randomBytes(24).toString("base64");
// An independent RFC 6238 implementation: it only checks what akb returns, akb does not use it.
const totpKey = randomBytes(20);
const base32 = (buffer) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");
  return bits
    .match(/.{1,5}/g)
    .map((chunk) => alphabet[parseInt(chunk.padEnd(5, "0"), 2)])
    .join("");
};
const totpSeed = base32(totpKey);
const totpAt = (seconds) => {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(seconds / 30)));
  const digest = createHmac("sha1", totpKey).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
};
const loginUri = "https://example.test/login?next=path-that-must-not-be-shown";
let count = 0;
const pass = (name) => {
  count++;
  console.log(`PASS ${name}`);
};

async function akb(args, input, expected = 0) {
  let result;
  try {
    result = await new Promise((resolve, reject) => {
      const child = execFile(
        binary || process.execPath,
        binary ? args : [cli, ...args],
        {
          env,
          cwd: binary ? home : undefined,
          windowsHide: true,
          timeout: 90000,
          maxBuffer: 2 ** 20,
        },
        (error, stdout, stderr) =>
          error ? reject({ code: error.code, stdout, stderr }) : resolve({ stdout, stderr }),
      );
      child.stdin.end(input ?? "");
    });
    assert.equal(expected, 0);
  } catch (error) {
    assert.equal(
      error.code,
      expected,
      `Unexpected CLI exit ${error.code}: ${error.stdout || error.stderr}`,
    );
    result = error;
  }
  // `--raw` and `run` write something other than an AKB JSON reply to stdout.
  const plain = args.includes("--raw") || args.includes("run");
  return { ...result, json: plain ? undefined : JSON.parse(result.stdout) };
}

/** Talk to `akb mcp` the way an agent harness does: JSON-RPC lines in, JSON-RPC lines out. */
async function mcp(messages, extraArgs = []) {
  const child = spawn(binary || process.execPath, [...(binary ? [] : [cli]), "mcp", ...extraArgs], {
    env,
    cwd: binary ? home : undefined,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const closed = new Promise((resolve) => child.once("close", resolve));
  const timer = setTimeout(() => child.kill(), 120_000);
  child.stdin.end(messages.map((message) => JSON.stringify(message)).join("\n") + "\n");
  await closed;
  clearTimeout(timer);
  const replies = new Map();
  for (const line of stdout.split("\n").filter(Boolean)) {
    const reply = JSON.parse(line); // Standard output carries nothing but protocol messages.
    replies.set(reply.id, reply);
  }
  return { replies, stdout, stderr };
}

const toolCall = (id, name, args) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: args },
});
const toolBody = (reply) => JSON.parse(reply.result.content[0].text);

async function waitForWindowsScreen(status) {
  const helper = path.join(binary ? path.dirname(binary) : path.dirname(cli), helperName);
  const until = Date.now() + 180_000;
  while (Date.now() < until) {
    const exit = await exec(helper, ["screen"], { env, windowsHide: true, timeout: 5000 }).then(
      () => 0,
      (error) => error.code,
    );
    if (exit === status) return;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error(`Windows screen transition not observed (expected status ${status})`);
}

function encrypt(value, key) {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const data = Buffer.concat([cipher.update(value), cipher.final()]);
  const mac = createHmac("sha256", key.subarray(32))
    .update(Buffer.concat([iv, data]))
    .digest();
  return `2.${iv.toString("base64")}|${data.toString("base64")}|${mac.toString("base64")}`;
}

try {
  execFileSync(
    "docker",
    [
      "run",
      "-d",
      "--rm",
      "--name",
      name,
      ...(vaultIp ? ["--network", vaultNetwork, "--ip", vaultIp] : ["-p", "127.0.0.1::80"]),
      "-e",
      "I_REALLY_WANT_VOLATILE_STORAGE=true",
      "-e",
      "SIGNUPS_ALLOWED=true",
      "-e",
      "SIGNUPS_VERIFY=false",
      "-e",
      "LOGIN_RATELIMIT_MAX_BURST=100",
      "-v",
      `${tlsDir}:/tls:ro`,
      "-e",
      'ROCKET_TLS={certs="/tls/cert.pem",key="/tls/key.pem"}',
      "-e",
      "DOMAIN=https://localhost",
      "-e",
      "LOG_LEVEL=error",
      image,
    ],
    { stdio: "pipe" },
  );
  const binding = vaultIp
    ? `${vaultIp}:80`
    : execFileSync("docker", ["port", name, "80/tcp"], { encoding: "utf8" }).trim();
  const base = `https://${binding}`;
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fixtureFetch(`${base}/alive`)).ok) {
        break;
      }
    } catch {}
    if (i === 99) {
      throw new Error("Vaultwarden did not become ready");
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  async function api(route, data, token) {
    const response = await fixtureFetch(base + route, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      throw new Error(`Fixture request ${route}: HTTP ${response.status}`);
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }
  const master = pbkdf2Sync(password, email, 600000, 32, "sha256");
  const hash = pbkdf2Sync(master, password, 1, 32, "sha256").toString("base64");
  const stretch = Buffer.concat(
    ["enc", "mac"].map((info) =>
      createHmac("sha256", master)
        .update(Buffer.concat([Buffer.from(info), Buffer.from([1])]))
        .digest(),
    ),
  );
  const userKey = randomBytes(64);
  const keys = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  const verification = await api("/identity/accounts/register/send-verification-email", {
    email,
    name: "AKB E2E",
  });
  await api("/identity/accounts/register/finish", {
    email,
    emailVerificationToken: verification,
    masterPasswordHash: hash,
    key: encrypt(userKey, stretch),
    kdf: 0,
    kdfIterations: 600000,
    keys: {
      publicKey: keys.publicKey.toString("base64"),
      encryptedPrivateKey: encrypt(keys.privateKey, userKey),
    },
  });
  const response = await fixtureFetch(`${base}/identity/connect/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "password",
      username: email,
      password: hash,
      scope: "api offline_access",
      client_id: "cli",
      deviceType: "23",
      deviceIdentifier: randomUUID(),
      deviceName: "AKB Fixture",
    }),
  });
  assert.equal(response.status, 200, "Fixture authentication failed");
  const { access_token: token } = await response.json();
  const userId = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).sub;
  const seed = {
    encryptedFor: userId,
    type: 1,
    name: encrypt(Buffer.from("AKB Fixture"), userKey),
    login: {
      username: encrypt(Buffer.from("fixture-user"), userKey),
      password: encrypt(Buffer.from(secret), userKey),
      totp: encrypt(Buffer.from(totpSeed), userKey),
      uris: [{ uri: encrypt(Buffer.from(loginUri), userKey), match: null }],
    },
    fields: [
      {
        type: 0,
        name: encrypt(Buffer.from("agentkeybox.ref"), userKey),
        value: encrypt(Buffer.from("test/account"), userKey),
      },
    ],
    favorite: false,
    reprompt: 0,
  };
  const item = await api("/api/ciphers", seed, token);
  // A passkey: a real P-256 key the test keeps the public half of, to check signatures.
  const passkeyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const passkeyCredentialId = randomBytes(16);
  const passkeyRp = "example.test";
  const passkeyField = (value) => encrypt(Buffer.from(String(value)), userKey);
  await api(
    "/api/ciphers",
    {
      encryptedFor: userId,
      type: 1,
      name: encrypt(Buffer.from("AKB Passkey"), userKey),
      login: {
        username: encrypt(Buffer.from("passkey-user"), userKey),
        fido2Credentials: [
          {
            credentialId: passkeyField("b64." + passkeyCredentialId.toString("base64url")),
            keyType: passkeyField("public-key"),
            keyAlgorithm: passkeyField("ECDSA"),
            keyCurve: passkeyField("P-256"),
            keyValue: passkeyField(
              passkeyPair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
            ),
            rpId: passkeyField(passkeyRp),
            rpName: passkeyField("Example"),
            userHandle: passkeyField(randomBytes(16).toString("base64url")),
            userName: passkeyField("passkey-user"),
            userDisplayName: passkeyField("Passkey User"),
            counter: passkeyField("0"),
            discoverable: passkeyField("true"),
            creationDate: new Date().toISOString(),
          },
        ],
      },
      fields: [
        {
          type: 0,
          name: encrypt(Buffer.from("agentkeybox.ref"), userKey),
          value: encrypt(Buffer.from("test/passkey"), userKey),
        },
      ],
      favorite: false,
      reprompt: 0,
    },
    token,
  );
  const ref = `id:${item.id}`;
  assert.ok(item.id);
  pass("temporary Vaultwarden account and independently encrypted fixture");

  await akb(["config", "server", "http://localhost", "--json"], undefined, 2);
  await akb(["config", "server", base, "--json"]);
  const rejected = await akb(
    ["auth", "login", "--email", email, "--password-stdin", "--json"],
    "wrong-password",
    3,
  );
  assert.equal(rejected.json.error.code, "LOGIN_FAILED");
  assert.equal((await akb(["status", "--json"])).json.data.status, "unauthenticated");
  pass("HTTPS required and failed login leaves no active account");
  assert.equal(
    (await akb(["auth", "login", "--email", email, "--password-stdin", "--json"], password)).json
      .data.status,
    "unlocked",
  );
  pass("source-integrated login (no bw process)");
  assert.equal((await akb(["auth", "status", "--json"])).json.data.status, "unlocked");
  pass("separate CLI calls restore the unlocked session");
  if (foreground) {
    assert.equal((await akb(["status", "--json"])).json.data.screen_state, "unlocked");
    pass("CLI recognizes the active desktop session");
  }
  await akb(["sync", "--json"]);
  const list = await akb(["account", "list", "--json"]);
  const fixtureEntry = list.json.data.find((entry) => entry.ref === "test/account");
  assert.equal(fixtureEntry?.name, "AKB Fixture", "Fixture reference must survive sync");
  assert.equal(list.json.data.length, 2, "The account and the passkey login are listed");
  assert.ok(!list.stdout.includes(secret));
  assert.equal(
    (await akb(["credential", "get", "ref:test/account", "--field", "password", "--raw"])).stdout,
    secret,
  );
  pass("sync, redacted discovery, exact reference and plaintext field retrieval");
  for (let i = 0; i < 10; i++) {
    assert.equal(
      (await akb(["credential", "get", "ref:test/account", "--field", "password", "--raw"])).stdout,
      secret,
    );
  }
  pass("ten consecutive fresh sync and field reads");

  // `akb run` injects values into the child process and never prints them itself. The child
  // is the test runner's own Node, started by absolute path because PATH may be restricted.
  const injected = await akb([
    "run",
    "--env",
    "TOKEN=ref:test/account",
    "--env",
    "FIXTURE_USER=ref:test/account#username",
    "--",
    process.execPath,
    "-e",
    `process.stdout.write(String(process.env.TOKEN === ${JSON.stringify(secret)} && ` +
      `process.env.FIXTURE_USER === "fixture-user") + "|"); console.log(process.env.TOKEN)`,
  ]);
  assert.equal(
    injected.stdout,
    "true|[REDACTED:TOKEN]\n",
    "Child sees exact values; output is redacted",
  );
  assert.ok(!injected.stdout.includes(secret) && !injected.stderr.includes(secret));
  await akb(
    ["run", "--env", "TOKEN=ref:test/account", "--", process.execPath, "-e", "process.exit(3)"],
    undefined,
    3,
  );
  const unresolved = await akb(
    [
      "--json",
      "run",
      "--env",
      "TOKEN=ref:test/missing",
      "--",
      process.execPath,
      "-e",
      "console.log('ran')",
    ],
    undefined,
    5,
  );
  assert.equal(JSON.parse(unresolved.stdout).error.code, "NOT_FOUND");
  assert.ok(
    !unresolved.stdout.includes("ran"),
    "A command is never started when a reference fails",
  );
  pass("run injects exact values, redacts output, passes exit codes and fails closed");

  const matched = await akb([
    "account",
    "list",
    "--url",
    "https://example.test/anything",
    "--json",
  ]);
  assert.equal(matched.json.data.length, 1);
  assert.deepEqual(matched.json.data[0].uris, ["https://example.test"]);
  assert.ok(matched.json.data[0].credential_fields.includes("totp"));
  for (const hidden of ["path-that-must-not-be-shown", secret, totpSeed]) {
    assert.ok(!matched.stdout.includes(hidden), "Discovery output never includes secrets or paths");
  }
  assert.deepEqual((await akb(["account", "list", "--url", "other.test", "--json"])).json.data, []);
  await akb(["account", "list", "--url", "http://", "--json"], undefined, 2);
  pass("account list --url matches by vault domain rules and reveals only origins");

  const before = Math.floor(Date.now() / 1000);
  const otp = await akb(["credential", "get", "ref:test/account", "--field", "totp", "--json"]);
  const after = Math.floor(Date.now() / 1000);
  assert.ok(
    [totpAt(before), totpAt(after)].includes(otp.json.data.value),
    "TOTP code matches an independent RFC 6238 computation",
  );
  assert.ok(otp.json.data.expires_in >= 1 && otp.json.data.expires_in <= 30);
  const injectedOtp = await akb([
    "run",
    "--env",
    "OTP=ref:test/account#totp",
    "--",
    process.execPath,
    "-e",
    "process.stdout.write(/^\\d{6}$/.test(process.env.OTP) ? 'ok|' : 'bad|'); console.log(process.env.OTP)",
  ]);
  assert.equal(injectedOtp.stdout, "ok|[REDACTED:OTP]\n");
  pass("totp is exact, reports its lifetime, and can be injected without being shown");

  // Writes go through the upstream SDK. Generated and rotated values are only ever read back
  // with an explicit `credential get`; the write commands themselves never print them.
  const created = await akb([
    "item",
    "create",
    "--name",
    "AKB Created",
    "--ref",
    "test/created",
    "--username",
    "bot",
    "--url",
    "created.test",
    "--generate-password",
    "--length",
    "32",
    "--json",
  ]);
  assert.equal(created.json.data.created, true);
  assert.equal(created.json.data.ref, "test/created");
  assert.deepEqual(created.json.data.uris, ["https://created.test"]);
  const generated = (
    await akb(["credential", "get", "ref:test/created", "--field", "password", "--raw"])
  ).stdout;
  assert.equal(generated.length, 32);
  assert.ok(!created.stdout.includes(generated), "Create never prints the generated password");
  assert.equal(
    (await akb(["credential", "get", "ref:test/created", "--field", "username", "--raw"])).stdout,
    "bot",
  );
  assert.equal(
    (await akb(["account", "list", "--url", "https://created.test/signin", "--json"])).json.data
      .length,
    1,
  );
  const duplicateRef = await akb(
    ["item", "create", "--name", "Again", "--ref", "test/created", "--generate-password", "--json"],
    undefined,
    6,
  );
  assert.equal(duplicateRef.json.error.code, "REF_EXISTS");
  await akb(["item", "create", "--name", "x", "--ref", "test/none", "--json"], undefined, 2);
  const given = randomBytes(18).toString("base64");
  await akb(
    ["item", "create", "--name", "Given", "--ref", "test/given", "--password-stdin", "--json"],
    given + "\n",
  );
  assert.equal(
    (await akb(["credential", "get", "ref:test/given", "--field", "password", "--raw"])).stdout,
    given,
    "A password from standard input is stored exactly, without its trailing newline",
  );
  pass("item create stores generated and given passwords, refuses duplicate references");

  const rotated = await akb([
    "item",
    "set",
    "ref:test/created",
    "--field",
    "password",
    "--generate",
  ]);
  assert.ok(!rotated.stdout.includes(generated));
  const regenerated = (
    await akb(["credential", "get", "ref:test/created", "--field", "password", "--raw"])
  ).stdout;
  assert.equal(regenerated.length, 24);
  assert.notEqual(regenerated, generated);
  const rotatedValue = randomBytes(18).toString("base64");
  await akb(
    ["item", "set", "ref:test/created", "--field", "password", "--stdin"],
    rotatedValue + "\n",
  );
  assert.equal(
    (await akb(["credential", "get", "ref:test/created", "--field", "password", "--raw"])).stdout,
    rotatedValue,
  );
  await akb(
    ["item", "set", "ref:test/missing", "--field", "password", "--generate", "--json"],
    undefined,
    5,
  );
  await akb(
    ["item", "set", "ref:test/created", "--field", "custom:agentkeybox.ref", "--stdin", "--json"],
    "other",
    2,
  );
  pass("item set rotates a password, generated or given, and refuses unknown or reserved targets");

  // Changing one field must leave the rest of the item as it was, including what akb never reads.
  await akb(
    ["item", "set", "ref:test/account", "--field", "custom:environment", "--stdin"],
    "prod",
  );
  assert.equal(
    (await akb(["credential", "get", "ref:test/account", "--field", "custom:environment", "--raw"]))
      .stdout,
    "prod",
  );
  const kept = await akb(["account", "list", "--url", "https://example.test/anything", "--json"]);
  assert.equal(kept.json.data[0].ref, "test/account");
  assert.equal(kept.json.data[0].username, "fixture-user");
  assert.ok(kept.json.data[0].credential_fields.includes("totp"));
  assert.equal(
    (await akb(["credential", "get", "ref:test/account", "--field", "password", "--raw"])).stdout,
    secret,
  );
  const keptOtp = await akb(["credential", "get", "ref:test/account", "--field", "totp", "--json"]);
  assert.ok(
    [totpAt(Math.floor(Date.now() / 1000) - 1), totpAt(Math.floor(Date.now() / 1000))].includes(
      keptOtp.json.data.value,
    ),
  );
  pass("a single-field change preserves the reference, address, username, password and totp");

  const seedBytes = randomBytes(20);
  await akb(
    ["item", "set", "ref:test/created", "--field", "totp", "--stdin"],
    base32(seedBytes) + "\n",
  );
  const createdOtp = await akb([
    "credential",
    "get",
    "ref:test/created",
    "--field",
    "totp",
    "--json",
  ]);
  assert.match(createdOtp.json.data.value, /^\d{6}$/);
  const badSeed = await akb(
    ["item", "set", "ref:test/created", "--field", "totp", "--stdin", "--json"],
    "%%% not a seed %%%",
    2,
  );
  assert.equal(badSeed.json.error.code, "INVALID_TOTP");
  pass("a totp seed is checked before it is stored");

  // Delete moves to the trash: the server still has the item, and its reference is free again.
  const trashed = await akb(["item", "delete", "ref:test/given", "--json"]);
  assert.equal(trashed.json.data.deleted, true);
  assert.equal(trashed.json.data.ref, "test/given");
  const stored = await fixtureFetch(`${base}/api/ciphers/${trashed.json.data.id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.ok(stored.ok, "The server still holds a deleted item");
  assert.ok((await stored.json()).deletedDate, "The server marks it as deleted");
  await akb(["credential", "get", "ref:test/given", "--field", "password", "--json"], undefined, 5);
  assert.equal(
    (await akb(["account", "list", "--search", "Given", "--json"])).json.data.length,
    0,
    "A deleted item is no longer listed",
  );
  await akb(
    ["item", "create", "--name", "Given again", "--ref", "test/given", "--generate-password"],
    undefined,
  );
  await akb(["item", "delete", "ref:test/missing", "--json"], undefined, 5);
  for (const inexact of ["Given", "ref:"]) {
    await akb(["item", "delete", inexact, "--json"], undefined, 2);
  }
  pass("item delete moves a login to the trash and frees its reference");

  // The trash can be listed, and a deleted login comes back unless its reference was reused.
  const inTrash = await akb(["account", "list", "--trashed", "--search", "Given", "--json"]);
  assert.equal(inTrash.json.data.length, 1);
  assert.equal(inTrash.json.data[0].id, trashed.json.data.id);
  assert.ok(Date.parse(inTrash.json.data[0].deleted_at) > 0);
  assert.ok(!inTrash.stdout.includes(given), "Listing the trash shows no values");
  const reused = await akb(["item", "restore", "ref:test/given", "--json"], undefined, 6);
  assert.equal(reused.json.error.code, "REF_EXISTS", "A reused reference cannot be restored over");
  await akb(["item", "delete", "ref:test/given", "--json"]);
  // Both logins named test/given are in the trash now, so the name alone no longer picks one.
  const both = await akb(["item", "restore", "ref:test/given", "--json"], undefined, 6);
  assert.equal(both.json.error.code, "AMBIGUOUS_MATCH");
  const restored = await akb(["item", "restore", `id:${trashed.json.data.id}`, "--json"]);
  assert.equal(restored.json.data.restored, true);
  assert.ok(!restored.stdout.includes(given));
  const back = await fixtureFetch(`${base}/api/ciphers/${trashed.json.data.id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal((await back.json()).deletedDate, null, "The server no longer marks it as deleted");
  assert.equal(
    (await akb(["credential", "get", "ref:test/given", "--field", "password", "--raw"])).stdout,
    given,
    "The restored login keeps its original password",
  );
  await akb(["item", "restore", "ref:test/missing", "--json"], undefined, 5);
  await akb(["item", "restore", "test/given", "--json"], undefined, 2);
  pass("item restore brings a login back from the trash, unless its reference was reused");

  // The MCP server: discovery, run with redaction, generated-only writes, and no values out.
  const initialize = {
    jsonrpc: "2.0",
    id: 0,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e" } },
  };
  const listed = await mcp([
    initialize,
    { jsonrpc: "2.0", method: "notifications/initialized" },
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
    toolCall(2, "akb_find", { url: "https://example.test/anything" }),
    toolCall(3, "akb_show", { ref: "ref:test/account" }),
    toolCall(4, "akb_run", {
      env: [{ name: "TOKEN", ref: "ref:test/account" }],
      command: [
        process.execPath,
        "-e",
        `process.stdout.write(String(process.env.TOKEN === ${JSON.stringify(secret)}) + "|"); ` +
          "console.log(process.env.TOKEN)",
      ],
    }),
    toolCall(5, "akb_run", {
      env: [{ name: "OTP", ref: "ref:test/account", field: "totp" }],
      command: [process.execPath, "-e", "console.log(/^\\d{6}$/.test(process.env.OTP))"],
    }),
    toolCall(6, "akb_run", {
      env: [{ name: "TOKEN", ref: "ref:test/missing" }],
      command: [process.execPath, "-e", "console.log('ran')"],
    }),
    toolCall(7, "akb_run", {
      env: [{ name: "TOKEN", ref: "ref:test/account" }],
      command: [process.execPath, "-e", "setInterval(() => {}, 1000)"],
      timeout_seconds: 2,
    }),
    toolCall(8, "akb_run", {
      env: [{ name: "TOKEN", ref: "ref:test/account" }],
      command: [
        process.execPath,
        "-e",
        "process.stdin.on('end', () => console.log('no input')).resume()",
      ],
    }),
  ]);
  assert.equal(listed.replies.get(0).result.serverInfo.name, "agentkeybox");
  assert.deepEqual(
    listed.replies.get(1).result.tools.map((tool) => tool.name),
    [
      "akb_status",
      "akb_find",
      "akb_show",
      "akb_run",
      "akb_passkey_assert",
      "akb_passkey_create",
      "akb_create",
      "akb_rotate",
      "akb_restore",
      "akb_delete",
    ],
  );
  const found = toolBody(listed.replies.get(2));
  assert.equal(found.length, 1);
  assert.deepEqual(found[0].uris, ["https://example.test"]);
  assert.equal(toolBody(listed.replies.get(3)).ref, "test/account");
  const mcpRun = toolBody(listed.replies.get(4));
  assert.equal(mcpRun.stdout, "true|[REDACTED:TOKEN]\n", "The command saw the exact value");
  assert.equal(mcpRun.exit_code, 0);
  assert.equal(toolBody(listed.replies.get(5)).stdout, "true\n", "A totp value can be injected");
  assert.equal(listed.replies.get(6).result.isError, true);
  assert.equal(toolBody(listed.replies.get(6)).code, "NOT_FOUND");
  assert.ok(!listed.stdout.includes("ran"), "No command starts when a reference fails");
  const timedOut = toolBody(listed.replies.get(7));
  assert.equal(timedOut.timed_out, true);
  assert.equal(timedOut.exit_code, 124);
  assert.equal(toolBody(listed.replies.get(8)).stdout, "no input\n", "The command has no stdin");
  for (const hidden of [secret, totpSeed]) {
    assert.ok(!listed.stdout.includes(hidden), "No MCP reply contains a credential value");
  }
  assert.equal(listed.stderr, "", "The server writes nothing else");

  // Writes through MCP accept no values, only generation.
  const written = await mcp([
    initialize,
    toolCall(1, "akb_create", {
      name: "MCP Created",
      ref: "test/mcp",
      urls: ["mcp.test"],
      length: 40,
      password: "must-be-ignored-by-the-tool",
    }),
  ]);
  assert.equal(toolBody(written.replies.get(1)).created, true);
  const mcpGenerated = (
    await akb(["credential", "get", "ref:test/mcp", "--field", "password", "--raw"])
  ).stdout;
  assert.equal(mcpGenerated.length, 40);
  assert.notEqual(mcpGenerated, "must-be-ignored-by-the-tool");
  const rotatedByMcp = await mcp([initialize, toolCall(1, "akb_rotate", { ref: "ref:test/mcp" })]);
  assert.equal(toolBody(rotatedByMcp.replies.get(1)).ref, "test/mcp");
  const mcpRotated = (
    await akb(["credential", "get", "ref:test/mcp", "--field", "password", "--raw"])
  ).stdout;
  assert.notEqual(mcpRotated, mcpGenerated);
  const removedByMcp = await mcp([initialize, toolCall(1, "akb_delete", { ref: "ref:test/mcp" })]);
  assert.equal(toolBody(removedByMcp.replies.get(1)).deleted, true);
  await akb(["credential", "get", "ref:test/mcp", "--field", "password", "--json"], undefined, 5);
  for (const output of [written.stdout, rotatedByMcp.stdout, removedByMcp.stdout]) {
    assert.ok(!output.includes(mcpGenerated) && !output.includes(mcpRotated));
  }

  const readOnly = await mcp(
    [
      initialize,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      toolCall(2, "akb_delete", { ref: "ref:test/account" }),
    ],
    ["--read-only"],
  );
  assert.deepEqual(
    readOnly.replies.get(1).result.tools.map((tool) => tool.name),
    ["akb_status", "akb_find", "akb_show", "akb_run", "akb_passkey_assert"],
  );
  assert.equal(readOnly.replies.get(2).error.code, -32602);
  assert.equal(
    (await akb(["credential", "get", "ref:test/account", "--field", "username", "--raw"])).stdout,
    "fixture-user",
    "A refused delete left the item in place",
  );
  pass("the MCP server finds, runs with redaction, writes only generated values, and leaks none");

  // A passkey signs a site's challenge; the key stays in the vault and only the signed answer leaves.
  const passkeyChallenge = randomBytes(32).toString("base64url");
  const origin = `https://${passkeyRp}`;
  const shown = await akb(["account", "show", "ref:test/passkey", "--json"]);
  assert.deepEqual(shown.json.data.passkey_rp_ids, [passkeyRp]);
  assert.ok(shown.json.data.credential_fields.includes("passkey"));
  const asserted = await akb([
    "passkey",
    "assert",
    "ref:test/passkey",
    "--origin",
    `${origin}/login?next=/x`,
    "--challenge",
    passkeyChallenge,
    "--json",
  ]);
  const proof = asserted.json.data;
  const authData = Buffer.from(proof.authenticator_data, "base64url");
  const clientJson = Buffer.from(proof.client_data_json, "base64url");
  assert.deepEqual(JSON.parse(clientJson.toString()), {
    type: "webauthn.get",
    challenge: passkeyChallenge,
    origin,
    crossOrigin: false,
  });
  assert.ok(
    authData.subarray(0, 32).equals(createHash("sha256").update(passkeyRp).digest()),
    "authenticator data names the site",
  );
  assert.equal(proof.credential_id, passkeyCredentialId.toString("base64url"));
  assert.ok(
    verify(
      "sha256",
      Buffer.concat([authData, createHash("sha256").update(clientJson).digest()]),
      { key: passkeyPair.publicKey, dsaEncoding: "der" },
      Buffer.from(proof.signature, "base64url"),
    ),
    "The signature verifies with the passkey's public key",
  );
  const privateKeyText = passkeyPair.privateKey
    .export({ type: "pkcs8", format: "der" })
    .toString("base64url");
  assert.ok(!asserted.stdout.includes(privateKeyText), "The reply never contains the private key");
  const wrongSite = await akb(
    [
      "passkey",
      "assert",
      "ref:test/passkey",
      "--origin",
      "https://other.test",
      "--challenge",
      passkeyChallenge,
      "--json",
    ],
    undefined,
    2,
  );
  assert.equal(wrongSite.json.error.code, "INVALID_ORIGIN");
  const plain = await akb(
    [
      "passkey",
      "assert",
      "ref:test/passkey",
      "--origin",
      "http://example.test",
      "--challenge",
      passkeyChallenge,
      "--json",
    ],
    undefined,
    2,
  );
  assert.equal(plain.json.error.code, "INVALID_ORIGIN");
  const noPasskey = await akb(
    [
      "passkey",
      "assert",
      "ref:test/account",
      "--origin",
      origin,
      "--challenge",
      passkeyChallenge,
      "--json",
    ],
    undefined,
    5,
  );
  assert.equal(noPasskey.json.error.code, "FIELD_NOT_FOUND");
  const viaMcp = await mcp([
    initialize,
    toolCall(1, "akb_passkey_assert", {
      ref: "ref:test/passkey",
      origin,
      challenge: passkeyChallenge,
    }),
  ]);
  const mcpProof = toolBody(viaMcp.replies.get(1));
  assert.ok(
    verify(
      "sha256",
      Buffer.concat([
        Buffer.from(mcpProof.authenticator_data, "base64url"),
        createHash("sha256").update(Buffer.from(mcpProof.client_data_json, "base64url")).digest(),
      ]),
      { key: passkeyPair.publicKey, dsaEncoding: "der" },
      Buffer.from(mcpProof.signature, "base64url"),
    ),
  );
  assert.ok(!viaMcp.stdout.includes(privateKeyText));
  pass("a passkey signs a challenge for its own site only, and its key never leaves the vault");

  // Registering: the new key is made and stored by the vault, and what comes back is enough for a
  // site to accept it. The proof is that the passkey then signs in and verifies with that key.
  await akb([
    "item",
    "create",
    "--name",
    "Passkey Site",
    "--ref",
    "test/registered",
    "--url",
    origin,
    "--generate-password",
  ]);
  const siteUserId = randomBytes(16);
  const registrationChallenge = randomBytes(32).toString("base64url");
  const registered = await akb([
    "passkey",
    "create",
    "ref:test/registered",
    "--origin",
    `${origin}/signup`,
    "--challenge",
    registrationChallenge,
    "--user-id",
    siteUserId.toString("base64url"),
    "--user-name",
    "alice@example.test",
    "--rp-name",
    "Example Site",
    "--json",
  ]);
  const made = registered.json.data;
  assert.equal(made.rp_id, passkeyRp);
  assert.equal(made.public_key_algorithm, -7);
  assert.deepEqual(JSON.parse(Buffer.from(made.client_data_json, "base64url").toString()), {
    type: "webauthn.create",
    challenge: registrationChallenge,
    origin,
    crossOrigin: false,
  });
  const madeAuthData = Buffer.from(made.authenticator_data, "base64url");
  assert.ok(madeAuthData.subarray(0, 32).equals(createHash("sha256").update(passkeyRp).digest()));
  assert.equal(madeAuthData[32] & 0x41, 0x41, "User present and attested credential data");
  assert.equal(madeAuthData[32] & 0x04, 0, "User verification is not claimed");
  const madeIdLength = madeAuthData.readUInt16BE(53);
  assert.equal(
    madeAuthData.subarray(55, 55 + madeIdLength).toString("base64url"),
    made.credential_id,
    "The attested credential id is the one returned",
  );
  assert.ok(Buffer.from(made.attestation_object, "base64url").includes(madeAuthData));
  const madeKey = createPublicKey({
    key: Buffer.from(made.public_key, "base64url"),
    format: "der",
    type: "spki",
  });
  const showRegistered = await akb(["account", "show", "ref:test/registered", "--json"]);
  assert.deepEqual(showRegistered.json.data.passkey_rp_ids, [passkeyRp]);
  assert.ok(showRegistered.json.data.credential_fields.includes("passkey"));

  const signIn = await akb([
    "passkey",
    "assert",
    "ref:test/registered",
    "--origin",
    origin,
    "--challenge",
    passkeyChallenge,
    "--json",
  ]);
  const signedIn = signIn.json.data;
  assert.equal(signedIn.credential_id, made.credential_id, "It signs with the credential it made");
  assert.equal(
    signedIn.user_handle,
    siteUserId.toString("base64url"),
    "The site's user id is returned at sign-in",
  );
  assert.ok(
    verify(
      "sha256",
      Buffer.concat([
        Buffer.from(signedIn.authenticator_data, "base64url"),
        createHash("sha256").update(Buffer.from(signedIn.client_data_json, "base64url")).digest(),
      ]),
      { key: madeKey, dsaEncoding: "der" },
      Buffer.from(signedIn.signature, "base64url"),
    ),
    "The sign-in verifies with the public key given at registration",
  );

  const again = await akb(
    [
      "passkey",
      "create",
      "ref:test/registered",
      "--origin",
      origin,
      "--challenge",
      registrationChallenge,
      "--user-id",
      siteUserId.toString("base64url"),
      "--user-name",
      "alice@example.test",
      "--json",
    ],
    undefined,
    6,
  );
  assert.equal(again.json.error.code, "PASSKEY_EXISTS", "An existing passkey is never overwritten");
  const stillSigns = await akb([
    "passkey",
    "assert",
    "ref:test/registered",
    "--origin",
    origin,
    "--challenge",
    passkeyChallenge,
    "--json",
  ]);
  assert.equal(stillSigns.json.data.credential_id, made.credential_id);
  const wrongSiteCreate = await akb(
    [
      "passkey",
      "create",
      "ref:test/account",
      "--origin",
      origin,
      "--rp-id",
      "other.test",
      "--challenge",
      registrationChallenge,
      "--user-id",
      siteUserId.toString("base64url"),
      "--user-name",
      "alice",
      "--json",
    ],
    undefined,
    2,
  );
  assert.equal(wrongSiteCreate.json.error.code, "INVALID_ORIGIN");
  // The same through MCP, and the model never sees anything but public material.
  await akb([
    "item",
    "create",
    "--name",
    "Second Site",
    "--ref",
    "test/registered2",
    "--generate-password",
  ]);
  const viaMcpCreate = await mcp([
    initialize,
    toolCall(1, "akb_passkey_create", {
      ref: "ref:test/registered2",
      origin,
      challenge: registrationChallenge,
      user_id: siteUserId.toString("base64url"),
      user_name: "bob@example.test",
    }),
    toolCall(2, "akb_passkey_create", {
      ref: "ref:test/registered2",
      origin,
      challenge: registrationChallenge,
      user_id: siteUserId.toString("base64url"),
      user_name: "bob@example.test",
    }),
  ]);
  const mcpMade = toolBody(viaMcpCreate.replies.get(1));
  assert.equal(mcpMade.public_key_algorithm, -7);
  assert.equal(toolBody(viaMcpCreate.replies.get(2)).code, "PASSKEY_EXISTS");
  const mcpSignIn = (
    await akb([
      "passkey",
      "assert",
      "ref:test/registered2",
      "--origin",
      origin,
      "--challenge",
      passkeyChallenge,
      "--json",
    ])
  ).json.data;
  assert.equal(mcpSignIn.credential_id, mcpMade.credential_id);
  assert.ok(
    verify(
      "sha256",
      Buffer.concat([
        Buffer.from(mcpSignIn.authenticator_data, "base64url"),
        createHash("sha256").update(Buffer.from(mcpSignIn.client_data_json, "base64url")).digest(),
      ]),
      {
        key: createPublicKey({
          key: Buffer.from(mcpMade.public_key, "base64url"),
          format: "der",
          type: "spki",
        }),
        dsaEncoding: "der",
      },
      Buffer.from(mcpSignIn.signature, "base64url"),
    ),
  );
  pass("a passkey is created for a site, stored in the vault, and then signs in");

  // Every access so far left a record, and no record holds a value.
  const auditText = readFileSync(path.join(home, "profiles/default/audit.log"), "utf8");
  const audited = auditText
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const op of ["get", "resolve", "run", "create", "set", "delete", "assert"]) {
    assert.ok(
      audited.some((entry) => entry.op === op && entry.outcome === "ok"),
      `audit log has a successful ${op}`,
    );
  }
  assert.ok(
    audited.some((entry) => entry.op === "get" && entry.code === "NOT_FOUND") ||
      audited.some((entry) => entry.op === "resolve" && entry.code === "NOT_FOUND"),
    "a failed lookup is recorded with its error code",
  );
  const exited = audited.find((entry) => entry.op === "run" && entry.exit_code === 3);
  assert.ok(exited && /^node(\.exe)?$/i.test(exited.command), "run records the program name only");
  assert.ok(
    audited.some((entry) => entry.targets?.some((t) => t.env === "TOKEN" && t.id)),
    "run records which variable got which item",
  );
  for (const hidden of [secret, totpSeed, generated, regenerated, rotatedValue, given]) {
    assert.ok(!auditText.includes(hidden), "The audit log never contains a value");
  }
  pass("the audit log records each access with references only, never values");

  await akb(["auth", "lock", "--json"]);
  assert.equal(
    (await akb(["credential", "get", ref, "--field", "password", "--json"], undefined, 4)).json
      .error.code,
    "VAULT_LOCKED",
  );
  await akb(["auth", "unlock", "--password-stdin", "--json"], "incorrect-password", 4);
  assert.equal((await akb(["auth", "status", "--json"])).json.data.status, "locked");
  await akb(["auth", "unlock", "--password-stdin", "--json"], password);
  assert.equal(
    (await akb(["credential", "get", ref, "--field", "password", "--raw"])).stdout,
    secret,
  );
  pass("lock, incorrect password, unlock and read again");

  if (foreground) {
    // The user's own limits end a session sooner than the desktop lock would.
    const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const readPassword = () =>
      akb(["credential", "get", ref, "--field", "password", "--raw"], undefined, 0);
    const readLocked = async () =>
      (await akb(["credential", "get", ref, "--field", "password", "--json"], undefined, 4)).json
        .error.code;
    const unlock = () => akb(["auth", "unlock", "--password-stdin", "--json"], password);

    const idleSet = await akb(["session", "policy", "set", "--idle", "10s", "--json"]);
    assert.equal(idleSet.json.data.policy.idle_ms, 10000);
    assert.equal((await akb(["session", "policy", "show", "--json"])).json.data.idle_ms, 10000);
    assert.equal((await readPassword()).stdout, secret, "Within the limit the session works");
    // A command takes a few seconds to start and finish, so the limits leave generous room.
    await pause(4000);
    assert.equal((await readPassword()).stdout, secret, "Use keeps an idle session alive");
    await pause(11_000);
    assert.equal(await readLocked(), "VAULT_LOCKED", "An idle session ends");
    assert.equal(
      (await akb(["status", "--json"])).json.data.lock_reason,
      "session_expired",
      "Status says why",
    );
    await unlock();
    assert.equal((await readPassword()).stdout, secret, "Unlocking starts a new session");

    await akb(["session", "policy", "set", "--idle", "never", "--max", "12s", "--json"]);
    await unlock();
    assert.equal((await readPassword()).stdout, secret);
    await pause(5000);
    assert.equal((await readPassword()).stdout, secret, "Still inside the maximum lifetime");
    await pause(5000);
    assert.equal(await readLocked(), "VAULT_LOCKED", "The maximum lifetime ends it despite use");

    await akb(["session", "policy", "set", "--idle", "never", "--max", "never", "--json"]);
    await unlock();
    await pause(1000);
    assert.equal((await readPassword()).stdout, secret, "With no limits the session stays");
    await akb(["session", "policy", "set", "--json"], undefined, 2);
    pass("session limits end an idle or old session on Windows and macOS");
  }

  const updated = randomBytes(24).toString("base64");
  const edit = await fixtureFetch(`${base}/api/ciphers/${item.id}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      ...seed,
      login: { ...seed.login, password: encrypt(Buffer.from(updated), userKey) },
    }),
  });
  assert.ok(edit.ok);
  assert.equal(
    (await akb(["credential", "get", ref, "--field", "password", "--raw"])).stdout,
    updated,
  );
  pass("online read observes another client's update");

  // A write based on an old copy is refused, and the refusal's text is what AKB recognizes.
  const staleWrite = await fixtureFetch(`${base}/api/ciphers/${item.id}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ ...seed, lastKnownRevisionDate: "2000-01-01T00:00:00.000Z" }),
  });
  assert.ok(!staleWrite.ok, "The server refuses a write made from an old copy");
  assert.match(await staleWrite.text(), /out of date|conflict/i);

  // Another client keeps changing the same login while AKB writes to it. Each write is either
  // stored, after one retry on fresh data, or reported as a conflict. It is never a plain
  // failure. AKB syncs just before it writes, so this run may never produce a conflict at all;
  // the unit tests cover how a refusal is recognized.
  const raceId = created.json.data.id;
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  let racing = true;
  let reportedRacerFailure = false;
  const racer = (async () => {
    let writes = 0;
    while (racing) {
      try {
        const read = await fixtureFetch(`${base}/api/ciphers/${raceId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const current = await read.json();
        const put = await fixtureFetch(`${base}/api/ciphers/${raceId}`, {
          method: "PUT",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          // The whole item goes back unchanged: only the server's revision date moves.
          body: JSON.stringify({ ...current, encryptedFor: userId }),
        });
        if (put.ok) writes++;
        else if (!reportedRacerFailure) {
          reportedRacerFailure = true;
          console.log(
            `racer write refused: HTTP ${put.status} ${(await put.text()).slice(0, 200)}`,
          );
        }
      } catch {
        // The fixture server may drop a connection under load; the next round tries again.
      }
      await sleep(80);
    }
    return writes;
  })();
  const outcomes = [];
  const attempt = (value) =>
    new Promise((resolve) => {
      const child = execFile(
        binary || process.execPath,
        [
          ...(binary ? [] : [cli]),
          ...["item", "set", "ref:test/created", "--field", "custom:race", "--stdin", "--json"],
        ],
        {
          env,
          cwd: binary ? home : undefined,
          windowsHide: true,
          timeout: 90000,
          maxBuffer: 2 ** 20,
        },
        (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }),
      );
      child.stdin.end(value);
    });
  for (let i = 0; i < 8; i++) {
    const run = await attempt(`race-${i}`);
    let outcome = "ok";
    if (run.code !== 0) {
      try {
        outcome = JSON.parse(run.stdout).error.code;
      } catch {
        outcome = `exit ${run.code}: ${(run.stderr || run.stdout).slice(0, 120)}`;
      }
    }
    outcomes.push(outcome);
  }
  racing = false;
  const raceWrites = await racer;
  assert.ok(raceWrites > 0, "The other client's writes went through");
  console.log(`race outcomes: ${outcomes.join(", ")} (${raceWrites} writes by the other client)`);
  assert.ok(
    outcomes.every((outcome) => outcome === "ok" || outcome === "WRITE_CONFLICT"),
    `A conflict must be recognized, not reported as a plain failure: ${outcomes}`,
  );
  await akb(["item", "set", "ref:test/created", "--field", "custom:race", "--stdin"], "settled");
  assert.equal(
    (await akb(["credential", "get", "ref:test/created", "--field", "custom:race", "--raw"]))
      .stdout,
    "settled",
  );
  pass(
    "writes made while another client keeps changing the item are stored or reported as conflicts",
  );

  const duplicate = await api("/api/ciphers", seed, token);
  await akb(
    ["credential", "get", "ref:test/account", "--field", "password", "--json"],
    undefined,
    6,
  );
  await fixtureFetch(`${base}/api/ciphers/${duplicate.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
  });
  pass("duplicate references are rejected");
  assert.equal(
    (await akb(["--profile", "other", "status", "--json"])).json.data.status,
    "unauthenticated",
  );
  if (!foreground) {
    await akb(["--profile", "other", "service", "stop", "--json"]);
  }
  pass("profile isolation");

  const snapshot = readFileSync(path.join(home, "profiles/default/bw/data.json"), "utf8");
  for (const value of [password, secret, updated]) {
    assert.ok(!snapshot.includes(value));
  }
  assert.deepEqual(
    readdirSync(path.join(home, "profiles/default")).sort(),
    // Foreground profiles also keep the session clock and the limits file: timestamps and
    // durations, nothing secret.
    foreground
      ? ["audit.log", "bw", "session-policy.json", "session-state.json"]
      : ["audit.log", "bw"],
  );
  pass("no plaintext password, secret or session file persisted");

  if (foreground) {
    if (windows) {
      const help = await exec(binary || process.execPath, binary ? ["--help"] : [cli, "--help"], {
        env,
        windowsHide: true,
      });
      assert.doesNotMatch(help.stdout, /^\s+service\b/m);
    } else {
      const dir = realpathSync(path.join(home, "profiles/default"));
      const hash = createHash("sha256").update(dir).digest("hex").slice(0, 20);
      assert.ok(!existsSync(path.join(tmpdir(), `akb-${process.getuid()}-${hash}`)));
    }
    const reads = await Promise.all(
      Array.from({ length: 3 }, () =>
        akb(["credential", "get", ref, "--field", "password", "--raw"]),
      ),
    );
    assert.ok(reads.every(({ stdout }) => stdout === updated));
    pass("parallel foreground calls restore from the OS credential store");
    if (windows && process.env.AKB_TEST_SCREEN_LOCK === "1") {
      console.log("Press Win+L now, wait ten seconds, then unlock Windows.");
      await waitForWindowsScreen(4);
      const locked = await akb(
        ["--no-input", "credential", "get", ref, "--field", "password", "--json"],
        undefined,
        4,
      );
      assert.equal(locked.json.error.code, "SCREEN_LOCKED");
      await waitForWindowsScreen(0);
      await akb(["--no-input", "sync", "--json"]);
      const afterUnlock = await akb([
        "--no-input",
        "credential",
        "get",
        ref,
        "--field",
        "password",
        "--raw",
      ]);
      assert.equal(afterUnlock.stdout, updated);
      pass("Windows lock denies reads, and unlock restores sync and reads without a password");
    }
  } else {
    await akb(["service", "stop", "--json"]);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal((await akb(["status", "--json"])).json.data.status, "locked");
    await akb(["auth", "unlock", "--password-stdin", "--json"], password);
    pass("service restart preserves login but drops unlock session");

    await akb(["session", "policy", "set", "--idle", "never", "--max", "never", "--json"]);
    assert.equal((await akb(["status", "--json"])).json.data.expires_at, null);
    await akb(["service", "stop", "--json"]);
    await new Promise((resolve) => setTimeout(resolve, 300));
    env.AKB_IDLE_MS = "100";
    env.AKB_MAX_MS = "100";
    await akb(["auth", "unlock", "--password-stdin", "--json"], password);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    assert.equal((await akb(["status", "--json"])).json.data.status, "unlocked");
    assert.equal((await akb(["status", "--json"])).json.data.expires_at, null);
    await akb(["auth", "lock", "--json"]);
    assert.equal((await akb(["status", "--json"])).json.data.status, "locked");
    pass("persistent never-lock policy overrides environment timeouts; manual lock still works");
    // Remaining tests intentionally exercise environment defaults instead.
    rmSync(path.join(home, "profiles/default/session-policy.json"));
    for (const [label, idle, max] of [
      ["idle", "1800", "60000"],
      ["maximum", "60000", "1800"],
    ]) {
      await akb(["service", "stop", "--json"]);
      await new Promise((resolve) => setTimeout(resolve, 300));
      env.AKB_IDLE_MS = idle;
      env.AKB_MAX_MS = max;
      await akb(["auth", "unlock", "--password-stdin", "--json"], password);
      const deadline = Date.now() + 4500;
      let status;
      do {
        await new Promise((resolve) => setTimeout(resolve, 400));
        status = (await akb(["status", "--json"])).json.data.status;
      } while (status === "unlocked" && Date.now() < deadline);
      assert.equal(status, "locked");
      pass(`${label} timeout locks session; status polling does not renew it`);
    }
    await akb(["service", "stop", "--json"]);
    await new Promise((resolve) => setTimeout(resolve, 300));
    env.AKB_IDLE_MS = "300000";
    env.AKB_MAX_MS = "3600000";
    await akb(["auth", "unlock", "--password-stdin", "--json"], password);
  }
  execFileSync("docker", ["stop", name], { stdio: "pipe" });
  assert.equal(
    (await akb(["credential", "get", ref, "--field", "password", "--json"], undefined, 8)).json
      .error.code,
    "SYNC_FAILED",
  );
  pass("network failure never silently returns cached credentials");
  await akb(["auth", "logout", "--json"]);
  assert.equal((await akb(["status", "--json"])).json.data.status, "unauthenticated");
  await akb(["auth", "logout", "--json"]);
  pass("logout clears authentication and is idempotent");
  console.log(
    `${count} integration checks passed; all secrets were randomly generated and not printed.`,
  );
} finally {
  if (foreground) {
    await akb(["auth", "logout", "--json"]).catch(() => {});
  } else {
    await akb(["service", "stop", "--json"]).catch(() => {});
    await akb(["--profile", "other", "service", "stop", "--json"]).catch(() => {});
  }
  try {
    await exec("docker", ["rm", "-f", name]);
  } catch {}
  await new Promise((resolve) => setTimeout(resolve, 300));
  rmSync(home, { recursive: true, force: true });
}
