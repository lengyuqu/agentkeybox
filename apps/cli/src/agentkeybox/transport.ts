import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

import * as lockfile from "proper-lockfile";

import { fileAudit } from "./audit";
import { defaultPolicy, loadPolicy } from "./policy";
import { AkbError, failure, Reply, Request } from "./protocol";

export function profileDirectory(profile: string) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$/.test(profile)) {
    throw new AkbError("INVALID_PROFILE", "Profile must contain only letters, digits, - or _.", 2);
  }
  const windows = process.platform === "win32";
  if (windows && /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(profile)) {
    throw new AkbError("INVALID_PROFILE", "This profile name is reserved on Windows.", 2);
  }
  const root = path.resolve(process.env.AKB_HOME || path.join(os.homedir(), ".agentkeybox"));
  const dir = path.join(root, "profiles", profile);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (!windows && stat.uid !== process.getuid())) {
    throw new AkbError(
      "UNSAFE_DIRECTORY",
      "Profile directory must be owned by the current user.",
      7,
    );
  }
  if (windows) {
    // The foreground runner checks Windows ownership and permissions using the native helper.
    return dir;
  }
  fs.chmodSync(dir, 0o700);
  return fs.realpathSync(dir);
}

export function locations(profile: string) {
  if (process.platform === "win32") {
    throw new AkbError("SERVICE_UNAVAILABLE", "AKB runs in the foreground on Windows.", 10);
  }
  const dir = profileDirectory(profile);
  // Unix sockets have a short path limit. Use a private, deterministic runtime directory.
  const hash = createHash("sha256").update(dir).digest("hex").slice(0, 20);
  const runtime = path.join(os.tmpdir(), `akb-${process.getuid()}-${hash}`);
  fs.mkdirSync(runtime, { mode: 0o700, recursive: true });
  const runtimeStat = fs.lstatSync(runtime);
  if (
    !runtimeStat.isDirectory() ||
    runtimeStat.isSymbolicLink() ||
    runtimeStat.uid !== process.getuid()
  ) {
    throw new AkbError("UNSAFE_DIRECTORY", "Unsafe runtime directory.", 7);
  }
  fs.chmodSync(runtime, 0o700);
  const socket = path.join(runtime, "s");
  if (Buffer.byteLength(socket) > 100) {
    throw new AkbError("SOCKET_PATH_TOO_LONG", "Set TMPDIR to a shorter private directory.", 2);
  }
  return { dir, socket };
}

export function call(socketPath: string, request: Request): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path: "/rpc",
        method: "POST",
        agent: false,
        headers: { "Content-Type": "application/json" },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          text += chunk;
          if (text.length > 8 * 1024 * 1024) {
            res.destroy(new Error("Response too large"));
          }
        });
        res.on("error", reject);
        res.on("end", () => {
          try {
            resolve(JSON.parse(text) as Reply);
          } catch {
            reject(new AkbError("IPC_ERROR", "Invalid response from local service."));
          }
        });
      },
    );
    req.setTimeout(60_000, () =>
      req.destroy(
        new AkbError("TIMEOUT", "Local operation timed out; check status before retrying.", 8),
      ),
    );
    req.on("error", reject);
    req.end(JSON.stringify(request));
  });
}

export async function connect(profile: string, autoStart = true): Promise<string> {
  const { socket } = locations(profile);
  try {
    await call(socket, { operation: "status" });
    return socket;
  } catch (error) {
    if (!["ENOENT", "ECONNREFUSED"].includes((error as NodeJS.ErrnoException).code)) {
      throw error;
    }
    if (!autoStart) {
      throw new AkbError("SERVICE_STOPPED", "Local service is stopped.");
    }
  }
  // Spawn our own session service, never the bw executable. No secrets in argv/env.
  const env = { ...process.env };
  delete env.BW_SESSION;
  delete env.BW_PASSWORD;
  delete env.BW_CLIENTSECRET;
  const packaged = !!(process as NodeJS.Process & { pkg?: unknown }).pkg;
  const serviceArgs = ["--profile", profile, "service", "serve"];
  // pkg embeds the entrypoint; supplying argv[1] would become an extra CLI argument.
  // Its bootstrap also treats PKG_EXECPATH specially when starting another process.
  if (packaged) {
    env.PKG_EXECPATH = "";
  } else {
    delete env.PKG_EXECPATH;
  }
  const child = spawn(
    process.execPath,
    packaged ? serviceArgs : [process.argv[1], ...serviceArgs],
    {
      detached: true,
      stdio: "ignore",
      env,
    },
  );
  let launchError: Error | undefined;
  child.on("error", (e) => {
    launchError = e;
  });
  child.unref();
  for (let attempt = 0; attempt < 100; attempt++) {
    if (launchError) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
    try {
      await call(socket, { operation: "status" });
      return socket;
    } catch (error) {
      if (!["ENOENT", "ECONNREFUSED"].includes((error as NodeJS.ErrnoException).code)) {
        throw error;
      }
    }
  }
  throw new AkbError(
    "SERVICE_START_FAILED",
    "Run akb service serve in a terminal to diagnose startup.",
    10,
  );
}

export async function serve(profile: string) {
  const { dir, socket } = locations(profile);
  // Claim the profile before removing stale sockets or opening its data store.
  let release: () => Promise<void>;
  try {
    release = await lockfile.lock(dir, { realpath: false, stale: 10_000 });
  } catch {
    throw new AkbError("SERVICE_RUNNING", "A service already owns this profile.");
  }
  process.umask(0o077);
  process.env.BITWARDENCLI_APPDATA_DIR = path.join(dir, "bw");
  process.env.BW_NOINTERACTION = "true";
  process.env.BW_QUIET = "true";
  delete process.env.BW_SESSION;
  delete process.env.BITWARDENCLI_DEBUG;
  const { ServiceContainer } = await import("../service-container/service-container");
  const { Backend } = await import("./backend");
  const services = new ServiceContainer();
  // Upstream errors may include responses. Do not emit them into persistent daemon logs.
  for (const level of ["debug", "info", "warning", "error"] as const) {
    services.logService[level] = () => {};
  }
  await services.init();
  const duration = (name: string, fallback: number | null) => {
    if (process.env[name] === undefined) {
      return fallback;
    }
    const value = Number(process.env[name]);
    if (!Number.isFinite(value) || value <= 0) {
      throw new AkbError("INVALID_TIMEOUT", `${name} must be a positive millisecond duration.`, 2);
    }
    return value;
  };
  const fallbackPolicy = {
    idle_ms: duration("AKB_IDLE_MS", defaultPolicy.idle_ms),
    max_ms: duration("AKB_MAX_MS", defaultPolicy.max_ms),
  };
  const backend = new Backend(services);
  backend.setPolicy(loadPolicy(dir, fallbackPolicy));
  backend.setAudit(fileAudit(dir));
  let queue = Promise.resolve();
  let stopping = false;
  const enqueue = <T>(work: () => Promise<T>) => {
    const result = queue.then(work);
    queue = result.then(
      () => {},
      () => {},
    );
    return result;
  };
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("error", () => {});
    req.on("data", (chunk: string) => {
      body += chunk;
      if (Buffer.byteLength(body) > 65536) {
        req.destroy();
      }
    });
    req.on("end", () => {
      void enqueue(async () => {
        let reply: Reply;
        let stop = false;
        try {
          backend.setPolicy(loadPolicy(dir, fallbackPolicy));
          if (stopping || req.method !== "POST" || req.url !== "/rpc") {
            throw new AkbError("INVALID_REQUEST", "Request not accepted.", 2);
          }
          let request: Request;
          try {
            request = JSON.parse(body);
          } catch {
            throw new AkbError("INVALID_REQUEST", "Invalid JSON.", 2);
          }
          body = "";
          if (
            !request ||
            typeof request.operation !== "string" ||
            (request.args !== undefined &&
              (!request.args ||
                typeof request.args !== "object" ||
                Array.isArray(request.args) ||
                Object.values(request.args).some((v) => typeof v !== "string")))
          ) {
            throw new AkbError("INVALID_REQUEST", "Invalid request shape.", 2);
          }
          stop = request.operation === "stop";
          const data = await backend.dispatch(stop ? { operation: "lock" } : request);
          reply = { schema_version: 1, ok: true, data };
          if (stop) {
            stopping = true;
          }
        } catch (error) {
          reply = failure(error);
        }
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(reply));
        if (stop && reply.ok) {
          setTimeout(() => {
            void shutdown();
          }, 50);
        }
      });
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.on("connection", (connection) =>
    connection.setTimeout(65_000, () => connection.destroy()),
  );
  const timer = setInterval(() => {
    void enqueue(async () => {
      backend.setPolicy(loadPolicy(dir, fallbackPolicy));
      await backend.expire();
    }).catch(() => {
      void shutdown();
    });
  }, 1000);
  let closing = false;
  const shutdown = async () => {
    if (closing) {
      return;
    }
    closing = true;
    stopping = true;
    clearInterval(timer);
    server.close();
    const hardStop = setTimeout(() => process.exit(1), 5000);
    hardStop.unref();
    try {
      await enqueue(() => backend.dispatch({ operation: "lock" }));
    } finally {
      services.dispose();
      fs.rmSync(socket, { force: true });
      await release();
      process.exit(0);
    }
  };
  process.once("SIGTERM", () => {
    void shutdown();
  });
  process.once("SIGINT", () => {
    void shutdown();
  });
  fs.rmSync(socket, { force: true });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, () => {
      fs.chmodSync(socket, 0o600);
      resolve();
    });
  });
}
