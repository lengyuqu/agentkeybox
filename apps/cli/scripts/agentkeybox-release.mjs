import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = fileURLToPath(new URL("../", import.meta.url));
const root = path.resolve(app, "../..");
const { version } = JSON.parse(readFileSync(path.join(app, "package.agentkeybox.json"), "utf8"));
const windows = process.argv[2] === "windows-x64";
const output = path.join(app, "dist/agentkeybox", windows ? "windows-x64" : "macos-arm64");
const cliName = windows ? "akb.exe" : "akb";
const helperName = windows ? "akb-credentials.exe" : "akb-keychain";
const executable = path.join(output, cliName);
const helper = path.join(output, helperName);
copyFileSync(path.join(app, "build-akb", helperName), helper);
const licenses = path.join(output, "licenses");
mkdirSync(licenses, { recursive: true });
for (const name of ["LICENSE.txt", "LICENSE_GPL.txt", "NOTICE"]) {
  copyFileSync(path.join(root, name), path.join(licenses, name));
}
const digest = createHash("sha256").update(readFileSync(executable)).digest("hex");
const helperDigest = createHash("sha256").update(readFileSync(helper)).digest("hex");
writeFileSync(
  path.join(output, "SHA256SUMS"),
  `${digest}  ${cliName}\n${helperDigest}  ${helperName}\n`,
);
const usage = windows ? `.\\${cliName}` : `./${cliName}`;
writeFileSync(
  path.join(output, "README.txt"),
  `AgentKeybox ${version} — ${windows ? "Windows x64" : "macOS Apple Silicon (arm64)"}

Keep ${cliName} and ${helperName} in the same directory.
The embedded Node 22 runtime needs no separately installed Node.js, npm or bw.
${windows ? "This is an unsigned development build." : "This is a local ad-hoc signed build."}

${usage} --help
${usage} --profile home config server https://vault.example.com
${usage} --profile home auth login --email you@example.com
${usage} --profile home account list --json
${usage} --profile home credential get id:ITEM_UUID --field password --raw

Local state lives under ~/.agentkeybox. AKB_HOME overrides it.
Each command runs in the foreground and checks the active desktop session.
AKB syncs online before every vault read and restores its session via ${windows ? "Windows Credential Manager" : "Keychain"}.
Use auth lock or auth logout to remove the stored session key.
${windows ? "" : "For an existing profile, stop any older daemon with service stop and run\nauth unlock once to store the session key in Keychain.\n"}

GPL-3.0 source-based modification. Preserve the accompanying licenses.
Upstream source: https://github.com/bitwarden/clients/tree/cli-v2026.11.0
Customized source and build scripts are in this AgentKeybox workspace.
`,
);
console.log(`Release directory: ${output}`);
console.log(`SHA-256: ${digest}`);
