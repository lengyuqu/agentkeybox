#!/usr/bin/env node
// Compare committed trees only. Fetch both remotes before running this read-only check.
import { execFileSync } from "node:child_process";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" });
const expectedPaths = new Set([
  ".github/CODEOWNERS",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".github/renovate.json5",
  ".github/workflows/agentkeybox-ci.yml",
  "README.md",
  "README.bitwarden.md",
  "SECURITY.md",
]);
const expectedDirectories = [
  "bitwarden_license/",
  ".github/DISCUSSION_TEMPLATE/",
  ".github/ISSUE_TEMPLATE/",
];

try {
  if (git("status", "--porcelain", "--untracked-files=no").trim()) {
    throw new Error("Tracked changes exist; commit or otherwise resolve them before comparing.");
  }
  git("rev-parse", "--verify", "refs/remotes/github/main");
  if (git("ls-tree", "-r", "--name-only", "refs/remotes/github/main", "--", "bitwarden_license").trim()) {
    throw new Error("Public main contains the excluded bitwarden_license directory.");
  }
  const paths = git("diff", "--name-only", "-z", "main", "refs/remotes/github/main")
    .split("\0")
    .filter(Boolean);
  const drift = paths.filter(
    (path) => !expectedPaths.has(path) && !expectedDirectories.some((dir) => path.startsWith(dir)),
  );
  if (drift.length) {
    console.error("Unexpected differences between CNB main and GitHub main:");
    for (const path of drift) console.error(`  ${path}`);
    process.exitCode = 1;
  } else {
    console.log(`Shared tracked files match; ${paths.length} intentional platform-specific differences.`);
  }
} catch (error) {
  console.error(`Cannot compare repositories: ${error.message}`);
  process.exitCode = 1;
}
