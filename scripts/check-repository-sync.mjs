#!/usr/bin/env node
// Compare the tips of local main, origin/main and github/main.
// Read-only. Fetch both remotes before running this check.
import { execFileSync } from "node:child_process";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();

const refs = [
  ["local", "main"],
  ["cnb", "refs/remotes/origin/main"],
  ["github", "refs/remotes/github/main"],
];

try {
  if (git("status", "--porcelain", "--untracked-files=no")) {
    throw new Error("Tracked changes exist; commit or otherwise resolve them before comparing.");
  }
  for (const [, ref] of refs) {
    git("rev-parse", "--verify", ref);
  }

  const tips = refs.map(([name, ref]) => ({ name, sha: git("rev-parse", ref) }));
  const unique = new Set(tips.map((tip) => tip.sha));

  if (unique.size === 1) {
    const count = git("rev-list", "--count", "main");
    console.log(`All refs share commit ${tips[0].sha.slice(0, 8)} (${count} commits).`);
  } else {
    console.error("Branch tips differ:");
    for (const tip of tips) console.error(`  ${tip.name.padEnd(7)} ${tip.sha.slice(0, 8)}`);
    const local = tips[0].sha;
    for (const tip of tips.slice(1)) {
      if (tip.sha === local) continue;
      const missing = git("rev-list", "--count", `${tip.sha}..main`);
      const extra = git("rev-list", "--count", `main..${tip.sha}`);
      console.error(
        `  ${tip.name}: ${missing} commit(s) in local main absent there, ${extra} there absent in local main`,
      );
    }
    console.error("Push the leading side to the trailing side, then re-fetch and rerun.");
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`Cannot compare repositories: ${error.message}`);
  process.exitCode = 1;
}
