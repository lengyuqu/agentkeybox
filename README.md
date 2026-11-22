# AgentKeybox

AgentKeybox is an experimental Vaultwarden client for agents, built on Bitwarden's GPL client code. It can inject credentials into a child process and offers an MCP server designed not to return credential values directly. This is a development build, not a security guarantee or a production release.

[中文使用与验收说明](AGENTKEYBOX.md) · [Upstream Bitwarden README](README.bitwarden.md)

## Build

Requires Node.js 24.17 or later and npm 11. From the repository root:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build:akb --workspace @bitwarden/cli
node apps/cli/build-akb/akb.js --help
```

On Windows, run the build in a Visual Studio x64 developer shell so `cl.exe` is available. Windows and macOS packaging, testing, security boundaries and known limitations are documented in [AGENTKEYBOX.md](AGENTKEYBOX.md). In particular, output redaction is best effort and is not a sandbox for an untrusted agent.

## Source and license

Based on [Bitwarden clients](https://github.com/bitwarden/clients) CLI tag `cli-v2026.11.0`, commit `28b247ac34877882aaef4faea082a9f3bb201114`. The GPL build and modifications are provided under [GPL-3.0](LICENSE_GPL.txt); retain upstream copyright and license notices. Other third-party components may have their own licenses.

This public source snapshot excludes Bitwarden's separately licensed `bitwarden_license` commercial modules and does not include the private repository's history. Commands requiring those modules are outside this distribution. Bitwarden names and logos belong to their respective owners; this project is not an official Bitwarden product.

## Security reports

Please use GitHub's private vulnerability reporting for AgentKeybox-specific security issues. Do not include passwords, tokens or vault data in public issues. For issues in unmodified upstream Bitwarden components, consult the upstream project's security policy.
