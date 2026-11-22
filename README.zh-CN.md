# AgentKeybox

面向 agent 的 Vaultwarden 客户端，构建在 Bitwarden 的 GPL 客户端代码之上。它可以把凭据注入子进程的环境变量，并提供一个设计上不直接返回凭据值的 MCP server。**这是开发版，不是安全保证，也不是可用于生产的发布版。**

[English README](README.md) · [完整使用与验收说明](AGENTKEYBOX.md) · [上游 Bitwarden README](README.bitwarden.md)

## 构建

需要 Node.js 24.17 或更高版本、npm 11。在仓库根目录运行：

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build:akb --workspace @bitwarden/cli
node apps/cli/build-akb/akb.js --help
```

在 Windows 上，构建要在 Visual Studio x64 开发者终端里运行，以便找到 `cl.exe`。Windows 和 macOS 的打包、测试、安全边界与已知限制见 [AGENTKEYBOX.md](AGENTKEYBOX.md)。

**特别注意：`run` 的打码是兜底手段，不是针对不可信 agent 的沙箱。**

## 源码与许可证

本项目基于 [Bitwarden clients](https://github.com/bitwarden/clients) 的 CLI 标签 `cli-v2026.11.0`、commit `28b247ac34877882aaef4faea082a9f3bb201114`。GPL 构建与改动按 [GPL-3.0](LICENSE.txt) 提供；须保留上游版权与许可证声明。其他第三方组件可能有各自的许可证，完整归因见 [NOTICE](NOTICE)。

本仓库只包含 GPL-3.0 代码。Bitwarden 另有单独许可的商业模块（"Bitwarden License v1.0"，上游放在 `bitwarden_license/` 目录），本仓库的任何提交都不包含这些代码；依赖这些模块的命令不在本次分发范围内。

Bitwarden 的名称与标识归其所有者；本项目不是 Bitwarden 官方产品。

## 安全报告

AgentKeybox 自身的安全问题请使用 GitHub 的私有漏洞报告功能。请勿在公开 issue 中包含密码、令牌或保险库数据。未修改的上游 Bitwarden 组件问题请参阅上游项目的安全策略。
