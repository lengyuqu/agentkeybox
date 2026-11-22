# MVP 验证记录：2026-11-03

## 环境

- macOS，本机 Node `v26.12.1`、npm `11.20.0`。
- 上游 CLI `cli-v2026.10.1`，commit `91214c3b978edb5496a32a946451960fe7d44531`。
- 临时 Vaultwarden `1.37.5`，镜像 digest `sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f`。
- 容器只绑定 `127.0.0.1` 随机端口，HTTPS 临时证书经显式 CA 信任验证；没有关闭 TLS 校验。
- 随机测试账户、独立生成的加密条目、独立 `AKB_HOME`，未访问用户已有 Vaultwarden 或本机 Bitwarden 配置。

## 结果

- 官方 GPL CLI 基线构建成功。
- AgentKeybox 独立构建成功。
- AgentKeybox 新增 TypeScript 文件 ESLint 通过；新增文件 Prettier 检查通过。
- 5 个单元测试通过：元数据不泄密、字段读取限制、精确/重复/删除引用、错误脱敏、空值/重复/链接字段。
- 15 组真实容器集成检查通过：
  1. 创建临时账户和独立加密测试条目。
  2. 拒绝 HTTP；登录失败后无活动账户。
  3. 直接复用源码服务完成密码登录。
  4. 独立 CLI 进程共用解锁会话。
  5. 同步、精简列表、按引用读取明文密码。
  6. 锁定后拒绝读取，错误密码拒绝解锁，正确密码恢复读取。
  7. 另一个 API 客户端修改后，下次读取获取新值。
  8. 重复逻辑引用报错。
  9. 不同 profile 的账户状态隔离。
  10. 数据文件不含测试主密码或业务密码明文，无单独会话文件。
  11. 服务重启保留登录但失去解锁状态。
  12. 空闲超时锁定，状态轮询不续期。
  13. 最长会话超时锁定。
  14. 服务器关闭后拒绝返回缓存密码。
  15. 注销清理登录状态，重复注销幂等。

测试容器和临时账户数据已由脚本清理。日志仅打印检查名称，不打印随机凭据。

## 复用过程中发现的边界

- SDK 强制 HTTPS，本地 HTTP 测试也不例外。
- 上游 `logout()` 需要活动账户；封装层需要守卫，避免在登录失败时掩盖原始错误。
- 上游解锁命令仍使用进程级环境 session key；因此当前采用每 profile 独立服务进程。
- 读取返回窄字段投影，不能直接输出完整 `CipherView`，否则会包含不需要的秘密。
- 构建 source map 未发现 `bitwarden_license/` 或 `commercial-sdk` 来源；这不是完整的分发许可证审计。

## 尚未验证/实现

用户真实 Vaultwarden 地址、版本和账户尚未提供，因此未做现网联调。上述结果只覆盖本地容器中的普通 PBKDF2 密码账户和个人登录条目，不代表组织共享、Argon2、2FA、API Key、SSO、SSH/Passkey 使用流程或 Windows 已验证。

当前是最小可运行源码原型，尚未实现完整命令规划中的修改操作、`run`、MCP、系统钥匙串、离线读取、打包发布和丰富错误分类。没有提交或推送这些定制改动。

## macOS 独立文件验证（后续）

- 新增 `dist:akb:mac-arm64` 构建命令，复用 `@yao-pkg/pkg`，嵌入其支持的 Node `22.15.1`。当前工具不支持 Node 24 目标。
- `package.agentkeybox.json` 显式包含 Webpack 动态 JS chunk、WASM、语言文件；没有依赖打包器猜测动态 require 路径。
- 打包模式启动服务时调用自身可执行文件，不再传 Node 脚本参数，并处理 pkg 的 `PKG_EXECPATH` 子进程引导行为。
- 发现并修正同步状态竞态：上游同步会先清空条目状态为 null，Lowdb 状态通知可能滞后；原读取接口将 null 映射为空仓库。读取现在等待非 null 状态（5 秒超时），并使用上游显式解密，不把 SDK 解密失败伪装成 NOT_FOUND。
- 16 组独立文件真实容器集成检查通过，覆盖上文 15 组，并增加十次连续同步/读取。程序复制到包含空格的临时目录，从非仓库目录运行，产品进程 PATH 中无 Node/npm/bw；证书仍通过显式 CA 信任校验。
- 5 个单元测试、ESLint、Prettier 通过。
- Mach-O arm64 可执行文件约 89 MiB；`codesign --verify` 校验通过，为本地 ad-hoc 签名，未做 Developer ID 签名或公证。
- 构建器仍提示动态 require（已通过 scripts glob 显式包含），以及未使用的可选代理模块和 Linux xdg-open 提示；本次验证的是 macOS 密码登录流程，不代表这些可选路径已验证。
- 输出目录：`apps/cli/dist/agentkeybox/macos-arm64/`，含二进制、README、许可证和 SHA256SUMS；Intel 架构未构建验证。
- 测试容器及随机账户数据已清理；用户现有 Vaultwarden 和 phynews profile 未参与此次凭据测试。
