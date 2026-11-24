# 错误码、平台差异与边界

## 错误码速查

从 `apps/cli/src/agentkeybox/` 源码提取，按场景分组。

### 状态 / 会话 / 锁屏

| 错误码 | 含义与处理 |
| --- | --- |
| `VAULT_LOCKED` | 保险库锁定或会话过期。让用户自己在终端 `auth unlock`；不要索要主密码 |
| `SCREEN_LOCKED` | 桌面锁屏，拒绝读取。等用户解锁后重试 |
| `SCREEN_STATE_UNAVAILABLE` | 无法确认桌面状态。按锁屏处理，停止并让用户确认 |
| `SESSION_UNAVAILABLE` | 会话不可用，需重新解锁 |
| `AUTH_REQUIRED` / `UNLOCK_FAILED` | 需登录 / 解锁失败 |
| `KEYCHAIN_UNAVAILABLE` (macOS) / `CREDENTIAL_STORE_UNAVAILABLE` (Windows) | 系统凭据存储不可访问，无法保存会话密钥 |
| `PROFILE_BUSY` | 同 profile 并发冲突。串行化操作 |
| `INVALID_PROFILE` / `INVALID_SESSION` | profile 或会话参数非法 |
| `SESSION_UNAVAILABLE` / `SERVICE_STOPPED` / `SERVICE_UNAVAILABLE` / `SERVICE_RUNNING` | Linux 后台服务状态异常 |
| `SERVICE_START_FAILED` / `SERVICE_STOP_FAILED` | 服务启停失败 |

### 配置 / 登录 / 同步

| 错误码 | 含义与处理 |
| --- | --- |
| `NOT_CONFIGURED` | 未配置服务器，先 `config server` |
| `INVALID_SERVER` / `INVALID_URL` | 服务器地址非法或不是 HTTPS |
| `CONFIG_FAILED` | 配置写入失败 |
| `LOGIN_FAILED` / `ALREADY_LOGGED_IN` / `LOGOUT_REQUIRED` | 登录状态冲突 |
| `INPUT_REQUIRED` / `INPUT_TOO_LARGE` / `INVALID_ARGUMENT` / `INVALID_OPTIONS` / `INVALID_REQUEST` | 输入参数问题，核对 `--help` |
| `SYNC_FAILED` | 在线同步失败，不返回缓存凭据。检查网络/代理/服务器 |
| `SYNC_STATE_TIMEOUT` / `TIMEOUT` | 同步或操作超时 |
| `DECRYPT_FAILED` / `TOKEN` / `BW_SESSION` / `BW_NOINTERACTION` / `BW_QUIET` | 上游 SDK 会话/解密状态异常 |

### 引用 / 字段 / 写入

| 错误码 | 含义与处理 |
| --- | --- |
| `INVALID_REFERENCE` | 引用不是精确 `ref:` / `id:`，或格式非法 |
| `NOT_FOUND` | 条目不存在或在回收站里找不到 |
| `AMBIGUOUS_MATCH` | 引用匹配多个条目，改用 `id:` |
| `REF_EXISTS` | 引用已被占用（新建重复或恢复时冲突） |
| `FIELD_NOT_FOUND` / `INVALID_FIELD` / `AMBIGUOUS_FIELD` / `UNSUPPORTED_FIELD` / `RESERVED_FIELD` | 字段不存在、不支持或保留（`agentkeybox.` 前缀） |
| `INVALID_SECRET_SPEC` / `INVALID_CHALLENGE` / `INVALID_DURATION` / `INVALID_POLICY` | `--env` / 挑战 / 时长 / 策略参数非法 |
| `INVALID_SSH_KEY` / `SSH_KEY_FAILED` | SSH 私钥无法解析或类型不支持；错误不回显输入 |
| `INVALID_TOTP` / `TOTP_FAILED` | TOTP 种子格式非法 / 生成失败 |
| `WRITE_CONFLICT` | 写入基于旧副本被服务端拒绝，已重试一次仍失败 |
| `WRITE_FAILED` / `PERMISSION_DENIED` | 写入失败 / 只读条目 |

### 运行 / 通行密钥 / 审计

| 错误码 | 含义与处理 |
| --- | --- |
| `RUN_FAILED` (9) | 子进程启动失败；AKB 自身错误用 2–10，用 `--json` 区分 |
| `PASSKEY_EXISTS` / `PASSKEY_FAILED` / `PASSKEY_UNAVAILABLE` | 已有 passkey / 签名或创建失败 / 不可用 |
| `INVALID_ORIGIN` | origin 不匹配或协议非法 |
| `AUDIT_FAILED` | 审计日志写不进去，读取类操作不返回凭据；写入类照常完成但带 `audit_failed: true` |
| `UNSAFE_DIRECTORY` | profile / TEMP 目录不是当前用户私有；见下 |
| `INTERNAL_ERROR` / `INVALID_OPERATION` / `IPC_ERROR` / `SOCKET_PATH_TOO_LONG` | 内部/IPC 错误 |

## 平台差异

| 项 | Windows | macOS | Linux |
| --- | --- | --- | --- |
| 会话恢复密钥 | Credential Manager | Keychain（需 12+） | 后台服务 |
| 构建产物 | `akb.exe` + `akb-credentials.exe` 同目录 | `akb` + `akb-keychain` 同目录 | `build-akb/akb.js` |
| 构建命令 | `npm run build:akb:win-x64 -w @bitwarden/cli`（含助手编译） | `npm run dist:akb:mac-arm64 -w @bitwarden/cli` | `npm run build:akb -w @bitwarden/cli` |
| 超时策略 | 默认无上限，锁屏控制 | 默认无上限，锁屏控制 | 支持 `session policy` / `AKB_IDLE_MS` / `AKB_MAX_MS` |
| 桌面要求 | 交互桌面；RDP 断开/无桌面会拒绝 | 解锁的 Mac | 无 |

### Windows `UNSAFE_DIRECTORY`

AKB 要求 profile 目录归当前用户所有且权限私有。管理员终端新建的目录默认归 Administrators 组，会触发此错误。**用普通权限终端运行**，或把 `AKB_HOME` 指到当前用户私有目录。这是有意的安全检查，不要放宽。

- webpack 每次构建会清掉输出目录里的 `akb-credentials.exe`；只重跑 webpack 后必须重新编译助手，否则读取失败。
- 助手需 Visual Studio 生成工具（`vcvars64.bat` 后的 `cl.exe`）；mingw 头文件因缺 `WTSINFOEX` 定义会失败。

### 代理

- 支持 `http_proxy` / `https_proxy`；流量经代理隧道，不绕过。
- 已知限制：agent 路径不读 `NO_PROXY`，回环地址也走代理（与上游一致，代理能正确隧道）。
- 私有 CA：`NODE_EXTRA_CA_CERTS` 指向证书。
- 独立 exe 的代理打包依赖 webpack allowlist，已修复；勿从 allowlist 移除 `proxy-agent-negotiate`。

## 数据位置

- 默认 `~/.agentkeybox/profiles/<profile>/bw`，`AKB_HOME` 可隔离。
- `audit.log`：每次 get/resolve/create/set/delete/run 追加一行 JSON，只记引用/ID/字段/环境变量名/命令名/退出码，不含值；超 5 MiB 轮转一份。POSIX 权限 0600；Windows 沿用 profile 目录 ACL。`AKB_AUDIT=off` 关闭。
- `session-state.json` / `session-policy.json`：只有时间戳和策略，无密钥。

## 能力边界（不要假定可用）

以仓库 `AGENTKEYBOX.md` 为准。未验证/未实现：

- 真实浏览器、真实网站、真实 MCP 客户端端到端（MCP 只用手写 JSON-RPC 客户端核对）
- 写入冲突后重试的真实服务端路径（仅单元测试覆盖）
- 标准用户 / UAC 开启的 Windows 环境（验证机是内置 Administrator、UAC 关闭）
- 真实 Linux 桌面 + 普通用户（端到端在 Docker root 容器里）
- 二次验证账户、组织共享条目、只读集合、Argon2 账户联调
- API Key / SSO、生物识别、用 passkey 登录保险库本身、彻底清除条目、完整 profile 管理
- 处理文件夹、收藏、附件、组织归属

安全边界：AKB 只保证凭据不进入 agent 上下文、对话记录和日志；不承担本机运行环墙安全（同系统用户改文件）。`run` 打码防意外泄露，不防恶意 agent 故意变换输出。操作系统用户仍是信任边界。
