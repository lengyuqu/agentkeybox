# 源码复用边界

基线：Bitwarden clients `cli-v2026.11.0` / `28b247ac34877882aaef4faea082a9f3bb201114`。

| 能力              | 复用模块                                                                                             | MVP 调用方式                                                                |
| ----------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 初始化/依赖装配   | `apps/cli/src/service-container/service-container.ts`                                                | macOS/Windows 每条命令初始化一次，Linux 每服务进程一次                      |
| 服务器地址        | `apps/cli/src/platform/commands/config.command.ts`                                                   | `ConfigCommand.run`，禁止登录后改服务器                                     |
| 密码登录/二次验证 | `apps/cli/src/auth/commands/login.command.ts`                                                        | `LoginCommand.run`，始终非交互，丢弃包含 session 的响应                     |
| 登录策略          | `libs/auth/src/common/`                                                                              | 通过服务容器复用，不重新实现认证协议                                        |
| 解锁              | `apps/cli/src/key-management/commands/unlock.command.ts`                                             | `UnlockCommand.run` → `UnlockService`，密码来自终端/标准输入                |
| 锁定              | `apps/cli/src/auth/commands/lock.command.ts`                                                         | `LockCommand.run` → `LockService`                                           |
| 同步              | `libs/common/src/platform/sync/default-sync.service.ts`                                              | `fullSync(true, true)`，失败不读取缓存                                      |
| 账户身份          | `AccountService` / `AuthService`                                                                     | 状态和 active account，不依赖 CLI 文本输出                                  |
| 条目解密          | `ENCRYPTED_CIPHERS` 状态 + `CipherService.decrypt`                                                   | 等待同步后的非 null 状态，过滤删除/partial 项，使用上游逐条解密并返回窄字段 |
| 密钥管理/密码学   | `libs/key-management`、`libs/unlock`、`libs/legacy-crypto`、`@bitwarden/sdk-internal`                | 全部复用上游，不复制到产品代码                                              |
| 本地持久化        | `LowdbStorageService`                                                                                | 独立的 AKB profile 目录                                                     |
| 解锁材料存储      | `NodeEnvSecureStorageService`                                                                        | Keychain 或 Windows Credential Manager 保存 BW_SESSION，命令启动时恢复      |
| 条目写入          | `CipherService.createWithServer` / `updateWithServer` / `softDeleteWithServer` / `restoreWithServer` | 新建、改一个字段、移入回收站、恢复；只读条目先拒绝，服务端拒绝时不透传文本  |
| 密码生成          | `PasswordGenerationService.generatePassword`                                                         | 生成的密码只存入保险库，不返回                                              |
| 一次性验证码      | `TotpService.getCode$`                                                                               | 返回验证码和剩余秒数；`run` 在不足 3 秒时等下一个窗口                       |
| 域名匹配          | `CipherService.filterCiphersForUrl`                                                                  | `account list --url`，等价域名和 URI 匹配规则                               |
| 通行密钥          | `Fido2AuthenticatorService.getAssertion` / `makeCredential`、`isValidRpId`                           | 无界面的固定凭据界面；签名、认证器数据、计数器全部来自上游                  |

## 定制层

- `main.ts`：Commander 命令入口、隐藏输入、标准输出约定。
- `one-shot.ts`、`session-store.ts`：macOS 和 Windows 复用前台执行、按 profile 串行、系统凭据恢复的流程。
- `keychain.swift`、`windows-credentials.c`：系统凭据读写，Windows 助手也检查交互桌面和 profile 权限。
- `transport.ts`：共享 profile 路径与 Linux 后台服务，macOS 仅保留停止旧服务的入口。
- `backend.ts`：认证/锁定状态、超时策略、同步、条目读取，以及写入、删除、恢复、通行密钥各操作。
- `protocol.ts`：稳定响应、错误码、精确引用、字段映射和 `run` 的密钥规格解析。
- `write.ts`：新建登录和改字段的参数校验、请求构造、冲突和失败的分类。
- `run.ts`、`redact.ts`：不经 shell 启动命令并注入值；输出经过滤，值被替换为 `[REDACTED:名称]`。
- `operations.ts`：命令行和 MCP 共用的“执行一个操作”“解析、运行、记录一次 `run`”，以及 MCP 用的串行队列。
- `mcp.ts`：手写的 MCP 服务，没有任何工具返回凭据的值。
- `passkey.ts`：通行密钥的参数校验、浏览器会拼的客户端数据、只返回公开内容的回复。
- `audit.ts`：`audit.log` 的记录格式、轮转，以及只保留合法形状的引用和字段名。
- `session-state.ts`：前台模式下的会话计时（两个时间戳），配合 `policy.ts` 的空闲和总时长上限。
- `webpack.agentkeybox.js`：独立构建入口和输出，保留官方 `bw` 构建。

AKB 直接调用上游源码，仅提供自身的认证和凭据命令。系统凭据助手在单次操作后退出。

## 后续设计约束

1. 上游服务不是稳定 SDK。每次升级固定标签并跑真实 Vaultwarden 闭环，不直接跟随 main。
2. 将会话存储从全局环境变量迁移到内存 provider 后，仍需确认上游 SDK 与全局容器是否允许同进程多账户；当前进程隔离最明确。
3. 条目修改一次只改一个字段，其他部分保持原样，保存交给上游 SDK，不在 AKB 里新增加密逻辑。版本冲突靠上游抛出的 `ErrorResponse` 识别（它不是 `Error`，只有 `message` 和状态码）；写入前刚同步过，实际很难碰上冲突，冲突后的那一次重试只有单元测试覆盖。不把本机队列当成跨机器事务。
4. 当前错误优先避免泄露，登录失败统一报告。后续基于结构化 AuthResult 拆分 2FA、新设备验证、凭据错误和网络错误。
5. TOTP 已用独立的 RFC 6238 计算核对。组织共享、只读/隐藏密码策略、SSH、Argon2 和 2FA 需要单独联调；当前闭环不代表这些场景已验证。写入时对组织数据所有权和受限条目类型的检查没有复制，由服务端决定是否接受。
6. 通行密钥只处理每个登录里的第一个；AKB 不声称做过用户验证；创建是先存后注册，不是原子的。真实网站和浏览器没有试过。
7. 任何会进入模型上下文的出口（MCP 工具结果、`run` 的输出、错误信息、审计日志）都不得包含凭据的值。新增出口时要先对照这一条。
8. 数据由 Vaultwarden/上游模型保存，不另建一套中心凭据数据库。
