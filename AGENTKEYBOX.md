# AgentKeybox 源码定制 MVP

面向 agent 的 Vaultwarden 客户端。直接复用 Bitwarden TypeScript/SDK 服务，不启动或解析 `bw` 子进程。保留官方目录结构和 README，定制代码位于 `apps/cli/src/agentkeybox/`。

## 当前状态

**Windows 开发版的功能范围已经做完，并用真实 Vaultwarden 做过端到端验证；它仍是开发版，不是已发布、已全面验证的产品。** 下面如实列出做了什么、验证了什么、没验证什么。

### 已实现

| 方面       | 内容                                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------- |
| 发现       | `account list`（`--search`、`--url`、`--trashed`）、`account show`，只返回元数据                  |
| 使用凭据   | `run` 把值注入命令环境并打码；`credential get`（给人手动用）；TOTP 验证码                         |
| 修改       | `item create`、`item set`、`item delete`（进回收站）、`item restore`；值只走标准输入或由 AKB 生成 |
| 通行密钥   | `passkey assert`（登录）、`passkey create`（为网站新建），私钥不离开保险库                        |
| agent 接入 | `akb mcp`：没有任何工具返回凭据的值                                                               |
| 会话       | 锁屏门控、`session policy` 的空闲和总时长上限、系统凭据存储                                       |
| 审计       | `audit.log` 记录谁用了哪个引用，不含值                                                            |

### 验证情况

| 平台和环节                                             | 状态                                                                                                                                                        |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows，真实 Vaultwarden 端到端（30 项）              | 通过。移除商业模块并修复代理打包缺陷后于 2026-11-23 重跑，用 `node apps/cli/build-akb/akb.js` 运行，退出码 0，见“验证”                                      |
| Linux，后台服务模式，真实 Vaultwarden 端到端（31 项）  | 通过。在 Docker 里的 `node:24`（Debian、x86_64，以 root 运行）中运行，宿主是 WSL2 上的 Docker Desktop，见“验证”。含 Unix 套接字服务、重启、空闲和总时长超时 |
| Linux，AKB 单元测试（167 项）                          | 全部通过，包括 `policy.spec`                                                                                                                                |
| Linux，CNB 流水线（类型检查、AKB 单元测试、独立构建）  | 核实时（共 20 次运行）全部成功，包括每一次合并到 `main`                                                                                                     |
| Windows，AKB 单元测试（167 项）                        | 全部通过。`policy.spec` 的 POSIX 权限位断言改为仅在 POSIX 平台执行（Windows 报告 0666，私有访问由 profile 目录的 DACL 保证）                                |
| macOS，真实 Vaultwarden 端到端（30 项）                | 通过。移除商业模块后重跑，退出码 0，含 Keychain 助手、锁屏门控、空闲与总时长上限；运行期间锁屏会让检查停在 `SCREEN_LOCKED`，解锁后全绿                      |
| macOS 独立可执行文件（`dist:akb:mac-arm64`）           | 早前验证过；移除商业模块这一轮没有重跑                                                                                                                      |
| 真实 Linux 机器、桌面环境                              | **没有验证。** Linux 的端到端是在容器里以 root 运行的，不是在装有桌面的 Linux 主机上，也没有用普通用户跑                                                    |
| Windows 锁屏门控的端到端步骤（`AKB_TEST_SCREEN_LOCK`） | 2026-11-22 实测通过：真实锁屏时拒绝读取，解锁后无需重新输入主密码即可同步和读取。2026-11-23 在 RDP 会话中重试未成功（见“验证”），沿用前次记录               |
| 打包出的 `akb.exe`（`dist:akb:win-x64`）               | 通过：2026-11-23 用修复后的构建重跑 30 项端到端检查，退出码 0（带空格路径、PATH 排除 Node/npm/bw）；锁屏步骤见上一行                                        |
| Windows 普通权限（标准用户 / UAC 开启）环境            | **没有验证。** 验证机是内置 Administrator 账户且 UAC 关闭，所有进程都持完整令牌；私有 TEMP 只满足目录检查，不等同于标准用户环境                             |
| Windows，代理路径（`http_proxy`/`https_proxy`）        | 通过。2026-11-24 用独立进程的记录代理实测 4 轮登录（源码构建与打包 exe），流量全部经代理隧道，未绕过，见“验证”                                              |

### 没有验证过的

- **没有对真实网站、真实浏览器或真实 MCP 客户端试过。** 通行密钥的签名只用测试里的独立验签核对过，MCP 只用手写的 JSON-RPC 客户端核对过。
- **写入冲突后的重试没有在真实服务端走通过。** AKB 写入前刚同步，实际很难碰上冲突；识别方式有单元测试，服务端拒绝旧副本写入的文本已核对。
- 要求用户验证的网站：AKB 不声称做过用户验证，这类网站会拒绝。
- 二次验证账户、组织共享条目、只读集合、Argon2 账户：没有联调。
- 通行密钥的创建是先存后注册，不是原子的（见“通行密钥”）。
- `run` 的打码是兜底，不是沙箱（见“用 `run` 注入凭据”）。
- 签名和公证：Windows 和 macOS 的可执行文件都没有做发布级签名。

### 不属于这个项目的

运行环境本身的安全（本机是否可信、同一系统用户是否会改文件）不由 AKB 负责；AKB 只负责不让凭据从 agent 这一侧泄露，也就是不进入它的上下文、对话记录和日志。

## 上游基线

- 仓库：<https://github.com/bitwarden/clients>
- CLI 标签：`cli-v2026.11.0`
- Commit：`28b247ac34877882aaef4faea082a9f3bb201114`
- 采用 GPL 构建入口。上游 `bitwarden_license` 商业模块（Bitwarden License v1.0，仅限内部开发测试、禁止分发和生产使用）已从本仓库移除，AKB 对它的依赖闭包为空；两个仓库现在都只含 GPL-3.0 代码。保留上游许可证和版权声明。
- 商业模块源码不在本仓库的任何历史提交里。它只存在于 CNB 私有仓库移除前的历史中，公开仓库没有那段历史；需要时只能回到上游 `bitwarden/clients` 获取。

## 构建与使用

在仓库根目录运行（Node/npm 版本遵循根 `package.json`）。macOS 上 Keychain 助手需要 macOS 12 或更高版本，源码构建需要 Xcode 或命令行开发工具；Windows 上的构建要求见“Windows x64 开发版”，构建要用 `build:akb:win-x64`，它会同时编译 Windows 助手：

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build:akb --workspace @bitwarden/cli
node apps/cli/build-akb/akb.js --help
```

仓库根目录已有 `./akb` 启动器：

```bash
./akb --profile home config server https://vault.example.com
./akb --profile home auth login --email you@example.com
./akb --profile home auth status --json
./akb --profile home sync --json
./akb --profile home account list --search github --json
./akb --profile home account list --url https://github.com/login --json
./akb --profile home account show id:ITEM_UUID --json
./akb --profile home credential get id:ITEM_UUID --field password --raw
./akb --profile home auth lock
./akb --profile home auth unlock
```

交互登录与解锁在终端隐藏读取主密码，不要把主密码写进 agent 对话或命令参数。自动化可使用 `--password-stdin`；`--json`、`--no-input` 或非 TTY 不会提示输入。二次验证可传 `--method` 和 `--code`，但目前仅普通密码账户经过真实容器验证。

引用支持 `id:<条目 UUID>` 和 `ref:<精确名称>`。后者对应条目的 `agentkeybox.ref` 自定义字段。重复引用报错。凭据字段支持 `password`、`username`、`notes`、`private_key`、`public_key`、`totp` 和 `custom:<字段名>`；只在明确读取时输出值。`--raw` 不添加换行。

`account list --url <地址或域名>` 只列出匹配该地址的登录，复用上游的域名和 URI 匹配规则（含等价域名），可与 `--search` 同时使用。裸域名会按 `https://` 处理。结果里的 `uris` 只显示协议加主机，不含路径和查询串，因为地址里可能带令牌。

`totp` 字段由上游 SDK 生成一次性验证码。`credential get --field totp --json` 同时返回 `expires_in`（剩余有效秒数）。AKB 面向 Vaultwarden，不复制上游命令行对 TOTP 的会员检查。

## 用 `run` 注入凭据

给 agent 用凭据时优先用 `run`，而不是 `credential get`：值只注入子进程的环境变量，AKB 自己不打印，调用方（包括 agent 的上下文和对话记录）看不到明文。

```bash
./akb --profile home run \
  --env GH_TOKEN=ref:github/ci \
  --env DB_USER=ref:db/prod#username \
  -- gh pr list
```

- `--env NAME=<引用>[#字段]`：引用同上；字段默认 `password`，可写 `#username`、`#notes`、`#private_key`、`#totp`、`#custom:<字段名>` 等。`#totp` 注入的验证码至少还有 3 秒有效期，不足时会等到下一个窗口再生成。`#` 后不是合法字段名时，它属于引用本身。可重复使用，环境变量名不区分大小写地不得重复。
- 全部引用先一次性解析：任何一个失败，命令都不会启动。
- 命令直接启动，不经过 shell，参数不会被解释或展开。Windows 上 `.cmd`、`.bat` 需要通过解释器运行，例如 `-- cmd /c script.cmd`。
- 子进程的标准输出和标准错误经过滤，注入的值会被替换为 `[REDACTED:<变量名>]`。同时覆盖原文、JSON 转义、URL 编码、base64、base64url 和十六进制，并处理跨数据块的情况。长度不足 4 个字符的值不过滤。过滤是兜底，不是保证：被命令以其他方式变换过的值无法识别。真正的保证是值不进入调用方的上下文，除非命令自己把它打印出来。
- 标准输入保持连接；标准输出和标准错误是管道，不是终端，因此没有颜色和交互提示。
- 退出码原样透传，被信号终止时为 `128+信号号`。AKB 自身错误（启动前）使用 2–10；`RUN_FAILED` 为 9。因此子命令自己的退出码可能与之重合，需要区分时用 `--json`，AKB 的失败会以 JSON 输出。
- 命令行里只出现引用，不出现值；也不会写 `.env` 之类的文件。

`credential get` 仍保留给人在终端里手动使用。需要禁止 agent 直接调用它时，可在 harness 的权限规则中拒绝 `akb credential get`。

## 新增和修改条目

写入只处理登录条目，且 AKB 不回显任何写入的值：生成的密码只存入保险库，之后用 `run` 注入或显式 `credential get` 读取。

```bash
# 新增：密码由 AKB 生成并保存，不显示
./akb --profile home item create --name GitHub --ref github/ci \
  --username bot --url https://github.com --generate-password --length 32

# 新增：密码从标准输入读取
printf '%s' "$PASSWORD" | ./akb --profile home item create --name Svc --ref svc/api --password-stdin

# 轮换：生成新密码，或从标准输入读取新值
./akb --profile home item set ref:github/ci --field password --generate
printf '%s' "$NEW_TOKEN" | ./akb --profile home item set ref:github/ci --field password --stdin

# 设置 TOTP 种子、备注、自定义字段（新建的自定义字段为隐藏类型）
printf '%s' "$SEED" | ./akb --profile home item set ref:github/ci --field totp --stdin

# 删除：移到保险库的回收站，不是彻底销毁
./akb --profile home item delete ref:github/ci

# 看回收站里有什么，再恢复其中一个
./akb --profile home account list --trashed --search github
./akb --profile home item restore id:<uuid>
```

- `delete` 只做软删除：条目进入回收站，服务端仍然保存，所有者可以在官方客户端里恢复，AKB 也可以用 `item restore` 恢复。AKB 没有彻底清除命令，所以 agent 无法永久销毁数据。删除后该引用立即可以重新使用。
- `account list --trashed` 列出回收站里的登录（只含元数据，多一个 `deleted_at`），可以配合 `--search`，不能和 `--url` 一起用。`item restore` 同样要精确的 `ref:<名称>` 或 `id:<uuid>`，只在回收站里找。如果回收站里有多个同名引用，用 `id:`。
- 恢复前会检查引用：删除之后这个引用若被别的登录用了，恢复返回 `REF_EXISTS`，不会让两个登录共用一个引用。只读条目返回 `PERMISSION_DENIED`。MCP 里对应 `akb_find` 的 `trashed` 参数和 `akb_restore`。
- 必须给出精确的 `ref:<名称>` 或 `id:<uuid>`，名称片段、搜索词或不带前缀的文字都会被拒绝（`INVALID_REFERENCE`）。找不到返回 `NOT_FOUND`，引用不唯一返回 `AMBIGUOUS_MATCH`，只读条目返回 `PERMISSION_DENIED`。
- 命令不要求二次确认，因为 agent 可以自行加确认参数，那只是摆设。可恢复性才是这里的保护。

- `--ref` 可带或不带 `ref:` 前缀，不得与现有条目重复，否则返回 `REF_EXISTS`。`--url` 可重复，裸域名按 `https://` 处理。
- `set` 可修改 `password`、`username`、`notes`、`totp` 和 `custom:<字段名>`，一次一个字段，其他部分保持原样。`agentkeybox.` 开头的自定义字段由 AKB 管理，不能修改。`--generate` 只用于密码，长度 8 到 128，默认 24。
- 值只通过标准输入传入，不接受命令行参数，因此不会出现在命令历史或 agent 的对话记录里。单个值上限 64 KiB，末尾一个换行会被去掉。
- TOTP 种子保存前先检查格式：base32 密钥、`otpauth://totp/` 地址或 `steam://` 密钥，其他文本返回 `INVALID_TOTP`。上游 SDK 对几乎任何文本都能“生成”验证码，所以不能靠试生成来判断种子是否有效；格式正确的种子仍可能是错的，需要用 `credential get --field totp` 对照确认。
- 写入前先在线同步，并通过上游 SDK 保存，不在 AKB 里新增加密逻辑。服务端报告条目已被他处修改时，会在最新数据上重试一次；仍失败返回 `WRITE_CONFLICT`，其他拒绝返回 `WRITE_FAILED`。错误不透传服务端内容。
- 只读条目（例如组织共享的只读集合）返回 `PERMISSION_DENIED`。上游命令行里的组织数据所有权和受限条目类型策略检查没有复制，由服务端决定是否接受。
- 冲突是根据上游抛出的错误判断的：错误里的文本含 `out of date` 或 `conflict`，或状态码为 409。上游 API 客户端抛的是 `ErrorResponse`，它不是 `Error`，只有 `message` 和状态码；早先的写法只认 `Error`，会把真实的冲突当成普通失败而不重试，现已修正并有单元测试。服务端对基于旧副本的写入会拒绝，文本符合上述规则，已用真实 Vaultwarden 核对。
- 但 AKB 写入前刚同步过，实际很难碰上冲突：端到端里让另一个客户端以约每 0.1 秒一次的频率不停改同一个条目，8 次写入全部直接成功，没有触发一次冲突。所以“冲突后重试一次”这条路径没有在真实环境里走通过，只有单元测试覆盖。
- 不处理文件夹、收藏、附件和组织归属。

## 审计日志

每次取出或修改凭据都会在 profile 目录的 `audit.log` 追加一行 JSON，用来事后查“哪个引用在什么时候被谁的命令用过”。

```json
{"ts":"2026-11-21T10:00:00.000Z","op":"resolve","outcome":"ok","targets":[{"env":"GH_TOKEN","ref":"ref:github/ci","id":"…","field":"password"}]}
{"ts":"…","op":"run","outcome":"ok","command":"gh","targets":[…],"exit_code":0}
```

- 记录 `get`、`resolve`、`create`、`set`、`delete` 和 `run`，成功和失败都记（失败带 `code`）。`list`、`show` 只是发现，不记。
- 只写时间、操作、引用、条目 ID、字段名、环境变量名、程序文件名和退出码。**不写任何值**，也不写命令参数（参数里可能带密钥）。引用和字段名只有符合格式才记录，否则留空。
- 读取类操作如果记录写不进去，凭据不会返回（`AUDIT_FAILED`）。写入类操作已经完成，照常返回，但回复里带 `audit_failed: true`。`run` 在命令结束后才记录，写入失败只在 AKB 自己的标准错误输出里提示。
- 文件超过 5 MiB 时改名为 `audit.log.1`，只保留一份旧文件。POSIX 下权限为 0600；Windows 沿用 profile 目录的权限。
- 设置环境变量 `AKB_AUDIT=off` 可关闭。日志不防篡改：同一操作系统用户能改写它，它记录的是 AKB 的使用，不是对抗本机攻击者的证据。

## 通行密钥

保险库里已有的通行密钥可以用来登录网站，私钥始终留在保险库里：AKB 让上游的 FIDO2 认证器对网站给的挑战签名，只有签好的响应离开进程，这和浏览器发给网站的内容相同，都是公开信息。

```bash
./akb --profile home passkey assert ref:site/login   --origin https://example.com --challenge "$CHALLENGE_B64URL"
```

- 输出 `credential_id`、`client_data_json`、`authenticator_data`、`signature` 和 `user_handle`（均为 base64url），`rp_id` 是这个通行密钥所属的网站。把它们交给网站的服务端验证即可。
- `--origin` 必须是 https 地址（本地开发允许 `http://localhost`），只保留协议、主机和端口，路径和参数会被丢弃。它必须是这个通行密钥所属网站的合法来源，否则返回 `INVALID_ORIGIN`。`--challenge` 是网站发来的挑战，base64url 文本。
- 签名、认证器数据和计数器都由上游代码生成，AKB 只负责拼出浏览器会拼的客户端数据并取它的哈希，不新增加密逻辑。计数器大于 0 的通行密钥，每次使用后会把递增的计数器保存回服务端。
- 只用第一个通行密钥；一个条目有多个时，上游也只用第一个。
- **不声称做过用户验证。** AKB 没有人可以验证，所以响应里的用户验证标志是关闭的。要求用户验证的网站会拒绝这个响应。
- 设置了“每次使用都要重新输入主密码”的条目返回 `PERMISSION_DENIED`，这一步只有人能完成。
- `account show` 和 `account list` 的结果里有 `passkey_rp_ids`，`credential_fields` 里有 `passkey`，agent 据此知道哪些登录有通行密钥。
- MCP 里对应 `akb_passkey_assert`，只读模式下也提供。审计日志记录引用、条目 ID 和来源。
- 浏览器里的实际登录还需要调用方把响应交给页面，AKB 不负责页面交互。

### 为网站新建通行密钥

```bash
./akb --profile home item create --name Example --ref site/login --url https://example.com --generate-password
./akb --profile home passkey create ref:site/login \
  --origin https://example.com --challenge "$CHALLENGE_B64URL" \
  --user-id "$USER_ID_B64URL" --user-name alice@example.com --rp-name Example
```

- 网站发来的创建参数里，`--challenge` 和 `--user-id`（`user.id`）按网站给的 base64url 原样传入，`--user-name` 是网站为这个账号显示的名字；可选 `--display-name`、`--rp-id`（默认取来源的主机名）和 `--rp-name`。
- 通行密钥保存在**已有的登录**里，所以先用 `item create` 建一个。上游的认证器生成 P-256 密钥并随登录一起保存到服务端，AKB 只返回公开的内容：`credential_id`、`client_data_json`、`attestation_object`、`authenticator_data`、`public_key`（SPKI，base64url）、`public_key_algorithm`（-7）。证明格式是 `none`。
- **不会覆盖已有的通行密钥。** 登录已经有通行密钥时返回 `PASSKEY_EXISTS`：覆盖会让它的主人在网站那边没完成注册时被锁在外面。只读条目、要求重新输入主密码的条目返回 `PERMISSION_DENIED`，不是登录类型的条目返回 `UNSUPPORTED_FIELD`。站点 id 与来源不匹配返回 `INVALID_ORIGIN`。
- 同样不声称做过用户验证，并总是创建可发现的（驻留）通行密钥。
- **先存后注册，不是原子的。** 密钥在返回结果之前就已保存；如果之后网站那一步失败，保险库里留下的是一个网站不认识的通行密钥。它不会覆盖任何东西，但会占着这个登录，需要在官方客户端里删掉它才能重新创建。
- MCP 里对应 `akb_passkey_create`，属于写入类工具，只读模式下不提供。审计日志记录为 `register`。

## MCP 服务

`akb mcp` 通过标准输入输出提供 MCP 服务，让 agent 框架不用拼命令行就能使用保险库。设计原则只有一条：**没有任何工具返回凭据的值**，因为工具结果会直接进入模型的上下文。

在 MCP 客户端里这样配置（Windows 用 `akb.exe` 的完整路径；`--profile` 可选）：

```json
{ "mcpServers": { "agentkeybox": { "command": "/path/to/akb", "args": ["mcp"] } } }
```

| 工具                 | 作用                                                                           |
| -------------------- | ------------------------------------------------------------------------------ |
| `akb_status`         | 保险库是否已解锁。锁着时让用户自己在终端里 `akb auth unlock`，绝不索要主密码   |
| `akb_find`           | 按网址或文字查找登录，只返回元数据                                             |
| `akb_show`           | 描述一个登录的字段和域名，不含值                                               |
| `akb_run`            | 用指定登录的值设置环境变量并运行命令，输出里的值被打码。这是使用凭据的唯一途径 |
| `akb_passkey_assert` | 用登录里的通行密钥对网站的挑战签名，返回签好的响应，私钥不出保险库             |
| `akb_passkey_create` | 为网站在已有登录里新建通行密钥，只返回公开内容；已有通行密钥时不覆盖           |
| `akb_create`         | 新建登录，密码只能由 AKB 生成                                                  |
| `akb_rotate`         | 把密码换成新生成的                                                             |
| `akb_restore`        | 把回收站里的登录恢复回来                                                       |
| `akb_delete`         | 移到回收站                                                                     |

- 不提供读取密码、TOTP 或任何字段值的工具。需要验证码时，用 `akb_run` 的 `field: "totp"` 把它注入命令。
- 写入工具不接受值：调用参数本身就在对话里，把密码放进去等于泄露。传入的 `password` 之类的多余字段会被忽略，不会存储。需要写入指定值时，用命令行的标准输入方式。
- `akb_run` 不经过 shell，没有标准输入；`command` 里程序和参数分开给。默认 120 秒超时，最长 600 秒，超时报告退出码 124 并停止命令。每路输出最多保留 64 KiB，超出时标明被截断。
- `--read-only` 只提供 `akb_status`、`akb_find`、`akb_show`、`akb_run`、`akb_passkey_assert`。
- 调用在服务进程内逐个执行：前台模式下会话密钥暂存在进程环境里，并发会互相取走。
- 审计日志照常记录，`akb_run` 与命令行 `run` 的记录相同。
- 协议部分直接实现了 `initialize`、`ping`、`tools/list`、`tools/call`，没有引入 MCP SDK，避免给保管密钥的工具带入一整套依赖。只用手写的 JSON-RPC 客户端验证过，还没有用真实的 MCP 客户端试过。
- `run` 的打码只能挡住原样、JSON、URL、base64、hex 等常见形式。agent 能自己写命令，若故意把值倒序、拆开或加密后输出，打码识别不了。这是“防止意外泄露”，不是对抗恶意 agent 的沙箱。

## 会话与数据边界

- macOS 和 Windows 上每次调用都在当前进程装配 Bitwarden CLI 服务，同步和读取结束后退出。Linux 仍使用原有后台服务。
- 服务器必须使用 HTTPS，包括本地测试。私有 CA 可通过 Node 的 `NODE_EXTRA_CA_CERTS` 指向受信任证书。
- 默认数据目录为 `~/.agentkeybox/profiles/<profile>/bw`，可用 `AKB_HOME` 隔离。每个 profile 的操作串行，避免并发进程覆盖同一个本地数据库。
- 首次登录或执行 `auth unlock` 后，macOS 把 Bitwarden 会话恢复密钥交给 Keychain，Windows 交给当前用户的 Credential Manager。后续命令可恢复会话。主密码和会话恢复密钥不写入 profile。上游仍维护登录令牌和加密保险库。
- 锁屏、切换用户或状态无法确认时，AKB 拒绝读取；返回结果前会再次检查。Windows 还会拒绝会话已断开和没有交互桌面的调用。手动 `auth lock` 或 `auth logout` 会移除已保存的密钥。可以另外设置时间上限（见下）。系统凭据存储不可访问时，分别返回 `KEYCHAIN_UNAVAILABLE` 或 `CREDENTIAL_STORE_UNAVAILABLE`。操作系统用户仍是信任边界。
- Windows 和 macOS 默认不设时间上限，会话一直保留到桌面锁屏或手动锁定。想让它更早结束，可以设置上限：

  ```bash
  ./akb --profile home session policy set --idle 30m --max 12h
  ./akb --profile home session policy show
  ./akb --profile home session policy set --idle never --max never   # 取消
  ```

  `--idle` 是最后一次使用后的空闲时间，`--max` 是自解锁起的总时长，以先到者为准；用得再频繁，到了 `--max` 也会结束。到期后下一条命令返回 `VAULT_LOCKED`，`status` 的 `lock_reason` 为 `session_expired`，需要在自己的终端里 `auth unlock`。设置立即对之后的每条命令生效，不需要重启任何进程。

- 上述计时放在 profile 目录的 `session-state.json`（只有两个时间戳，没有密钥），上限放在 `session-policy.json`。设上限之前就已解锁的会话没有起始时间，会被当作已到期，需要再解锁一次；这样比猜一个起始时间安全。同一系统用户能改写这两个文件，所以它是节制 agent 使用的时间窗，不是对抗本机攻击者的措施。
- 每次保险库读取都先在线同步；同步失败时不返回缓存凭据。状态查询不强制同步。
- 读取错误不透传上游 payload；`audit.log` 只记录引用，不含凭据（见“审计日志”）；API Key/SSO、生物识别、用通行密钥登录保险库本身、彻底清除条目和完整 profile 管理尚未实现。

## 验证

```bash
npm test --workspace @bitwarden/cli -- --runInBand src/agentkeybox
npx tsc --noEmit -p apps/cli/tsconfig.json
node apps/cli/scripts/agentkeybox-e2e.mjs
```

单元测试和类型检查也是 CNB 流水线（`.cnb.yml`）在每次推送和合并请求里跑的内容，另外还有一次 `build:akb` 构建。流水线不跑端到端，因为它需要 Docker 和 OpenSSL，在 Windows 和 macOS 上还需要交互桌面，所以端到端是手动步骤。核实时的 20 次流水线运行全部成功；之后的运行请直接看 CNB 上的结果。

`policy.spec` 的 POSIX 文件权限位断言（期望 0600）只在 POSIX 平台执行：Windows 报告 0666，私有访问由 profile 目录的 DACL 检查保证，该断言在 Windows 上跳过。2026-11-23 在 Windows 上 167 项单元测试全部通过，类型检查无错误。

集成脚本启动仅绑定 loopback 的临时 Vaultwarden Docker 容器，使用固定镜像 digest、随机生成账户和凭据，并在结束后清理测试目录与容器。它不会使用用户已有仓库。测试中的独立加密代码只生成测试夹具，不进入产品构建。目前共 30 项检查，覆盖登录和会话、读取、`run`、按网址查找、TOTP、新建与修改、删除与恢复、MCP、通行密钥的签名与新建、审计日志、会话时长限制，以及断网时不返回缓存凭据。

在 Windows 上运行端到端的前提，都是实际踩过的：

- **用普通权限的终端运行，不要用管理员终端。** 管理员终端建出的临时目录属于 Administrators 组，AKB 的 profile 目录检查要求目录归当前用户所有、权限私有，会返回 `UNSAFE_DIRECTORY`。这是产品检查在起作用，不要为了跑通测试而放宽它。可以把 `TEMP` 指向一个当前用户私有的目录。
- **先构建，并且构建要带 Windows 助手：** `npm run build:akb:win-x64 --workspace @bitwarden/cli`。它先跑 webpack 再编译 `akb-credentials.exe`；webpack 每次都会清掉输出目录里的助手，所以只重跑 webpack 之后必须再编译一次助手，否则读取会失败。助手用 Visual Studio 生成工具（`vcvars64.bat` 后的 `cl.exe`）编译通过；在验证用的机器上，用 mingw 头文件编译会因为缺少 `WTSINFOEX` 定义而失败。
- 脚本要用 `openssl req` 生成测试证书。如果本机的 OpenSSL 配置让它报错（例如某些发行版配置里的 `keyid:nonss`），把 `OPENSSL_CONF` 指向一个最小的配置文件即可，这只影响测试夹具。
- 整个脚本要几分钟：会话时长限制那一步为了留出命令本身的几秒耗时，设了 10 秒和 12 秒的上限并等待它们到期。
- 默认不跑锁屏那一步，要跑需要 `AKB_TEST_SCREEN_LOCK=1`（见“Windows x64 开发版”）。

2026-11-22 Windows x64 独立版验收：重新执行 `dist:akb:win-x64`，测试将 `akb.exe` 和助手复制到带空格的路径，产品进程的 PATH 排除 Node、npm 和 bw，并连接临时真实 Vaultwarden。第一轮实际锁屏时验证了拒绝读取、解锁后恢复同步与读取；这轮共通过 30 项，但最后登出后的状态检查返回 `locked`，预期为 `unauthenticated`，所以整轮没有通过。该次未记录状态查询时的桌面状态，原因未确定。

随后在桌面解锁状态下完整重跑（锁屏步骤关闭，因为已在第一轮实测），30 项通过、退出码 0。断网读取返回 `SYNC_FAILED`，登出响应及紧随其后的状态查询均为 `unauthenticated`、`screen_state: unlocked`，重复登出通过。另一次聚焦断网、登出和重复登出的测试也得到相同结果；第一次异常未复现，不能断言其原因。本次环境为提升权限的管理员会话，测试使用限制访问的临时目录，并将测试进程的默认文件所有者设为当前用户，以满足目录检查；它不代替普通权限用户环境的验收。

2026-11-23 Windows 重跑（移除商业模块后）：源码构建与独立版各 30 项通过、退出码 0，单元测试 167 项全部通过，类型检查无错误。过程中发现并修复一个独立版专属缺陷：配置 `http_proxy`/`https_proxy` 时登录崩溃（`ReferenceError: Cannot access 'HttpsProxyAgent' before initialization`）。原因是 `https-proxy-agent` 9.1.0 的新依赖 `proxy-agent-negotiate` 为纯 ESM（只有 `exports`、没有 `main`），不在 webpack 的打包 allowlist 里，pkg 无法把它纳入快照；源码构建在运行时从 `node_modules` 解析，所以不受影响。已将它加入 `apps/cli/webpack.base.js` 的 allowlist，并在带代理变量的环境下用临时真实 Vaultwarden 复现、验证修复。2026-11-22 的验收终端没有代理变量，因此当时没有暴露这条路径。

2026-11-24 代理路径复核（两仓库历史同源后）：用独立进程里记录 CONNECT 的代理加临时真实 Vaultwarden，跑了 4 轮登录——源码构建（node26，`NODE_USE_ENV_PROXY` 关/开各一轮）、打包 exe（node22）、exe 加 `NO_PROXY=127.0.0.1,localhost`——全部成功，代理共记录 24 个 CONNECT，目标全部是 vault 地址，确认流量没有绕过代理。机制上，`node-api.service.ts` 把全局 fetch 替换为 node-fetch 2.7.0，它会读取 `request.agent` 上的 `HttpsProxyAgent`，因此“原生 fetch 忽略 agent、代理被绕过”的怀疑不成立。一个已知限制：这条 agent 路径不读 `NO_PROXY`，回环地址也会走代理（与上游行为一致，代理能正确隧道回环流量，不影响功能）。测试方法上有一个实际踩过的坑：记录代理必须跑在独立进程里，否则编排脚本的 spawnSync 会阻塞它的事件循环，CONNECT 无人应答，所有轮次都会假性挂起。

本轮环境说明：验证机是内置 Administrator 账户且 UAC 关闭（`EnableLUA=0`），不存在当前用户的普通权限令牌，普通权限环境的验收仍待在有标准用户或开启 UAC 的机器上做。系统 `Temp` 的 ACL 被其他沙箱工具加入了额外的组（Modify 权限），AKB 的 `UNSAFE_DIRECTORY` 检查正确地拒绝了它；测试改用当前用户所有、DACL 干净的私有目录作为 `TEMP`。OpenSSL 用最小配置文件绕开本机配置里的 `keyid:nonss` 笔误。这两项都只影响测试环境，不改变产品检查。锁屏步骤本轮重试失败：验证机通过 RDP 接入，Win+L 锁定的是本地客户端而不是远程会话，脚本在 180 秒内没有观察到锁屏状态；这是测试环境限制，不是产品缺陷，锁屏门控沿用 2026-11-22 的实测记录。在 RDP 中重跑需要用 Ctrl+Alt+End → 锁定，或 `tsdiscon` 断开后重连。

在 Linux 上运行端到端时，如果脚本本身在容器里（没有现成的 Linux 主机时，这是在 Windows 上借 Docker Desktop 的办法），有两处和直接运行不同，都是实际踩过的：

- **脚本要从宿主的 Docker 守护进程启动 Vaultwarden，并把存放证书的目录挂给它。** 这个目录必须在宿主和容器里是同一个路径：把宿主的一个目录挂到容器里同样的路径，并让 `TMPDIR` 指向它。否则 Vaultwarden 看到的是一个空目录，起不来。
- **容器里连不上发布到宿主回环地址的端口**，用 `--network host` 也不行。改成设置 `AKB_TEST_DOCKER_NETWORK` 和 `AKB_TEST_VAULT_IP`（必须同时设置）：先建一个 Docker 网络，让运行脚本的容器加入它，脚本就会让 Vaultwarden 以这个固定地址加入同一网络，并把该地址写进测试证书。固定地址不要用网络里第一个空闲地址，那是运行脚本的容器自己会拿到的。

例如（`/host/tmp` 是宿主上的一个目录）：

```bash
docker network create --subnet 172.29.0.0/24 akb-e2e-net
docker run --rm --network akb-e2e-net \
  -e AKB_TEST_VAULT_IP=172.29.0.50 -e AKB_TEST_DOCKER_NETWORK=akb-e2e-net \
  -v "$PWD":/work -w /work \
  -v /host/tmp:/host/tmp -e TMPDIR=/host/tmp \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(readlink -f "$(command -v docker)")":/usr/local/bin/docker:ro \
  node:24 bash -c 'npm ci --ignore-scripts && npm run build:akb --workspace @bitwarden/cli && node apps/cli/scripts/agentkeybox-e2e.mjs'
docker network rm akb-e2e-net
```

具体复用模块与下一步见 [模块梳理](docs/agentkeybox/source-map.md)。

## macOS 独立可执行文件

当前提供 Apple Silicon（arm64）开发构建，运行时不需要另外安装 Node.js：

```bash
npm run dist:akb:mac-arm64 --workspace @bitwarden/cli
apps/cli/dist/agentkeybox/macos-arm64/akb --version
```

输出目录包含 `akb`、`akb-keychain`、校验和、使用说明和上游许可证。移动或安装时将两个可执行文件放在同一目录。

嵌入运行时为打包工具支持的 Node 22。二进制使用本地 ad-hoc 签名，尚未做 Apple Developer ID 签名或公证；Intel 版本未构建验证。本地构建更换 `akb-keychain` 后，Keychain 可能要求重新绑定。

独立文件集成验证（Docker、Node 和 OpenSSL 仅用于测试夹具，不是产品运行依赖）：

```bash
AKB_TEST_BINARY=apps/cli/dist/agentkeybox/macos-arm64/akb node apps/cli/scripts/agentkeybox-e2e.mjs
```

脚本将两个文件复制到含空格的临时目录，在产品 PATH 中排除 Node/npm/bw，验证 HTTPS Vaultwarden 登录、Keychain 恢复和读取流程。

## Windows x64 开发版

在 Windows 10/11 的 x64 Visual Studio 开发者终端运行（已验证）。也可以在装有 `x86_64-w64-mingw32-gcc` 的交叉编译环境运行，但这条路没有验证通过：在验证用的机器上它因缺少 `WTSINFOEX` 定义而编译失败。

```powershell
npm run dist:akb:win-x64 --workspace @bitwarden/cli
```

将 `apps/cli/dist/agentkeybox/windows-x64` 中的 `akb.exe` 与 `akb-credentials.exe` 放在同一目录，然后以登录桌面的 Windows 用户运行：

```powershell
.\akb.exe --profile home config server https://vault.example.com
.\akb.exe --profile home auth login --email you@example.com
.\akb.exe --profile home --json --no-input account list
```

首次登录成功后，会话恢复密钥保存在当前用户、本机的 Windows Credential Manager。后续命令可在同一用户解锁的交互桌面中恢复会话。自定义 `AKB_HOME` 时使用当前用户所有、具有私有 Windows ACL 的目录。

**在管理员（提升权限）的终端里运行会报 `UNSAFE_DIRECTORY`。** 管理员终端里新建的目录默认归 Administrators 组所有，而 AKB 要求 profile 目录归当前用户所有、权限私有。请用普通权限的终端运行 AKB，或把 `AKB_HOME` 指到当前用户私有的目录。这是有意的检查，不是故障。

Windows 上的会话默认不设时间上限，只受锁屏和手动锁定控制；需要时用 `session policy set --idle 30m --max 12h` 设置（见“会话与数据边界”）。

本节的构建和运行方式已用打包出的独立 `akb.exe` 做端到端验证，结果和首次登出状态异常的限制见“验证”。`akb.exe` 尚未做代码签名。

在 Windows 交互桌面中，可用 Node.js、OpenSSL 和 Docker 运行完整验收。脚本会提示按 Win+L 锁屏，等待约十秒后解锁，并自动核对锁屏拒绝、重新同步及读取成功：

```powershell
$env:AKB_TEST_BINARY = "apps/cli/dist/agentkeybox/windows-x64/akb.exe"
$env:AKB_TEST_SCREEN_LOCK = "1"
node apps/cli/scripts/agentkeybox-e2e.mjs
```

## 从 macOS 后台版迁移

已有 profile 可保留服务器、登录状态和加密数据。先退出该 profile 的旧服务，再在已解锁的 Mac 上输入一次主密码完成绑定：

```bash
./akb --profile phynews service stop
./akb --profile phynews auth unlock
./akb --profile phynews status --json
```

此后的凭据请求只需正常解锁 Mac。若系统刚锁屏，等待用户解锁后重试。主动执行 `auth lock` 会撤销已保存的解锁能力，可用 `auth unlock` 重新绑定。macOS 默认由锁屏策略控制，不设超时；如需超时，用 `session policy set`。Linux 仍可通过 `session policy` 或 `AKB_IDLE_MS` / `AKB_MAX_MS` 配置超时。
