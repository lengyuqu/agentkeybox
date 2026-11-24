---
name: agentkeybox
version: 0.1.0
description: 通过 AgentKeybox (akb) CLI 或 MCP 安全使用 Vaultwarden 保险库中的凭据、SSH 密钥、TOTP 与通行密钥。当任务需要用保险库里的密码/令牌跑命令、查找账号、读取 TOTP、新建或轮换凭据与 SSH 密钥、用 passkey 登录、配置或排查 akb 时使用。核心约束：凭据值绝不进入 agent 上下文或对话记录，优先用 run 注入。适用于本仓库源码构建场景；不适用于实现 Bitwarden 客户端源码功能或通用 vault 产品咨询。
---

# AgentKeybox (akb)

## 概述

AgentKeybox 是面向 agent 的 Vaultwarden 客户端，基于本仓库 `apps/cli` 的 Bitwarden SDK 构建。CLI 入口为仓库根目录的 `./akb`，MCP 入口为 `akb mcp`。设计前提：agent 会用凭据，但不能看到凭据值。

完整命令语法见 `references/commands.md`；错误码、平台差异与边界见 `references/troubleshooting.md`。仅在需要具体参数或排错时读取对应 reference，不要一次全部加载。

## 安全铁律（任何操作前先遵守）

1. **凭据值不进上下文。** 用 `run --env NAME=<ref>[#field]` 把值注入子进程环境变量，让命令消费；不要在命令参数、对话、文件里出现明文。
2. **避免 `credential get`。** 它把值打印到 stdout，会直接进入上下文。仅当用户明确要手动查看、且由人在终端执行时考虑；agent 自己调用一律改用 `run`。
3. **绝不索要主密码。** 锁着时（`VAULT_LOCKED` / `akb_status` locked）让用户自己在终端执行 `auth unlock` 或 `auth login`。不接收、不转述、不写入主密码。
4. **写入值只走标准输入或由 AKB 生成。** 用 `--password-stdin`、`--stdin`、`--private-key-stdin`、`--generate`、`--generate-key`。不要把新密码放进命令行参数。
5. **不绕过锁屏门控。** 锁屏、`SCREEN_LOCKED`、会话断开时停止并让用户处理，不要改环境变量或 profile 权限来"跑通"。
6. **引用用 `ref:<名称>` 或 `id:<UUID>`。** 精确匹配；名称片段会被拒绝（`INVALID_REFERENCE`）。重复引用报 `AMBIGUOUS_MATCH`，改用 `id:`。
7. **删除是软删除。** `item delete` 进回收站，可用 `item restore` 恢复；没有彻底清除命令，agent 无法永久销毁数据。

## 调用入口

`akb` 不在任何 shell 的 PATH 中（bash 与 PowerShell 均已核实）。按 shell 选择调用方式，均从仓库根目录执行：

| shell | 调用形式 | 说明 |
| --- | --- | --- |
| bash / git-bash | `./akb --profile <name> ...` | 根目录 `akb` 是 node 启动器 |
| PowerShell | `node apps/cli/build-akb/akb.js --profile <name> ...` | 避免直接执行 shebang 脚本 |
| 任一（构建产物） | `node apps/cli/build-akb/akb.js ...` | 通用、最稳妥 |

前置条件：`apps/cli/build-akb/akb.js` 存在。若无，先构建：

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build:akb --workspace @bitwarden/cli
```

Windows 上若读取报 `akb-credentials.exe` 相关失败，需带助手重新构建 `npm run build:akb:win-x64 --workspace @bitwarden/cli`（webpack 会清理助手，只重跑 webpack 后必须重编助手）。

## 决策树：该用哪个接口

- **只是找账号、看有哪些字段** → `account list` / `account show`（只返回元数据，无值）
- **用凭据执行命令（最常见）** → `run`，值注入环境变量，输出自动打码
- **人要手动复制一个值** → 让人在终端自己跑 `credential get`，agent 不代劳
- **代码里要集成、不想拼命令行** → `akb mcp`，通过 MCP 工具调用（`akb_run` 是唯一使用值的工具）
- **新建/修改/轮换凭据或 SSH 密钥** → `item create` / `item set`，值走 stdin 或自动生成
- **网站登录 / 注册 passkey** → `passkey assert` / `passkey create`
- **查状态、配置服务器、登录、锁定、会话策略** → `status` / `config` / `auth` / `session`

优先用 `--json` 获取机器可读输出；`--no-input` 保证非交互不卡住。

## 常用工作流

### 1. 首次接入（人完成登录）

```bash
./akb --profile home config server https://vault.example.com
./akb --profile home auth login --email you@example.com     # 终端隐藏读取主密码
./akb --profile home status --json
./akb --profile home sync --json
```

服务器必须是 HTTPS（含本地测试）。私有 CA 用 `NODE_EXTRA_CA_CERTS` 指向证书。

### 2. 找账号（只看元数据）

```bash
./akb --profile home account list --search github --json
./akb --profile home account list --url https://github.com/login --json
./akb --profile home account show id:ITEM_UUID --json
```

`--url` 按域名匹配登录，`uris` 只显示协议+主机（不含路径/查询串，避免令牌泄露）。`--trashed` 查回收站（不能与 `--url` 同用）。

### 3. 用凭据跑命令（核心模式）

```bash
./akb --profile home run \
  --env GH_TOKEN=ref:github/ci \
  --env DB_USER=ref:db/prod#username \
  -- gh pr list
```

- 字段默认 `password`；可写 `#username` / `#notes` / `#private_key` / `#totp` / `#custom:<字段名>`。
- 全部引用先解析，任一失败则不启动命令。
- 命令不经 shell，参数不展开；Windows 的 `.cmd`/`.bat` 用 `-- cmd /c script.cmd`。
- 输出中的值被打码成 `[REDACTED:<变量名>]`；打码是兜底不是沙箱，不要依赖它对抗恶意命令。
- 退出码透传；AKB 自身错误用 2–10，`RUN_FAILED`=9，用 `--json` 区分。

### 4. 写入 / 轮换（不回显值）

```bash
# 新建，密码由 AKB 生成
./akb --profile home item create --name GitHub --ref github/ci \
  --username bot --url https://github.com --generate-password --length 32

# 新值从 stdin 读入
printf '%s' "$NEW" | ./akb --profile home item set ref:github/ci --field password --stdin

# SSH 密钥：生成 / 导入 / 轮换
./akb --profile home item create --type ssh --name Deploy --ref ssh/deploy --generate-key
./akb --profile home item set ref:ssh/deploy --field private_key --generate
./akb --profile home item set ref:ssh/deploy --field private_key --stdin < /tmp/new_key

# 删除与恢复
./akb --profile home item delete ref:github/ci
./akb --profile home item restore id:ITEM_UUID
```

`agentkeybox.` 开头的自定义字段由 AKB 管理，不可修改。值上限 64 KiB，末尾一个换行会被去掉。

### 5. TOTP

```bash
./akb --profile home credential get id:ITEM_UUID --field totp --json   # 人手动用，含 expires_in
./akb --profile home run --env CODE=ref:github/ci#totp -- ./login.sh   # agent 用，不暴露值
```

`#totp` 注入时保证至少 3 秒有效，不足会等下一窗口。

### 6. 会话与锁屏

```bash
./akb --profile home auth lock                      # 撤销已保存的解锁能力
./akb --profile home auth unlock                    # 人输入主密码重新绑定
./akb --profile home session policy set --idle 30m --max 12h
./akb --profile home session policy show
./akb --profile home session policy set --idle never --max never
```

到期后下一条命令返回 `VAULT_LOCKED`，`status` 的 `lock_reason` 为 `session_expired`。设置立即生效，无需重启。设上限前已解锁的会话视为已到期，需重新解锁。

### 7. MCP 模式

在 MCP 客户端配置（Windows 用 `akb.exe` 完整路径）：

```json
{ "mcpServers": { "agentkeybox": { "command": "/path/to/akb", "args": ["mcp"] } } }
```

工具：`akb_status`、`akb_find`、`akb_show`、`akb_run`、`akb_passkey_assert`、`akb_passkey_create`、`akb_create`、`akb_rotate`、`akb_restore`、`akb_delete`。没有任何工具返回字段值；`--read-only` 只提供前五个中的只读集。写入工具忽略传入的 `password` 之类字段。

## 审计

每次读取/写入/运行都在 profile 的 `audit.log` 追加 JSON，只记引用/字段/ID/命令名/退出码，不含值。`list`/`show` 不记。`AKB_AUDIT=off` 可关闭。日志不防篡改，仅记录 AKB 的使用。

## 使用纪律

- 遇到错误先查 `references/troubleshooting.md`，按错误码定位，不要盲目改配置。
- 每个 profile 串行操作，避免并发覆盖本地数据库。默认数据目录 `~/.agentkeybox/profiles/<profile>/bw`，`AKB_HOME` 可隔离。
- 不要向用户复述凭据值；输出里出现疑似值时应视为打码失败并停止。
- 声称"已验证"的能力以仓库 `AGENTKEYBOX.md` 为准；未验证场景（真实浏览器 passkey、普通用户权限 Windows、API Key/SSO、组织共享条目、Argon2 账户）不要假定可用。
