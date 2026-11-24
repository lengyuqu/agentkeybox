# akb 命令完整参考

基于实际 CLI `--help` 输出。所有命令均从仓库根目录执行；`akb` 代表 `./akb`（bash）或 `node apps/cli/build-akb/akb.js`（PowerShell / 通用）。全局选项：`--profile <name>`（默认 `default`）、`--json`、`--no-input`。

## 顶层命令

`status` · `sync` · `config server <url>` · `auth` · `account` · `credential` · `run` · `passkey` · `item` · `session` · `mcp`

## 认证与配置

| 命令 | 参数 | 说明 |
| --- | --- | --- |
| `config server <url>` | — | 设置服务器，必须 HTTPS（含本地测试）；私有 CA 用 `NODE_EXTRA_CA_CERTS` |
| `auth login` | `--email <email>` `--password-stdin` `--method <number>` `--code <code>` | 交互模式在终端隐藏读主密码；`--password-stdin` 供自动化；2FA 仅普通密码账户经过真实验证 |
| `auth unlock` | `--password-stdin` | 恢复本地会话；锁屏后由人执行，agent 不索要主密码 |
| `auth lock` / `auth logout` | — | 移除已保存的会话密钥 |
| `auth status` | — | 查看登录/解锁状态 |
| `status` | — | 完整状态，含 `lock_reason`、`screen_state` |
| `sync` | — | 在线同步；读取操作自动同步，同步失败不返回缓存凭据 |

## 发现（不返回字段值）

| 命令 | 参数 | 说明 |
| --- | --- | --- |
| `account list` | `--search <text>` `--url <url>` `--trashed` | 只返回元数据。`--search` 匹配名称/引用/用户名；`--url` 用保险库域名规则匹配；`--trashed` 列回收站（不能与 `--url` 同用） |
| `account show <ref>` | — | 描述字段与域名、passkey rp id、`credential_fields`，不含值 |

引用格式：`id:<UUID>` 或 `ref:<精确名称>`。`ref` 对应 `agentkeybox.ref` 自定义字段；重复引用报 `AMBIGUOUS_MATCH`，用 `id:` 消歧。名称片段/裸词报 `INVALID_REFERENCE`。

## 凭据

### `credential get <ref>` — 仅人手动使用

`--field <name>`（password / username / notes / private_key / public_key / totp / custom:<name>）、`--raw`（无末尾换行）。

**agent 不要调用**：值打印到 stdout 会进入上下文。用 `run` 代替。`totp` 字段的 JSON 输出含 `expires_in`。

### `run --env NAME=<ref>[#field] ... -- <command> [args...]`

- `--env` 可重复；`NAME` 不区分大小写地不得重复。
- `#field` 默认 `password`；支持 `username` / `notes` / `private_key` / `totp` / `custom:<name>`。`#` 后不是合法字段名时属于引用本身。
- 所有引用先解析，任一失败命令不启动。
- 命令不经 shell，参数不展开。Windows `.cmd`/`.bat` → `-- cmd /c script.cmd`。
- stdout/stderr 过滤注入值 → `[REDACTED:<NAME>]`；覆盖原文/JSON/URL/base64/base64url/hex，跨块处理。短于 4 字符不过滤。打码是兜底，不是沙箱。
- stdin 保持连接；stdout/stderr 是管道，无颜色/交互。
- 退出码透传；信号终止为 `128+信号号`；AKB 自身错误 2–10；`RUN_FAILED`=9。区分用 `--json`。
- 不写 `.env` 文件，命令行只有引用。

## 写入（不回显值）

### `item create`

| 参数 | 说明 |
| --- | --- |
| `--name <name>` | 条目名称 |
| `--ref <name>` | 引用名，可带/不带 `ref:` 前缀；重复报 `REF_EXISTS` |
| `--type <login\|ssh>` | 默认 `login` |
| `--username <username>` | 用户名 |
| `--url <url>` | 可重复；裸域名按 `https://` 处理 |
| `--password-stdin` | 从 stdin 读密码 |
| `--generate-password` | 生成并保存，不显示 |
| `--length <number>` | 生成密码长度 8–128，默认 24 |
| `--private-key-stdin` | ssh 类型：从 stdin 读未加密 OpenSSH / PKCS8 私钥（ed25519 或 RSA） |
| `--generate-key` | ssh 类型：生成 Ed25519 密钥对并保存，不显示 |

### `item set <ref>`

`--field <name>`（password / username / notes / totp / private_key / custom:<name>）、`--stdin`、`--generate`（仅 password / private_key）、`--length <number>`。一次一个字段，agentkeybox. 前缀的自定义字段不可改。

- `private_key` 仅 ssh 条目，替换整个密钥对，公钥与指纹随之更新。
- TOTP 种子接受 base32 / `otpauth://totp/` / `steam://`，否则 `INVALID_TOTP`。格式正确仍可能错，需用人在终端 `credential get --field totp` 对照。
- 值上限 64 KiB，去掉末尾一个换行。写入前在线同步；冲突在最新数据上重试一次，仍失败 `WRITE_CONFLICT`。

### `item delete <ref>` / `item restore <ref>`

软删除进回收站，可恢复。都需精确 `ref:` / `id:`。恢复前检查引用是否被占用（占用报 `REF_EXISTS`）。无彻底清除命令。

## 通行密钥

| 命令 | 参数 |
| --- | --- |
| `passkey assert <ref>` | `--origin <url>` `--challenge <base64url>` |
| `passkey create <ref>` | `--origin` `--challenge` `--user-id <base64url>` `--user-name <name>`，可选 `--display-name` `--rp-id <host>` `--rp-name <name>` |

- `--origin` 必须 https（本地开发允许 `http://localhost`），丢弃路径与参数。
- `assert` 输出 `credential_id` / `client_data_json` / `authenticator_data` / `signature` / `user_handle`（base64url）、`rp_id`。只用第一个 passkey。
- `create` 在**已有登录**里创建，不覆盖（已有报 `PASSKEY_EXISTS`）；输出 `attestation_object` / `public_key`（SPKI）等公开内容。先存后注册，非原子。
- 两者都不声称用户验证（UV 标志关闭），要求 UV 的网站会拒绝；需重新输入主密码的条目报 `PERMISSION_DENIED`。

## 会话策略

| 命令 | 参数 |
| --- | --- |
| `session policy show` | — |
| `session policy set` | `--idle <duration>` `--max <duration>`，值如 `30m`、`12h` 或 `never` |

`--idle` 最后使用后空闲时间，`--max` 解锁总时长，先到者为准。立即对之后每条命令生效。到期后下一条命令 `VAULT_LOCKED`，`status.lock_reason = session_expired`。设上限前已解锁的会话视为过期，需重新解锁。策略存 `session-policy.json`，时间戳存 `session-state.json`，均不含密钥。Linux 另可用 `AKB_IDLE_MS` / `AKB_MAX_MS`。

## MCP

`akb mcp [--read-only]` — stdio 服务。工具：`akb_status` / `akb_find` / `akb_show` / `akb_run` / `akb_passkey_assert` / `akb_passkey_create` / `akb_create` / `akb_rotate` / `akb_restore` / `akb_delete`。

- 无工具返回字段值；写入工具忽略传入的 `password` 等字段。
- `akb_run` 是非 shell、无 stdin、`command` 与参数分开给；默认 120s 超时，最长 600s，超时退出码 124；每路输出最多 64 KiB。
- `--read-only` 只提供 `akb_status` / `akb_find` / `akb_show` / `akb_run` / `akb_passkey_assert`。
- 协议手写实现 `initialize` / `ping` / `tools/list` / `tools/call`，未引入 MCP SDK。前台模式会话密钥暂存进程环境，并发会互相取走 —— 逐个调用。

MCP 客户端配置：

```json
{ "mcpServers": { "agentkeybox": { "command": "/path/to/akb", "args": ["mcp"] } } }
```
