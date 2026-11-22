# 保持解锁策略（2026-11-04）

新增每 profile 的 `session policy show/set`，支持 idle/max 独立设置 `never` 或正数时间（ms/s/m/h/d）。以 `session-policy.json` 原子保存，权限 0600；null 表示禁用该期限。显式策略优先于环境变量默认值。

新后台服务在处理请求和定时检查时加载策略，无需重启即可应用。已锁定不会因修改策略自动解锁。状态包含 `session_policy`，解锁且 `expires_at=null` 表示没有自动锁定期限。手动锁定、注销、进程退出和机器重启仍然有效；没有持久化主密码或明文 session key。

兼容旧后台：命令保存设置后查询实际策略，若旧进程未返回该策略，则输出 `applied=false` / `restart_required=true`，不主动停止旧会话。用户执行一次 `service stop` + `auth unlock` 后使用新后台。

已为 phynews 保存 idle/max 均为 never。未读取真实密码或业务条目，也未停止其当前旧会话。

验证：8 个单元测试、17 组独立文件真实 Vaultwarden 容器集成检查通过，包含策略持久化、运行中生效、覆盖 100ms 环境变量期限、手动锁定及默认空闲/最长会话策略回归。ESLint、Prettier 和构建通过。测试用随机账户，不访问真实用户仓库。
