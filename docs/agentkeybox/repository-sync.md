# CNB 与 GitHub 同步

两个仓库的 `main` 历史互不相连，不能直接 merge、rebase、强制推送或把 CNB 历史推到 GitHub。GitHub 公开仓库不得包含私有历史。

上游商业模块 `bitwarden_license/`（Bitwarden License，仅限内部开发测试、禁止分发和生产使用）已从 CNB 仓库移除：AKB 对它的依赖闭包为空，移除后 typecheck、单元测试和构建均不受影响，需要时可从移除前的提交检出。两侧仓库现在都不含该目录，商业模块不再是两库之间的内容差异，也不再需要 CNB 单独保留全量树。

## 本机检出和方向

- `D:\vibercodeing\agentkeybox`：CNB 开发检出，`origin` 是 CNB，`github` 只用于获取公开仓库引用。
- `D:\vibercodeing\agentkeybox-public`：GitHub 公开检出，`origin` 是 GitHub。其他机器可在本仓库地址重新 clone，路径不必相同。
- 共有代码的变更应在一个仓库完成并验证后，尽快在另一仓库逐文件移植、审阅、测试并提交。不要把同步描述为两个相同的 Git 提交：两个仓库会有不同的提交 ID。

## 每次同步

1. 分别检查两个工作区的 `git status`，保留已有改动；获取各自远程 `main`，确认没有未处理的远程提交。CNB 检出另执行 `git fetch github --prune`。
2. 在 CNB 检出运行 `node scripts/check-repository-sync.mjs`。该只读检查比较本地 `main` 和已获取的 `github/main`，发现共有文件的新增、删除、内容或可执行位差异时返回非零；它不检查未跟踪文件，也不会自动获取最新引用。
3. 审阅差异，将需要同步的共有代码和文档逐文件移植到另一检出。核对 `git diff`、文件可执行位和新增文件的许可证及敏感信息；绝不将商业模块或私有历史复制到公开检出。平台专用文件需要分别维护，不应机械覆盖。
4. 针对变更运行测试，在每个仓库只暂存对应文件并提交，分别推送各自的 `main`。检查 GitHub Actions 和 CNB 流水线；再次获取两个远程引用并运行检查脚本。脚本成功表示共有的已跟踪文件一致，不代表测试通过或安全审计完成。

检查脚本允许以下有意保留的差异：商业模块目录、GitHub 模板和 CODEOWNERS、公开版 GitHub Actions、README 与 SECURITY；其他差异都需审阅。允许列表需要随平台专用文件变更谨慎维护。不要依靠此列表替代公开前的许可证和凭据审查。此流程是人工触发，不会自动推送或自动监控。
