# CNB 与 GitHub 同步

两个仓库共享同一提交历史：同一根提交、同一提交 ID。同步是 fast-forward 推送，不再逐文件移植。

## 历史沿革

旧 CNB 仓库承载过 35 个提交，其中 `bitwarden_license/`（Bitwarden License v1.0，仅限内部开发测试、禁止分发和生产使用）随初始提交 `c1ef245` 进入历史。`git rm` 只能新增删除提交，无法从历史中移除，因此该仓库已归档改名，原路径 `phynews/agentkeybox` 现在承载从 GitHub 导入的公开历史，根提交为 `1df023a`。

AKB 对该商业模块的依赖闭包为空，正常开发不需要它。归档前的全量备份为 `~/Backups/agentkeybox/agentkeybox-all-20261124.bundle`（54 MB，含归档仓库全部 35 个提交与 GitHub 全部提交）。该备份含 Bitwarden License v1.0 源码，**不得同步到 iCloud、Dropbox、OneDrive 或任何云端目录，也不得公开分享**。

## 安全红线

公开仓库不得包含 `bitwarden_license/` 或任何 Bitwarden License v1.0 内容。两侧历史已同源，一旦提交，该内容会同时进入两个远程仓库的历史，无法通过删除文件撤回。提交前检查 `git status` 与 `git diff --cached`，不要从归档仓库复制目录。

## 日常同步

1. 获取两侧远程引用：`git fetch origin --prune` 与 `git fetch github --prune`。
2. 运行 `node scripts/check-repository-sync.mjs`。该只读脚本比较本地 `main`、`origin/main`、`github/main` 三个指针，不一致时列出差距并返回非零。
3. 按提示把领先方的提交推送到落后方。历史同源，推送是 fast-forward，不需要 `--force`。
4. 再次获取并重跑脚本，三者一致即完成。

脚本只验证指针一致，不代表测试通过或安全审查完成。提交前仍须跑测试并复核许可证与凭据。

## 平台专用文件

`.cnb.yml`（CNB 流水线）与 `.github/workflows/agentkeybox-ci.yml`（GitHub Actions）并存于同一棵树，两个平台各读自己的配置，互不干扰。改动会随同一提交进入两侧历史，因此两份配置的步骤目前保持一致，修改其中一份时应同步另一份。

`.github/CODEOWNERS`、`SECURITY.md`、README 已统一为面向本项目的版本，不再保留 Bitwarden 上游的组织配置。

## 从旧检出切换

归档前的检出（包括其他机器上的旧 clone）与当前历史无关，`git pull` 会报无关历史。切换到当前历史：

```
git fetch origin --prune
git reset --hard origin/main
```

执行前确认该检出没有未推送的提交，`git reset --hard` 会丢弃它们。需要保留时先在旧检出执行 `git bundle create` 备份。
