# LinuxGuard 修复模式 / Repair Mode

LinuxGuard V1.0 introduces an opt-in repair framework; repair never runs automatically.
LinuxGuard V1.0 引入可选的修复框架，修复操作**绝不自动运行**，必须由用户显式调用。

## Workflow / 工作流程

1. **Detect / 检测** — run detection modules / 运行检测模块
2. **Analyze / 分析** — identify repairable findings, assign levels / 识别可修复项并分级
3. **Plan / 计划** — present the plan (`--dry-run`) / 展示修复计划
4. **Authorize / 授权** — confirm by mode (`--safe`/`--interactive`/`--all`) / 按模式确认
5. **Execute / 执行** — back up, modify, validate, verify / 备份、修改、验证、复核
6. **Rollback / 回滚** — restore originals on validation/verification failure / 验证或复核失败时还原

## Repair Modes / 修复模式

| Mode / 模式 | Behavior / 行为 |
| ---- | -------- |
| `scan` (default / 默认) | Detect only, no changes / 仅检测，不修改 |
| `fix --dry-run` | Show plan, no changes, **no root needed** / 仅显示计划，不修改，**无需 root** |
| `fix --safe` | Auto-repair L1 only / 仅自动修复 L1 项 |
| `fix --interactive` | Confirm each repair (default) / 逐项确认（默认） |
| `fix --all` | Confirm L3/L4 once, then repair all / 一次性确认 L3/L4 后全部修复 |

The report also prints **repair feasibility / 修复可行性**: how many findings are auto-repairable vs manual, split by level.
报告还会输出**修复可行性**统计：可自动修复项与需手工处理项数量，并按等级拆分。

## Repair Levels / 修复等级

| Level | Description / 说明 | Examples / 示例 |
| ----- | ----------- | -------- |
| L1 | Low risk, safe to auto-repair / 低风险，可自动修复 | Stale passwords / 过期密码、sudoers 权限 |
| L2 | Medium risk / 中风险 | ASLR、kptr_restrict、rp_filter、SSH 空密码 |
| L3 | High risk, must confirm / 高风险，需确认 | 禁用 SSH root 登录/密码认证、启用防火墙 |
| L4 | Critical risk, strict review / 严重风险，严格审查 | 修改 UID 0 账户、宽泛 sudo 规则 |

## Implemented Repairs in V1.0 / 已实现修复项

- **SSH**: `PermitRootLogin no`、`PasswordAuthentication no`、`PermitEmptyPasswords no` / 关闭 root 登录与密码认证
- **sudoers permissions / 权限**: `/etc/sudoers` → `440`
- **File permissions / 文件权限**: `/etc/passwd`、`/etc/group` → `644`；`/etc/shadow`、SSH 主机私钥 → `600`
- **Firewall / 防火墙**: 启用 UFW 或启动 firewalld
- **Kernel / 内核**: 启用 ASLR、kptr_restrict、rp_filter；禁用 IPv4 转发与新模块加载
- **Docker socket**: `/var/run/docker.sock` → `660`

Detected but **not auto-repaired** (need human judgment / 需人工判断，暂不自动修复):

- UID 0 accounts other than root / root 之外的 UID 0 账户
- Empty password accounts / 空密码账户
- Unusual login shells / 异常登录 Shell
- Stale passwords / 过期密码
- Broad or risky sudoers rules / 宽泛或危险的 sudoers 规则
- Custom nftables/iptables rules / 自定义 nftables/iptables 规则
- Published Docker ports or privileged containers / 暴露的 Docker 端口或特权容器
- Threat indicators from `processes` / `malware` / `vulnscan` (require human judgment and dedicated scanners) / 来自 `processes`/`malware`/`vulnscan` 的威胁指标（需人工判断与专用扫描器）
- All findings from the V1.2 hardening modules (`netstack`, `filesystem`, `auth`, `audit`, `services`) / V1.2 加固模块的全部发现项

These findings have **no** repair-policy entry, so they are always reported as `Manual / 需手工` in the feasibility statistics and never touched by `--safe`/`--all`.
这些发现项**没有**修复策略条目，因此在可行性统计中始终记为 `Manual / 需手工`，`--safe`/`--all` 也不会对其做任何修改。

## Backup and Rollback / 备份与回滚

Backups are stored under / 备份目录：

- `/var/backups/linuxguard/<session>/` as root / 以 root 运行时
- `/tmp/linuxguard-backups/<session>/` otherwise / 其他情况

Each session uses a timestamped directory; on failure the original file is restored automatically. You can also roll back manually from the backup directory.
每次会话使用带时间戳的目录；失败时自动还原，也可从备份目录手工回滚。

## Logging / 日志

- `/var/log/linuxguard.log` as root / 以 root 运行时
- `/tmp/linuxguard-<pid>.log` otherwise / 其他情况

Entries include timestamp, action, target and details / 每条记录包含时间、动作、目标与详情。

## Safety Rules / 安全规则

- Fix mode (except `--dry-run`) requires root / 修复模式（除 dry-run）需 root。
- Files are backed up before modification / 修改前先备份。
- Configurations validated where possible (e.g. `sshd -t`) / 尽可能校验配置（如 `sshd -t`）。
- Repairs verified by re-running the relevant rule / 通过重新运行相关规则复核修复。
- No user deletion, blind service shutdown, or full system upgrades / 不删除用户、不盲目关闭服务、不做全系统升级。

## Example Session / 示例

```sh
# Review what would change / 预览变更（无需 root）
./linuxguard.sh fix --dry-run

# Apply only low-risk fixes / 仅应用低风险修复
sudo ./linuxguard.sh fix --safe

# Confirm each repair / 逐项确认
sudo ./linuxguard.sh fix --interactive
```
