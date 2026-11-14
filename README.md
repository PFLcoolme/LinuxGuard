# LinuxGuard

A read-only Linux security auditing tool written in POSIX Shell, with an optional, backup-backed repair mode.
一个用 POSIX Shell 编写的 Linux 只读安全审计工具，附带受备份保护的可选修复模式。

No compilation, no package installation, no daemons. Just `/bin/sh` and standard POSIX utilities.
无需编译、无需安装依赖、无守护进程，只需 `/bin/sh` 与标准 POSIX 工具。

**Version / 版本:** v1.2.0 · **License:** MIT · **Modules:** 20 / **Checks:** 98

---

## Features / 特性

- **Read-only by design** — scan mode never modifies the system: no package changes, no permission changes, no service restarts, no patching. / 扫描模式**只读**，绝不修改系统。
- **Security score (0–100)** with severity breakdown, grouped findings tree and repair feasibility statistics. / 安全评分、严重度统计、分组发现项与修复可行性统计。
- **98 checks across 20 modules**, covering kernel, SSH, accounts, firewall, ports, Docker, logs, threat indicators and hardening baselines. / 20 个模块共 98 项检查。
- **Graceful degradation** — missing tools or privileges yield `UNKNOWN` / `SKIP` with an explanation instead of a false pass. / 缺少工具或权限时标记 `UNKNOWN`/`SKIP`，绝不误报为通过。
- **Controlled repair mode** — root required, automatic backup, rollback, config validation, post-repair verification and level-based confirmation. / 修复模式需 root，含自动备份、回滚、配置校验、修复复核与分级确认。
- **No sensitive output** — password hashes and SSH private keys are never printed. / 从不输出密码哈希与 SSH 私钥。

## Quick Start / 快速开始

```sh
git clone https://github.com/PFLcoolme/LinuxGuard.git
cd LinuxGuard
chmod +x linuxguard.sh

./linuxguard.sh                    # full audit / 完整审计
./linuxguard.sh --help
./linuxguard.sh --version
```

### Scan examples / 扫描示例

```sh
./linuxguard.sh scan --ssh --verbose          # single module / 单模块
./linuxguard.sh scan --threats                # processes + malware + vulnscan
./linuxguard.sh scan --hardening --verbose    # 50 hardening checks / 50 项加固检查
./linuxguard.sh scan --report /tmp/report.txt # export / 导出报告
./linuxguard.sh scan --no-color --quiet
```

### Fix examples / 修复示例

```sh
./linuxguard.sh fix --dry-run        # plan only, no root needed / 仅计划，无需 root
sudo ./linuxguard.sh fix --safe      # auto-repair L1 only / 仅自动修复 L1
sudo ./linuxguard.sh fix --interactive
sudo ./linuxguard.sh fix --all
```

> `--dry-run` changes nothing. All other fix modes require **root** and back up every file before modifying it.
> `--dry-run` 不做任何更改；其余修复模式均需 **root**，并在修改前自动备份。

## Modules / 模块清单

|Group / 分组|Modules|
|---|---|
|Core / 基础|`system` `ssh` `users` `sudo` `firewall` `kernel` `ports` `permissions` `packages` `cron` `docker` `logs`|
|Threat indicators / 威胁指标（只读）|`processes` `malware` `vulnscan`|
|Hardening / 加固基线（只读）|`netstack` `filesystem` `auth` `audit` `services`|

Threat and hardening modules are **indicator checks**, not a full antivirus/CVE scan. A clean result is not proof that a host is secure — human judgment and dedicated scanners are still required.
威胁与加固模块均为**指标检查**，并非完整的杀毒/CVE 扫描；未发现问题不代表主机绝对安全。

Useful aggregate options / 常用聚合选项：

- `--threats` → `processes` `malware` `vulnscan`
- `--hardening` → `netstack` `filesystem` `auth` `audit` `services`（50 项）
- `--network` → `firewall` `ports`
- `--all-modules` → 全部 20 个模块

## Privileges / 权限说明

|Mode|Requirement|Notes|
|---|---|---|
|Scan / 扫描|any user / 任意用户|root 可读取 `/etc/shadow`、执行 `sshd -T`、检查全部 sudoers/cron 文件|
|Fix / 修复|**root**（除 `--dry-run`）|无 root 时拒绝启动，以保证备份与系统变更安全|

## Security Boundaries / 安全边界

- Scan mode is strictly read-only; `--report FILE` only writes a plain-text report to the path you choose. / 扫描严格只读，报告仅写出你指定的文本文件。
- Threat modules only read `/proc`, local package indexes and indicator files. They never run an antivirus scan, refresh repositories, download signatures or kill a process. / 威胁模块不扫描、不刷新仓库、不下载特征库、不终止进程。
- Hardening modules only read `/proc/sys`, `/proc/mounts`, `/etc` policy files and service state. They never write sysctl values, remount, change passwords, edit PAM rules or toggle services. / 加固模块不写 sysctl、不重挂载、不改口令、不改 PAM、不启停服务。
- All threat/hardening findings are reported as `Manual / 需手工` and are **never** auto-repaired. / 这些发现项永不被自动修复。
- The security score is an **indicator, not a certification** — always review individual findings. / 评分仅为参考指标，并非安全认证。

## Requirements / 环境要求

- Linux with `/bin/sh` (dash, bash in sh mode, busybox ash, …) / 带 `/bin/sh` 的 Linux
- POSIX utilities: `grep` `awk` `sed` `tr` `cut` `wc` `date` `id` `uname` `dirname` `readlink`
- Optional for full coverage / 完整检测可选：`sshd` `chage` `nft` `iptables` `ufw` `firewall-cmd` `systemctl` `sysctl`

Target distributions / 目标发行版：Debian / Ubuntu、Arch Linux、Fedora、Alpine Linux；其他发行版通常也可运行（依赖通用 POSIX 命令与 `/etc/os-release` 解析）。

## Documentation / 文档

- [`docs/INSTALL.md`](docs/INSTALL.md) — installation, usage, privileges / 安装、用法、权限
- [`docs/SECURITY.md`](docs/SECURITY.md) — read-only design, scoring, repair safety, sensitive data handling / 只读设计、评分、修复安全、敏感数据
- [`docs/REPAIR.md`](docs/REPAIR.md) — repair levels, backups, rollback / 修复等级、备份、回滚

## License

[MIT](LICENSE) © 2026 LinuxGuard Contributors
