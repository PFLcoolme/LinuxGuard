# LinuxGuard 安装与使用 / Installation & Usage

LinuxGuard is a POSIX Shell script. No compilation or package installation is required.
LinuxGuard 是一个 POSIX Shell 脚本，无需编译或安装软件包。

## Requirements / 环境要求

- A Linux system with `/bin/sh` (dash, bash in sh mode, busybox ash, etc.) / 带 `/bin/sh` 的 Linux 系统（dash、sh 模式下的 bash、busybox ash 等）
- Standard POSIX utilities: `grep`, `awk`, `sed`, `tr`, `cut`, `wc`, `date`, `id`, `uname`, `dirname`, `readlink` / 标准 POSIX 工具
- Optional for full coverage: `sshd`, `chage`, `nft`, `iptables`, `ufw`, `firewall-cmd`, `systemctl`, `sysctl` / 完整检测所需的可选工具

## Install / 安装

```sh
git clone <repository-url> LinuxGuard
cd LinuxGuard
chmod +x linuxguard.sh
./linuxguard.sh --help
```

Or copy the `LinuxGuard/` directory anywhere (e.g. `/opt/linuxguard`) and run from there.
也可将 `LinuxGuard/` 目录复制到任意位置（如 `/opt/linuxguard`）后直接运行。

## Usage / 用法

### Scan mode (default) / 扫描模式（默认）

```sh
# Full audit / 完整审计
./linuxguard.sh
./linuxguard.sh scan

# Module-specific audit / 指定模块审计
./linuxguard.sh scan --ssh --verbose
./linuxguard.sh scan --kernel --no-color
./linuxguard.sh scan --threats --verbose   # processes + malware + vulnscan / 威胁检查
./linuxguard.sh scan --hardening --verbose # 50 hardening checks / 50 项加固检查

# Detailed output / 详细输出
./linuxguard.sh --verbose

# Report & colour / 报告导出与颜色
./linuxguard.sh scan --report /tmp/linuxguard-report.txt
./linuxguard.sh scan --color          # force colours / 强制彩色（截图/演示用）
./linuxguard.sh scan --no-color       # plain output / 无颜色
./linuxguard.sh scan --quiet          # hide banner / 隐藏横幅
./linuxguard.sh --help
```

The scan report shows a **security score (0-100)**, severity breakdown, a grouped findings tree, and repair feasibility.
扫描报告包含**安全评分（0-100）**、严重度统计、分组树状发现项与修复可行性统计。

### Fix mode / 修复模式

`--dry-run` only displays a plan and needs no root; all other fix modes require **root** and back up files before modifying them.
`--dry-run` 仅展示计划、无需 root；其余修复模式均需 **root** 权限，并在修改前自动备份文件。

```sh
# Show repair plan without changes (no root needed) / 仅显示修复计划（无需 root）
./linuxguard.sh fix --dry-run

# Auto-repair only low-risk (L1) findings / 仅自动修复低风险 L1 项
sudo ./linuxguard.sh fix --safe

# Confirm each repair (default) / 逐项确认修复（默认）
sudo ./linuxguard.sh fix --interactive

# Repair all after summary confirmation / 汇总确认后全部修复
sudo ./linuxguard.sh fix --all
```

## Privileges / 权限说明

### Scan / 扫描

LinuxGuard runs as any user; root enables reading `/etc/shadow`, `sshd -T`, accurate permission checks and all sudoers/cron files.
LinuxGuard 可以任意用户运行；root 可读取 `/etc/shadow`、执行 `sshd -T`、精确检查权限及全部 sudoers/cron 文件。

Non-root checks that need elevation are marked `UNKNOWN` or `SKIP` with an explanation.
非 root 环境下需要提权的检查会标记为 `UNKNOWN` 或 `SKIP` 并附说明。

### Fix / 修复

Fix mode (except `--dry-run`) **must** run as root; it refuses to start otherwise so backups and system changes are safe.
修复模式（除 `--dry-run` 外）**必须**以 root 运行，否则会拒绝启动，以保证备份与系统变更安全。

## Supported Distributions / 支持的发行版

V1.2 implements 20 detection modules / V1.2 实现 20 个检测模块：

- system, ssh, users, sudo, firewall, kernel
- ports, permissions, packages, cron, docker, logs
- processes, malware, vulnscan (threat indicators / 威胁指标，只读)
- netstack, filesystem, auth, audit, services (hardening / 加固检查，只读)

Three threat modules are read-only indicator checks; `--threats` runs all of them together.
三个威胁模块为只读指标检查；`--threats` 可一次性运行全部三项。

The five V1.2 hardening modules add 50 read-only checks (10 each); `--hardening` runs all of them.
V1.2 的五个加固模块共新增 50 项只读检查（每个模块 10 项）；`--hardening` 可一次运行全部。

Target distributions / 目标发行版：Debian / Ubuntu、Arch Linux、Fedora、Alpine Linux。其他发行版通常也可运行（依赖通用 POSIX 命令与 `/etc/os-release` 解析）。
