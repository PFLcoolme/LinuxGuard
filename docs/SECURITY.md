# LinuxGuard 安全说明 / Security Notes

## Read-Only by Design (Scan Mode) / 扫描模式只读设计

In scan mode LinuxGuard does **not** modify the system. It never installs/removes packages, changes permissions, disables services, applies patches or restarts daemons.
扫描模式下 LinuxGuard **不会**修改系统：不安装/卸载软件包、不改权限、不停服务、不打补丁、不重启守护进程。所有操作均为只读观测。

The three threat modules (`processes`, `malware`, `vulnscan`) follow the same rule: they only read `/proc`, local package indexes and a few indicator files. They never run an antivirus scan, refresh repositories, download signatures, or kill a process.
三个威胁模块（`processes`、`malware`、`vulnscan`）同样只读：仅读取 `/proc`、本地软件包索引和少量指标文件；**不会**运行杀毒扫描、刷新仓库、下载特征库或终止进程。

Absence of findings in these modules is **not** proof that a host is clean — they are indicator checks that require human judgment and a dedicated scanner for full assurance.
这些模块未发现问题**不代表**主机绝对干净——它们属于指标检查，完整保障仍需人工判断与专用扫描器。

The five V1.2 hardening modules (`netstack`, `filesystem`, `auth`, `audit`, `services`) add 50 further read-only checks. They read `/proc/sys`, `/proc/mounts`, `/etc` policy files and service state only; they never write a sysctl value, remount a filesystem, change a password, modify a PAM rule, or enable/disable a service.
V1.2 的五个加固模块（`netstack`、`filesystem`、`auth`、`audit`、`services`）新增 50 项只读检查：仅读取 `/proc/sys`、`/proc/mounts`、`/etc` 下的策略文件与服务状态；**不会**写入 sysctl、重新挂载、修改口令、改动 PAM 规则或启停服务。

All 50 checks are reported as `Manual / 需手工` in fix mode and are never auto-repaired.
这 50 项检查在修复模式下均记为 `Manual / 需手工`，不会被自动修复。

The report is read-only too; `--report FILE` only writes a plain-text file to the path you choose.
报告本身也是只读的；`--report FILE` 仅在你指定的路径写出纯文本文件。

## Security Score / 安全评分

The scan computes a composite score (0-100) via weighted deductions per severity, with a grade A–F:
扫描按严重度加权扣分计算综合评分（0-100）并给出 A–F 等级：

- `CRITICAL` −25、`HIGH` −12、`MEDIUM` −5、`LOW` −2、`UNKNOWN` −1；`PASS`/`SKIP` 不扣分
- 90–100 A/优秀 · 80–89 B/良好 · 70–79 C/一般 · 60–69 D/及格 · 50–59 E/偏低 · <50 F/危险

The score is an **indicator, not a certification**; always review individual findings.
评分仅为**参考指标，并非安全认证**，请务必逐项查看具体发现。

## Automatic Repair Safety (Fix Mode) / 修复模式安全机制

Fix mode modifies configuration; these protections apply (except `--dry-run`, which changes nothing and needs no root):
修复模式会修改配置，具备以下保护（`--dry-run` 除外，它不修改任何内容且无需 root）：

- **Root required / 需 root**：`fix` 除 dry-run 外拒绝无 root 运行。
- **Automatic backup / 自动备份**：修改前将文件复制到会话备份目录。
- **Automatic rollback / 自动回滚**：验证或复核失败时从备份还原。
- **Configuration validation / 配置校验**：SSH 修复后运行 `sshd -t`，其他修复尽可能校验。
- **Repair verification / 修复复核**：每项修复后重新运行对应检测规则确认问题已解决。
- **Level-based policy / 分级策略**：按风险等级分级，`--safe` 仅自动修复 L1，更高级别需确认。
- **Operation logging / 操作日志**：记录修复、备份、回滚与校验动作。

## Sensitive Data Handling / 敏感数据处理

- Password hashes from `/etc/shadow` are never displayed / 从不显示 `/etc/shadow` 密码哈希。
- SSH private keys are not read or printed / 不读取或打印 SSH 私钥。
- Auth logs are summarized, not dumped / 认证日志仅汇总、不全量输出。

Some evidence (sudoers snippets, account names) may still be sensitive; review output before sharing.
部分证据（sudoers 片段、账户名）仍可能敏感，分享输出前请审阅。

## Risk Ratings / 风险等级

- `CRITICAL` — immediate risk / 立即风险
- `HIGH` — clear unsafe configuration / 明显不安全配置
- `MEDIUM` — potential weakness / 潜在弱点
- `LOW` — optimization or info / 优化或信息项
- `PASS` — check passed / 检查通过
- `UNKNOWN` — could not determine (≠ pass) / 无法判定（≠ 通过）
- `SKIP` — not applicable / missing dependency / 不适用或缺少依赖

## Repair Levels / 修复等级

- `L1` — low risk, auto-repairable in `--safe` / 低风险，`--safe` 可自动修复
- `L2` — medium risk / 中风险
- `L3` — high risk, explicit confirmation / 高风险，需显式确认
- `L4` — critical risk, strict confirmation + manual review / 严重风险，严格确认 + 人工复核

## Reporting Issues / 问题反馈

Please include / 请提供：

- Output of `./linuxguard.sh --version` / 版本输出
- Linux distribution and version / 发行版与版本
- Shell (`ls -l /bin/sh`) / Shell 信息
- The module and rule that appear wrong / 出错的模块与规则
- Whether it occurs in scan or fix mode / 发生在扫描还是修复模式
