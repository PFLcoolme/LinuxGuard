#!/bin/sh
# modules/audit.sh - Auditing & logging subsystem module
# Read-only: checks service status, config files and log file metadata.

_lg_audit_clean() {
    printf '%s' "$1" | tr '\n|' ';/' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-260
}

# _lg_audit_file RULE NAME PATH WANT_MODE IMPACT FIX
_lg_audit_file() {
    _title='Audit & Logging / 审计与日志'
    _p=$3
    if [ ! -e "$_p" ]; then
        lg_finding "UNKNOWN" "$_title" "$1" "$2" "Unknown / 未知" \
            "${_p} not found / 未找到 ${_p}" \
            "Cannot assess this log source / 无法评估该日志来源。" \
            "Ensure the logging service is installed / 请确认日志服务已安装。"
        return
    fi
    _m=$(lg_file_mode "$_p" 2>/dev/null)
    _ok=0
    case "$4" in
        le600) [ -n "$_m" ] && [ "$_m" -le 600 ] 2>/dev/null && _ok=1 ;;
        le640) [ -n "$_m" ] && [ "$_m" -le 640 ] 2>/dev/null && _ok=1 ;;
    esac
    if [ "$_ok" -eq 1 ]; then
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "$(_lg_audit_clean "$_p") mode=${_m}" "$5" \
            "No action required / 无需操作。"
    else
        lg_finding "MEDIUM" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "$(_lg_audit_clean "$_p") mode=${_m:-unknown}" "$5" "$6"
    fi
}

# _lg_audit_svc RULE NAME SERVICE
_lg_audit_svc() {
    _title='Audit & Logging / 审计与日志'
    _s=$3
    _active=''
    if lg_command_exists systemctl; then
        _active=$(systemctl is-active "$_s" 2>/dev/null)
    fi
    if [ "$_active" = "active" ]; then
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "${_s}: ${_active}" \
            "The service is running / 该服务正在运行。" \
            "No action required / 无需操作。"
    elif [ -n "$_active" ]; then
        lg_finding "MEDIUM" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "${_s}: ${_active}" \
            "The logging service is not active / 该日志服务未处于运行状态。" \
            "Enable and start the service / 启用并启动该服务。"
    else
        lg_finding "SKIP" "$_title" "$1" "$2" "Skipped / 跳过" \
            "systemctl unavailable or service unknown / systemctl 不可用或服务未知" \
            "Cannot determine service status / 无法确定服务状态。" \
            "Check service status manually / 请手动检查服务状态。"
    fi
}

lg_run_audit() {
    _title='Audit & Logging / 审计与日志'

    # 1. auditd daemon status.
    _lg_audit_svc "AUDIT_AUDITD" "auditd service / auditd 服务" "auditd"

    # 2. audit rules file presence.
    if [ -r /etc/audit/audit.rules ]; then
        _n=$(grep -cvE '^[[:space:]]*(#|$)' /etc/audit/audit.rules 2>/dev/null)
        if [ "$_n" -gt 0 ] 2>/dev/null; then
            lg_finding "PASS" "$_title" "AUDIT_RULES" \
                "auditd rules configured / 已配置 auditd 规则" "Compliant / 合规" \
                "${_n} active rule line(s) in /etc/audit/audit.rules" \
                "Active audit rules record security-relevant events / 生效的审计规则可记录安全相关事件。" \
                "No action required / 无需操作。"
        else
            lg_finding "MEDIUM" "$_title" "AUDIT_RULES" \
                "auditd rules configured / 已配置 auditd 规则" "Risk found / 发现风险" \
                "No active rule lines / 无生效规则行" \
                "Without rules auditd records little of value / 没有规则时 auditd 几乎不记录有效事件。" \
                "Deploy a baseline ruleset (e.g. 30-stig.rules) / 部署基线规则集（如 30-stig.rules）。"
        fi
    else
        lg_finding "UNKNOWN" "$_title" "AUDIT_RULES" \
            "auditd rules configured / 已配置 auditd 规则" "Unknown / 未知" \
            "/etc/audit/audit.rules unreadable / 该文件不可读" \
            "Cannot verify audit rules / 无法验证审计规则。" \
            "Ensure auditd is installed / 请确认 auditd 已安装。"
    fi

    # 3. systemd-journald status.
    _lg_audit_svc "AUDIT_JOURNALD" "journald service / journald 服务" "systemd-journald"

    # 4. rsyslog / syslog-ng status.
    if lg_command_exists systemctl && [ "$(systemctl is-active rsyslog 2>/dev/null)" = "active" ]; then
        lg_finding "PASS" "$_title" "AUDIT_SYSLOG" \
            "Syslog daemon active / Syslog 守护进程运行中" "Compliant / 合规" \
            "rsyslog: active" \
            "A syslog daemon is collecting system logs / Systemd 日志之外仍有 syslog 守护进程收集日志。" \
            "No action required / 无需操作。"
    elif lg_command_exists systemctl && [ "$(systemctl is-active syslog-ng 2>/dev/null)" = "active" ]; then
        lg_finding "PASS" "$_title" "AUDIT_SYSLOG" \
            "Syslog daemon active / Syslog 守护进程运行中" "Compliant / 合规" \
            "syslog-ng: active" \
            "A syslog daemon is collecting system logs / 有 syslog 守护进程收集日志。" \
            "No action required / 无需操作。"
    elif [ -d /etc/rsyslog.d ] || [ -r /etc/rsyslog.conf ] || [ -r /etc/syslog-ng.conf ]; then
        lg_finding "MEDIUM" "$_title" "AUDIT_SYSLOG" \
            "Syslog daemon active / Syslog 守护进程运行中" "Risk found / 发现风险" \
            "Config present but no active syslog service / 存在配置但服务未运行" \
            "Syslog configuration without a running daemon loses logs / 守护进程未运行时日志会丢失。" \
            "Enable rsyslog or syslog-ng / 启用 rsyslog 或 syslog-ng。"
    else
        lg_finding "SKIP" "$_title" "AUDIT_SYSLOG" \
            "Syslog daemon active / Syslog 守护进程运行中" "Skipped / 跳过" \
            "No syslog daemon detected / 未检测到 syslog 守护进程" \
            "journald may be the only logger / 可能仅由 journald 记录日志。" \
            "Verify the intended logging architecture / 请确认预期的日志架构。"
    fi

    _lg_audit_file "AUDIT_AUTHLOG_MODE" "auth.log permissions / auth.log 权限" \
        /var/log/auth.log 640 \
        "Authentication logs may contain sensitive account data / 认证日志可能包含敏感账户信息。" \
        "chmod 640 /var/log/auth.log / 执行 chmod 640 /var/log/auth.log。"
    _lg_audit_file "AUDIT_SECURE_MODE" "secure log permissions / secure 日志权限" \
        /var/log/secure 640 \
        "Authentication logs may contain sensitive account data / 认证日志可能包含敏感账户信息。" \
        "chmod 640 /var/log/secure / 执行 chmod 640 /var/log/secure。"
    _lg_audit_file "AUDIT_MESSAGES_MODE" "messages log permissions / messages 日志权限" \
        /var/log/messages 640 \
        "System logs can leak host details to unprivileged users / 系统日志可能向非特权用户泄露主机细节。" \
        "chmod 640 /var/log/messages / 执行 chmod 640 /var/log/messages。"

    # 8. journald persistent storage.
    if [ -r /etc/systemd/journald.conf ]; then
        _st=$(grep -E '^[[:space:]]*Storage=' /etc/systemd/journald.conf 2>/dev/null | head -n 1)
        case "$_st" in
            *persistent*|*auto*)
                lg_finding "PASS" "$_title" "AUDIT_JOURNAL_PERSIST" \
                    "Persistent journal storage / 持久化 journal 存储" "Compliant / 合规" \
                    "$(_lg_audit_clean "${_st:-Storage=auto (default)}")" \
                    "Logs survive a reboot for forensic review / 日志在重启后仍可用于取证。" \
                    "No action required / 无需操作。" ;;
            *volatile*|*none*)
                lg_finding "MEDIUM" "$_title" "AUDIT_JOURNAL_PERSIST" \
                    "Persistent journal storage / 持久化 journal 存储" "Risk found / 发现风险" \
                    "$(_lg_audit_clean "$_st")" \
                    "Volatile journals are lost on reboot / 易失性 journal 在重启后丢失，妨碍取证。" \
                    "Set Storage=persistent / 设置 Storage=persistent。" ;;
            *)
                lg_finding "LOW" "$_title" "AUDIT_JOURNAL_PERSIST" \
                    "Persistent journal storage / 持久化 journal 存储" "Informational / 信息" \
                    "Storage not explicitly configured / 未显式配置 Storage" \
                    "Default behaviour depends on /var/log/journal presence / 默认行为取决于 /var/log/journal 是否存在。" \
                    "Set Storage=persistent explicitly / 显式设置 Storage=persistent。" ;;
        esac
    else
        lg_finding "UNKNOWN" "$_title" "AUDIT_JOURNAL_PERSIST" \
            "Persistent journal storage / 持久化 journal 存储" "Unknown / 未知" \
            "/etc/systemd/journald.conf unreadable / 该文件不可读" \
            "Cannot verify journal persistence / 无法验证 journal 持久化配置。" \
            "Check journald configuration / 请检查 journald 配置。"
    fi

    # 9. Log rotation configured.
    if [ -d /etc/logrotate.d ] && [ -n "$(ls -A /etc/logrotate.d 2>/dev/null)" ]; then
        lg_finding "PASS" "$_title" "AUDIT_LOGROTATE" \
            "Log rotation configured / 已配置日志轮转" "Compliant / 合规" \
            "/etc/logrotate.d has entries / 该目录存在配置项" \
            "Rotation prevents logs from filling the filesystem / 轮转可防止日志占满文件系统。" \
            "No action required / 无需操作。"
    else
        lg_finding "LOW" "$_title" "AUDIT_LOGROTATE" \
            "Log rotation configured / 已配置日志轮转" "Risk found / 发现风险" \
            "No logrotate.d entries found / 未发现 logrotate.d 配置项" \
            "Unbounded logs may exhaust disk and stop recording / 无限制增长的日志可能耗尽磁盘并停止记录。" \
            "Install and configure logrotate / 安装并配置 logrotate。"
    fi

    # 10. Remote log forwarding (defence-in-depth, informational).
    _remote=''
    for _f in /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog-ng/syslog-ng.conf; do
        [ -r "$_f" ] || continue
        if grep -Eq '^[[:space:]]*[^#].*@@?[0-9a-zA-Z.:_-]+' "$_f" 2>/dev/null; then
            _remote="$_f"; break
        fi
    done
    if [ -n "$_remote" ]; then
        lg_finding "PASS" "$_title" "AUDIT_REMOTE_LOG" \
            "Remote log forwarding / 远程日志转发" "Compliant / 合规" \
            "Forwarding rule found in ${_remote}" \
            "Off-host copies survive local tampering / 异地副本可在本机被篡改后保留证据。" \
            "No action required / 无需操作。"
    else
        lg_finding "LOW" "$_title" "AUDIT_REMOTE_LOG" \
            "Remote log forwarding / 远程日志转发" "Informational / 信息" \
            "No remote forwarding rule detected / 未检测到远程转发规则" \
            "An attacker with root can erase local logs / 获得 root 的攻击者可清除本地日志。" \
            "Consider a centralised log collector / 可考虑集中式日志收集。"
    fi
}
