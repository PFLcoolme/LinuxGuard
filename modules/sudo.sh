#!/bin/sh
# modules/sudo.sh - sudo privilege audit module

# Collect all sudoers configuration lines (excluding comments and empty lines)
_lg_sudo_collect_lines() {
    _tmp=$(lg_mktemp)
    if [ -r /etc/sudoers ]; then
        grep -vE '^[[:space:]]*(#|$)' /etc/sudoers >> "$_tmp" 2>/dev/null
    fi
    if [ -d /etc/sudoers.d ]; then
        for _f in /etc/sudoers.d/*; do
            if [ -f "$_f" ] && [ -r "$_f" ]; then
                grep -vE '^[[:space:]]*(#|$)' "$_f" >> "$_tmp" 2>/dev/null
            fi
        done
    fi
    printf '%s' "$_tmp"
}

# Check if sudo is installed
lg_run_sudo() {
    if ! lg_command_exists sudo; then
        lg_finding \
            "SKIP" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_INSTALLED" \
            "sudo command not found / 未找到 sudo 命令" \
            "Skipped / 跳过" \
            "sudo not in PATH / sudo 不在 PATH 中" \
            "sudo does not appear to be installed / sudo 似乎未安装。" \
            "No action required unless sudo is expected / 除非需要 sudo，否则无需操作。"
        return
    fi

    if ! lg_command_exists visudo && ! [ -r /etc/sudoers ]; then
        lg_finding \
            "UNKNOWN" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_READABLE" \
            "Cannot read sudoers configuration / 无法读取 sudoers 配置" \
            "Unknown / 未知" \
            "Permission denied / 权限拒绝" \
            "Run as root for complete sudoers analysis / 请以 root 运行以完成 sudoers 分析。" \
            "Re-run with root privileges / 请以 root 权限重新运行。"
        return
    fi

    _sudoers_file=$(_lg_sudo_collect_lines)

    # Check for NOPASSWD usage
    _nopasswd=$(grep -iE '\bNOPASSWD\b' "$_sudoers_file" 2>/dev/null)
    if [ -n "$_nopasswd" ]; then
        _nopasswd_summary=$(printf '%s' "$_nopasswd" | head -n 3 | tr '\n' '; ' | sed 's/; $//')
        lg_finding \
            "HIGH" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_NOPASSWD" \
            "NOPASSWD sudo entries found / 发现 NOPASSWD sudo 条目" \
            "Risk found / 发现风险" \
            "${_nopasswd_summary}" \
            "NOPASSWD allows privilege escalation without password verification / NOPASSWD 允许无需密码验证提升权限。" \
            "Require password authentication for all sudo commands / 要求所有 sudo 命令进行密码认证。"
    else
        lg_finding \
            "PASS" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_NOPASSWD" \
            "No NOPASSWD sudo entries found / 未发现 NOPASSWD sudo 条目" \
            "Compliant / 合规" \
            "No NOPASSWD directives / 无 NOPASSWD 指令" \
            "All sudo commands require password authentication / 所有 sudo 命令都需要密码认证。" \
            "No action required / 无需操作。"
    fi

    # Check for ALL=(ALL) or ALL=(ALL:ALL) usage
    _all_all=$(grep -iE 'ALL[[:space:]]*=[[:space:]]*\(ALL' "$_sudoers_file" 2>/dev/null)
    if [ -n "$_all_all" ]; then
        _all_all_summary=$(printf '%s' "$_all_all" | head -n 3 | tr '\n' '; ' | sed 's/; $//')
        lg_finding \
            "MEDIUM" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_ALL_ALL" \
            "Broad sudo privileges (ALL) detected / 检测到宽泛的 sudo 权限 (ALL)" \
            "Risk found / 发现风险" \
            "${_all_all_summary}" \
            "Granting ALL privileges reduces accountability and increases blast radius / 授予 ALL 权限会降低可追溯性并扩大影响范围。" \
            "Restrict sudo rules to specific users, commands, and hosts / 将 sudo 规则限制为特定用户、命令和主机。"
    else
        lg_finding \
            "PASS" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_ALL_ALL" \
            "No unrestricted ALL sudo entries / 无不受限制的 ALL sudo 条目" \
            "Compliant / 合规" \
            "No ALL=(ALL) directives / 无 ALL=(ALL) 指令" \
            "Sudo privileges are scoped / sudo 权限已限定范围。" \
            "No action required / 无需操作。"
    fi

    # Check for risky patterns: wildcards, !authenticate
    _risky=$(grep -iE '(!authenticate|Cmnd_Alias[[:space:]]+.*=.*\*|\*[[:space:]]+ALL|ALL[[:space:]]+NOPASSWD)' "$_sudoers_file" 2>/dev/null)
    if [ -n "$_risky" ]; then
        _risky_summary=$(printf '%s' "$_risky" | head -n 3 | tr '\n' '; ' | sed 's/; $//')
        lg_finding \
            "MEDIUM" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_RISKY_PATTERN" \
            "Suspicious sudoers patterns found / 发现可疑的 sudoers 模式" \
            "Risk found / 发现风险" \
            "${_risky_summary}" \
            "Wildcards, !authenticate, or overly broad aliases may bypass security controls / 通配符、!authenticate 或过于宽泛的别名可能绕过安全控制。" \
            "Audit sudoers rules and remove unnecessary wildcards / 审计 sudoers 规则并移除不必要的通配符。"
    else
        lg_finding \
            "PASS" \
            "Sudo Privileges / sudo 权限" \
            "SUDO_RISKY_PATTERN" \
            "No suspicious sudoers patterns / 无可疑的 sudoers 模式" \
            "Compliant / 合规" \
            "No wildcards or !authenticate / 无通配符或 !authenticate" \
            "Sudoers rules appear clean / sudoers 规则看起来正常。" \
            "No action required / 无需操作。"
    fi

    # Check sudoers file permissions
    if [ -r /etc/sudoers ]; then
        _mode=$(lg_file_mode /etc/sudoers)
        if [ -n "$_mode" ] && [ "$_mode" -le 440 ]; then
            lg_finding \
                "PASS" \
                "Sudo Privileges / sudo 权限" \
                "SUDOERS_PERMISSIONS" \
                "/etc/sudoers permissions are restrictive / /etc/sudoers 权限受限" \
                "Compliant / 合规" \
                "Mode ${_mode} / 模式 ${_mode}" \
                "Sudoers file is not world-writable / sudoers 文件不可被其他用户写入。" \
                "No action required / 无需操作。"
        else
            lg_finding \
                "HIGH" \
                "Sudo Privileges / sudo 权限" \
                "SUDOERS_PERMISSIONS" \
                "/etc/sudoers permissions too permissive / /etc/sudoers 权限过于宽松" \
                "Risk found / 发现风险" \
                "Mode ${_mode:-unknown} / 模式 ${_mode:-unknown}" \
                "World-writable or overly permissive sudoers allows privilege escalation / 全局可写或过于宽松的 sudoers 可导致权限提升。" \
                "Set permissions to 440 or 400 (chmod 440 /etc/sudoers) / 设置权限为 440 或 400。"
        fi
    fi

    rm -f "$_sudoers_file"
}
