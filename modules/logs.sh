#!/bin/sh
# modules/logs.sh - Authentication log audit module

lg_run_logs() {
    if lg_command_exists journalctl; then
        _count=$(journalctl --no-pager -p err..alert -n 200 2>/dev/null | wc -l | tr -d ' ')
        lg_finding \
            "LOW" \
            "Log Audit / 日志审计" \
            "LOG_SYSTEM_ERRORS" \
            "Recent high-priority journal entries sampled / 已采样近期高优先级 journal 条目" \
            "Informational / 信息" \
            "${_count:-0} line(s) in last 200 entries / 最近 200 条中有 ${_count:-0} 行" \
            "High-priority journal entries may indicate errors or security events / 高优先级 journal 条目可能表示错误或安全事件。" \
            "Review relevant entries; this is not a complete intrusion-detection analysis / 查看相关条目；这不是完整的入侵检测分析。"
    elif [ -r /var/log/auth.log ]; then
        _count=$(grep -Ei 'failed password|authentication failure|invalid user' /var/log/auth.log 2>/dev/null | tail -n 100 | wc -l | tr -d ' ')
        lg_finding \
            "LOW" \
            "Log Audit / 日志审计" \
            "LOG_AUTH_FAILURES" \
            "Authentication failure sample collected / 已收集认证失败样本" \
            "Informational / 信息" \
            "${_count:-0} matching line(s) in recent sample / 近期样本中有 ${_count:-0} 行匹配" \
            "Repeated authentication failures may indicate brute-force attempts / 重复的认证失败可能表示暴力破解尝试。" \
            "Investigate repeated failures and correlate source addresses / 调查重复失败并关联源地址。"
    elif [ -r /var/log/secure ]; then
        _count=$(grep -Ei 'failed password|authentication failure|invalid user' /var/log/secure 2>/dev/null | tail -n 100 | wc -l | tr -d ' ')
        lg_finding \
            "LOW" \
            "Log Audit / 日志审计" \
            "LOG_AUTH_FAILURES" \
            "Authentication failure sample collected / 已收集认证失败样本" \
            "Informational / 信息" \
            "${_count:-0} matching line(s) in recent sample / 近期样本中有 ${_count:-0} 行匹配" \
            "Repeated authentication failures may indicate brute-force attempts / 重复的认证失败可能表示暴力破解尝试。" \
            "Investigate repeated failures and correlate source addresses / 调查重复失败并关联源地址。"
    else
        lg_finding \
            "UNKNOWN" \
            "Log Audit / 日志审计" \
            "LOG_AUTH_UNAVAILABLE" \
            "No readable authentication log source found / 未找到可读的认证日志源" \
            "Unknown / 未知" \
            "journalctl/auth.log/secure unavailable / journalctl/auth.log/secure 不可用" \
            "Cannot sample authentication failures / 无法采样认证失败。" \
            "Check journald or distribution-specific authentication logs / 检查 journald 或发行版特定的认证日志。"
    fi
}
