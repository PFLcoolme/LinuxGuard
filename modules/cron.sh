#!/bin/sh
# modules/cron.sh - Scheduled task audit module

lg_run_cron() {
    _count=0
    _files=''
    for _f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
        if [ -f "$_f" ]; then
            _count=$((_count + 1))
            if [ -n "$_files" ]; then
                _files="${_files}, ${_f}"
            else
                _files="${_f}"
            fi
        fi
    done

    if [ "$_count" -gt 0 ]; then
        lg_finding \
            "LOW" \
            "Scheduled Tasks / 计划任务" \
            "CRON_INVENTORY" \
            "Scheduled task files found / 发现计划任务文件" \
            "Informational / 信息" \
            "${_files}" \
            "Cron files can be abused for persistence if writable by non-root users / 若 cron 文件可被非 root 用户写入，可能被用于持久化。" \
            "Review unfamiliar commands, writable scripts, and unexpected schedules / 检查不熟悉的命令、可写脚本和异常计划。"
    else
        lg_finding \
            "PASS" \
            "Scheduled Tasks / 计划任务" \
            "CRON_INVENTORY" \
            "No conventional cron files found / 未发现常规 cron 文件" \
            "Compliant / 合规" \
            "Checked /etc/crontab, /etc/cron.d, /var/spool/cron / 已检查 /etc/crontab、/etc/cron.d、/var/spool/cron" \
            "No cron files detected / 未检测到 cron 文件。" \
            "Systemd timers may still be present / 仍可能存在 systemd timers。"
    fi

    # Check systemd timers if available
    if lg_command_exists systemctl; then
        _timers=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -n 20)
        _timer_count=$(printf '%s' "$_timers" | grep -c . 2>/dev/null || printf '0')
        if [ "$_timer_count" -gt 0 ]; then
            lg_finding \
                "LOW" \
                "Scheduled Tasks / 计划任务" \
                "SYSTEMD_TIMERS" \
                "Systemd timers are active / 存在活动的 systemd timers" \
                "Informational / 信息" \
                "${_timer_count} timer(s) / ${_timer_count} 个 timer" \
                "Timers can also be used for persistence / Timers 也可能被用于持久化。" \
                "Review timer units and their associated services / 检查 timer 单元及其关联服务。"
        else
            lg_finding \
                "PASS" \
                "Scheduled Tasks / 计划任务" \
                "SYSTEMD_TIMERS" \
                "No active systemd timers / 无活动的 systemd timers" \
                "Compliant / 合规" \
                "systemctl list-timers returned none / systemctl list-timers 未返回结果" \
                "No systemd timers detected / 未检测到 systemd timers。" \
                "No action required / 无需操作。"
        fi
    fi
}
