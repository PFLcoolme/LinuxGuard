#!/bin/sh
# modules/services.sh - Services, autostart & legacy network services module
# Read-only: systemctl/list-unit-files, /etc/xinetd.d, /etc/inetd.conf, rc dirs.

_lg_svc_clean() {
    printf '%s' "$1" | tr '\n|' ';/' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-260
}

# _lg_svc_enabled RULE NAME SERVICE IMPACT FIX
_lg_svc_enabled() {
    _title='Services / 服务与自启动'
    _s=$3
    if ! lg_command_exists systemctl; then
        lg_finding "SKIP" "$_title" "$1" "$2" "Skipped / 跳过" \
            "systemctl unavailable / systemctl 不可用" \
            "Cannot query service enablement / 无法查询服务启用状态。" \
            "Check init scripts manually / 请手动检查 init 脚本。"
        return
    fi
    _state=$(systemctl is-enabled "$_s" 2>/dev/null)
    case "$_state" in
        enabled|enabled-runtime|static|indirect|generated|alias)
            lg_finding "MEDIUM" "$_title" "$1" "$2" "Risk found / 发现风险" \
                "${_s}: ${_state}" "$4" "$5" ;;
        disabled|masked|'')
            lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
                "${_s}: ${_state:-not-found}" "$4" \
                "No action required / 无需操作。" ;;
        *)
            lg_finding "UNKNOWN" "$_title" "$1" "$2" "Unknown / 未知" \
                "${_s}: ${_state}" \
                "Unrecognised enablement state / 无法识别的启用状态。" \
                "Check with systemctl is-enabled / 请用 systemctl is-enabled 复核。" ;;
    esac
}

lg_run_services() {
    : "${LG_SVC_STARTUP_DIRS:=/etc/init.d /etc/rc.d /etc/cron.d /etc/systemd/system}"
    _title='Services / 服务与自启动'

    _lg_svc_enabled "SVC_TELNET" "Telnet service / Telnet 服务" "telnet.socket" \
        "Telnet transmits credentials in cleartext / Telnet 以明文传输凭据。" \
        "Disable telnet.socket and use SSH / 禁用 telnet.socket 并改用 SSH。"
    _lg_svc_enabled "SVC_RLOGIN" "rlogin/rsh services / rlogin/rsh 服务" "rlogin.socket" \
        "r-commands use weak host-based trust / r 系列命令使用脆弱的基于主机的信任。" \
        "Disable rlogin/rsh/rexec and use SSH / 禁用 rlogin/rsh/rexec 并改用 SSH。"
    _lg_svc_enabled "SVC_FTP" "FTP service / FTP 服务" "vsftpd.service" \
        "Plain FTP sends credentials unencrypted / 普通 FTP 不加密传输凭据。" \
        "Disable or switch to SFTP/FTPS / 禁用或改用 SFTP/FTPS。"
    _lg_svc_enabled "SVC_RPCBIND" "NFS/rpcbind service / NFS/rpcbind 服务" "rpcbind.service" \
        "rpcbind exposes NFS-related attack surface if unused / 不使用时 rpcbind 会暴露 NFS 相关攻击面。" \
        "Disable rpcbind when NFS is not required / 不需要 NFS 时禁用 rpcbind。"
    _lg_svc_enabled "SVC_AVAHID" "mDNS/Bonjour service / mDNS 服务" "avahi-daemon.service" \
        "mDNS advertises host services on the local network / mDNS 会在局域网广播本机服务信息。" \
        "Disable avahi-daemon on servers / 服务器上建议禁用 avahi-daemon。"
    _lg_svc_enabled "SVC_CUPS" "CUPS print service / CUPS 打印服务" "cups.service" \
        "CUPS has a history of remote vulnerabilities / CUPS 历史上存在多个远程漏洞。" \
        "Disable cups on headless servers / 无打印需求的服务器请禁用 cups。"

    # 7. xinetd / inetd super-server configuration.
    _legacy=''
    for _f in /etc/inetd.conf /etc/xinetd.conf; do
        [ -r "$_f" ] || continue
        _n=$(grep -cvE '^[[:space:]]*(#|$)' "$_f" 2>/dev/null)
        [ "$_n" -gt 0 ] 2>/dev/null && _legacy="${_legacy}${_legacy:+; }${_f}(${_n} entries)"
    done
    if [ -n "$(ls -A /etc/xinetd.d 2>/dev/null)" ]; then
        _legacy="${_legacy}${_legacy:+; }/etc/xinetd.d entries present"
    fi
    if [ -n "$_legacy" ]; then
        lg_finding "MEDIUM" "$_title" "SVC_INETD" \
            "Legacy inetd services / 遗留 inetd 服务" "Risk found / 发现风险" \
            "$(_lg_svc_clean "$_legacy")" \
            "Legacy super-servers often expose unencrypted services / 遗留超级服务器常暴露未加密服务。" \
            "Disable unused inetd entries or remove the super-server / 禁用无用条目或卸载超级服务器。"
    else
        lg_finding "PASS" "$_title" "SVC_INETD" \
            "Legacy inetd services / 遗留 inetd 服务" "Compliant / 合规" \
            "No active inetd/xinetd entries / 无生效的 inetd/xinetd 条目" \
            "No legacy on-demand network services detected / 未发现遗留的按需网络服务。" \
            "No action required / 无需操作。"
    fi

    # 8. Count enabled systemd units (baseline inventory).
    if lg_command_exists systemctl; then
        _cnt=$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | wc -l | tr -d '[:space:]')
        case "$_cnt" in
            ''|*[!0-9]*) _cnt='' ;;
        esac
    else
        _cnt=''
    fi
    if [ -n "$_cnt" ]; then
        lg_finding "LOW" "$_title" "SVC_ENABLED_COUNT" \
            "Enabled service count / 已启用服务数量" "Informational / 信息" \
            "${_cnt} service unit(s) enabled at boot / 开机启用 ${_cnt} 个服务单元" \
            "A smaller service footprint reduces the attack surface / 更少的服务意味着更小的攻击面。" \
            "Review enabled units with systemctl list-unit-files / 用 systemctl list-unit-files 复查。"
    else
        lg_finding "SKIP" "$_title" "SVC_ENABLED_COUNT" \
            "Enabled service count / 已启用服务数量" "Skipped / 跳过" \
            "systemctl query unavailable / systemctl 查询不可用" \
            "Cannot enumerate enabled units / 无法枚举已启用单元。" \
            "Check service manager manually / 请手动检查服务管理器。"
    fi

    # 9. Failed systemd units.
    if lg_command_exists systemctl; then
        _bad=$(systemctl --failed --no-legend 2>/dev/null | head -n 5)
        if [ -n "$_bad" ]; then
            lg_finding "MEDIUM" "$_title" "SVC_FAILED_UNITS" \
                "Failed systemd units / 存在失败的 systemd 单元" "Risk found / 发现风险" \
                "$(_lg_svc_clean "$_bad")" \
                "Failed security or logging units may silently reduce protection / 失败的安全或日志单元可能悄悄削弱防护。" \
                "Inspect and repair each failed unit / 逐一排查并修复失败单元。"
        else
            lg_finding "PASS" "$_title" "SVC_FAILED_UNITS" \
                "Failed systemd units / 存在失败的 systemd 单元" "Compliant / 合规" \
                "No failed units reported / 未报告失败单元" \
                "All started units are healthy / 已启动单元均正常。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding "SKIP" "$_title" "SVC_FAILED_UNITS" \
            "Failed systemd units / 存在失败的 systemd 单元" "Skipped / 跳过" \
            "systemctl unavailable / systemctl 不可用" \
            "Cannot query failed units / 无法查询失败单元。" \
            "Check service manager manually / 请手动检查服务管理器。"
    fi

    # 10. World-writable init/cron directories (persistence surface).
    _wdir=''
    for _d in $LG_SVC_STARTUP_DIRS; do
        [ -d "$_d" ] || continue
        _m=$(lg_file_mode "$_d" 2>/dev/null)
        case "$_m" in
            755|750|700|'') ;;
            *) _wdir="${_wdir}${_wdir:+; }${_d}=${_m}" ;;
        esac
    done
    if [ -n "$_wdir" ]; then
        lg_finding "HIGH" "$_title" "SVC_INIT_DIR_MODE" \
            "Permissive startup directory permissions / 启动目录权限过宽" \
            "Risk found / 发现风险" "$_wdir" \
            "Writable startup directories allow trivial persistence / 可写的启动目录可被轻易用于持久化。" \
            "Restrict to 755 root:root / 收紧为 755 且属主 root:root。"
    else
        lg_finding "PASS" "$_title" "SVC_INIT_DIR_MODE" \
            "Permissive startup directory permissions / 启动目录权限过宽" \
            "Compliant / 合规" "Checked init/cron/systemd directories" \
            "Startup directories are not writable by non-root / 启动目录对非 root 不可写。" \
            "No action required / 无需操作。"
    fi
}
