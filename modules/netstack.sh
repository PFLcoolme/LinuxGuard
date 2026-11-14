#!/bin/sh
# modules/netstack.sh - Kernel network-stack hardening module
# Read-only: reads /proc/sys values only, never writes sysctl. Missing -> SKIP.

_lg_net_get() {
    _key=$1
    _path="/proc/sys/$(printf '%s' "$_key" | tr '.' '/')"
    if lg_command_exists sysctl; then sysctl -n "$_key" 2>/dev/null
    elif [ -r "$_path" ]; then cat "$_path" 2>/dev/null; fi
}

# _lg_net_ctl RULE NAME KEY MODE SEV IMPACT FIX
# MODE off = 0 compliant, on = >=1 compliant
_lg_net_ctl() {
    _title='Network Stack / 网络协议栈'
    _val=$(_lg_net_get "$3" | head -n 1 | tr -d '[:space:]')
    if [ -z "$_val" ]; then
        lg_finding "SKIP" "$_title" "$1" "$2" "Skipped / 跳过" \
            "sysctl $3 unavailable / 该 sysctl 键不可用" \
            "Kernel parameter not exposed on this host / 该主机未暴露此内核参数。" \
            "Ensure /proc/sys is mounted / 请确认 /proc/sys 已挂载。"
        return
    fi
    case "$_val" in
        *[!0-9]*)
            lg_finding "UNKNOWN" "$_title" "$1" "$2" "Unknown / 未知" \
                "$3=${_val}" "Non-numeric sysctl value / sysctl 值非数字。" \
                "Inspect the parameter manually / 请手动检查该参数。"
            return ;;
    esac
    _ok=0
    case "$4" in
        off) [ "$_val" -eq 0 ] 2>/dev/null && _ok=1 ;;
        on)  [ "$_val" -ge 1 ] 2>/dev/null && _ok=1 ;;
    esac
    if [ "$_ok" -eq 1 ]; then
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "$3=${_val}" "$6" "No action required / 无需操作。"
    else
        lg_finding "$5" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "$3=${_val}" "$6" "$7"
    fi
}

lg_run_netstack() {
    _lg_net_ctl "NET_SYNCOOKIES" "TCP SYN flood protection / TCP SYN 洪水防护" \
        "net.ipv4.tcp_syncookies" on MEDIUM \
        "SYN cookies help withstand SYN flood DoS / SYN Cookie 有助于抵御 SYN 洪水攻击。" \
        "Set net.ipv4.tcp_syncookies=1 / 设置 net.ipv4.tcp_syncookies=1。"
    _lg_net_ctl "NET_LOG_MARTIANS" "Log suspicious packets / 记录异常报文" \
        "net.ipv4.conf.all.log_martians" on LOW \
        "Logging martian packets aids spoofing detection / 记录异常报文有助于发现地址欺骗。" \
        "Set net.ipv4.conf.all.log_martians=1 / 设置 net.ipv4.conf.all.log_martians=1。"
    _lg_net_ctl "NET_ACCEPT_REDIRECTS" "Reject ICMP redirects / 拒绝 ICMP 重定向" \
        "net.ipv4.conf.all.accept_redirects" off MEDIUM \
        "ICMP redirects can let attackers alter routing / ICMP 重定向可能被用于篡改路由表。" \
        "Set net.ipv4.conf.all.accept_redirects=0 / 设置 net.ipv4.conf.all.accept_redirects=0。"
    _lg_net_ctl "NET_SEND_REDIRECTS" "Do not send ICMP redirects / 不发送 ICMP 重定向" \
        "net.ipv4.conf.all.send_redirects" off LOW \
        "A non-router host should not emit redirects / 非路由器主机不应发送重定向。" \
        "Set net.ipv4.conf.all.send_redirects=0 / 设置 net.ipv4.conf.all.send_redirects=0。"
    _lg_net_ctl "NET_SECURE_REDIRECTS" "Restrict secure redirects / 限制安全重定向" \
        "net.ipv4.conf.all.secure_redirects" off LOW \
        "Secure redirects remain redirects; disable on hosts / 安全重定向仍是重定向，主机上应禁用。" \
        "Set net.ipv4.conf.all.secure_redirects=0 / 设置 net.ipv4.conf.all.secure_redirects=0。"
    _lg_net_ctl "NET_SOURCE_ROUTE" "Reject source-routed packets / 拒绝源路由报文" \
        "net.ipv4.conf.all.accept_source_route" off MEDIUM \
        "Source routing can bypass network controls / 源路由可绕过网络访问控制。" \
        "Set net.ipv4.conf.all.accept_source_route=0 / 设置 net.ipv4.conf.all.accept_source_route=0。"
    _lg_net_ctl "NET_IGNORE_BROADCASTS" "Ignore broadcast ICMP / 忽略广播 ICMP" \
        "net.ipv4.icmp_echo_ignore_broadcasts" on LOW \
        "Ignoring broadcast pings mitigates Smurf amplification / 忽略广播 ping 可缓解 Smurf 放大攻击。" \
        "Set net.ipv4.icmp_echo_ignore_broadcasts=1 / 设置 net.ipv4.icmp_echo_ignore_broadcasts=1。"
    _lg_net_ctl "NET_BOGUS_ERROR" "Ignore bogus ICMP errors / 忽略伪造 ICMP 错误" \
        "net.ipv4.icmp_ignore_bogus_error_responses" on LOW \
        "Suppresses noisy forged ICMP error responses / 抑制伪造 ICMP 错误响应造成的干扰。" \
        "Set net.ipv4.icmp_ignore_bogus_error_responses=1 / 设置 net.ipv4.icmp_ignore_bogus_error_responses=1。"
    _lg_net_ctl "NET_RP_FILTER_DEFAULT" "Default reverse path filtering / 默认反向路径过滤" \
        "net.ipv4.conf.default.rp_filter" on MEDIUM \
        "Default rp_filter protects newly created interfaces / 默认 rp_filter 保护新建接口免受 IP 欺骗。" \
        "Set net.ipv4.conf.default.rp_filter=1 / 设置 net.ipv4.conf.default.rp_filter=1。"
    _lg_net_ctl "NET_IPV6_REDIRECTS" "Reject IPv6 redirects / 拒绝 IPv6 重定向" \
        "net.ipv6.conf.all.accept_redirects" off MEDIUM \
        "IPv6 redirects pose the same routing risk as IPv4 / IPv6 重定向与 IPv4 具有相同的路由篡改风险。" \
        "Set net.ipv6.conf.all.accept_redirects=0 / 设置 net.ipv6.conf.all.accept_redirects=0。"
}
