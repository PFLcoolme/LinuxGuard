#!/bin/sh
# modules/kernel.sh - Kernel security audit module

# Read a sysctl value, returning empty if unavailable
_lg_sysctl_get() {
    _key=$1
    _proc_path="/proc/sys/$(printf '%s' "$_key" | tr '.' '/')"
    if lg_command_exists sysctl; then
        sysctl -n "$_key" 2>/dev/null
    elif [ -r "$_proc_path" ]; then
        cat "$_proc_path" 2>/dev/null
    fi
}

lg_run_kernel() {
    # ASLR
    _aslr=$(_lg_sysctl_get "kernel.randomize_va_space")
    if [ -n "$_aslr" ]; then
        if [ "$_aslr" -eq 2 ] 2>/dev/null; then
            lg_finding \
                "PASS" \
                "Kernel Security / 内核安全" \
                "KERNEL_ASLR" \
                "Kernel ASLR enabled / 内核 ASLR 已启用" \
                "Compliant / 合规" \
                "kernel.randomize_va_space=${_aslr}" \
                "Address Space Layout Randomization is fully enabled / 地址空间布局随机化已完全启用。" \
                "No action required / 无需操作。"
        elif [ "$_aslr" -eq 1 ] 2>/dev/null; then
            lg_finding \
                "MEDIUM" \
                "Kernel Security / 内核安全" \
                "KERNEL_ASLR" \
                "Kernel ASLR partially enabled / 内核 ASLR 部分启用" \
                "Partial / 部分" \
                "kernel.randomize_va_space=${_aslr}" \
                "ASLR is enabled but not in the strongest mode / ASLR 已启用，但未处于最强模式。" \
                "Set kernel.randomize_va_space=2 in sysctl / 在 sysctl 中设置 kernel.randomize_va_space=2。"
        elif [ "$_aslr" -eq 0 ] 2>/dev/null; then
            lg_finding \
                "HIGH" \
                "Kernel Security / 内核安全" \
                "KERNEL_ASLR" \
                "Kernel ASLR disabled / 内核 ASLR 已禁用" \
                "Risk found / 发现风险" \
                "kernel.randomize_va_space=${_aslr}" \
                "ASLR is disabled, making memory corruption exploits easier / ASLR 已禁用，内存损坏漏洞利用更容易。" \
                "Set kernel.randomize_va_space=2 and apply with sysctl -p / 设置 kernel.randomize_va_space=2 并通过 sysctl -p 应用。"
        else
            lg_finding \
                "UNKNOWN" \
                "Kernel Security / 内核安全" \
                "KERNEL_ASLR" \
                "Kernel ASLR value unrecognized / 无法识别内核 ASLR 值" \
                "Unknown / 未知" \
                "kernel.randomize_va_space=${_aslr}" \
                "Unexpected value for ASLR setting / ASLR 设置值异常。" \
                "Investigate and set kernel.randomize_va_space=2 / 调查原因并设置 kernel.randomize_va_space=2。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Kernel Security / 内核安全" \
            "KERNEL_ASLR" \
            "Cannot determine ASLR status / 无法确定 ASLR 状态" \
            "Unknown / 未知" \
            "sysctl or proc entry unavailable / sysctl 或 proc 条目不可用" \
            "Unable to read kernel.randomize_va_space / 无法读取 kernel.randomize_va_space。" \
            "Run as root or ensure sysctl is available / 请以 root 运行或确保 sysctl 可用。"
    fi

    # Kernel pointer restrictions (kptr_restrict)
    _kptr=$(_lg_sysctl_get "kernel.kptr_restrict")
    if [ -n "$_kptr" ]; then
        if [ "$_kptr" -ge 1 ] 2>/dev/null; then
            lg_finding \
                "PASS" \
                "Kernel Security / 内核安全" \
                "KERNEL_KPTR_RESTRICT" \
                "Kernel pointer exposure restricted / 内核指针暴露已受限" \
                "Compliant / 合规" \
                "kernel.kptr_restrict=${_kptr}" \
                "Kernel pointers are not exposed to unprivileged users / 内核指针不会暴露给非特权用户。" \
                "No action required / 无需操作。"
        else
            lg_finding \
                "MEDIUM" \
                "Kernel Security / 内核安全" \
                "KERNEL_KPTR_RESTRICT" \
                "Kernel pointers exposed / 内核指针已暴露" \
                "Risk found / 发现风险" \
                "kernel.kptr_restrict=${_kptr}" \
                "Exposing kernel pointers aids exploit development / 暴露内核指针有助于漏洞利用开发。" \
                "Set kernel.kptr_restrict=1 or 2 / 设置 kernel.kptr_restrict=1 或 2。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Kernel Security / 内核安全" \
            "KERNEL_KPTR_RESTRICT" \
            "Cannot determine kernel pointer restriction / 无法确定内核指针限制" \
            "Unknown / 未知" \
            "sysctl unavailable / sysctl 不可用" \
            "Unable to read kernel.kptr_restrict / 无法读取 kernel.kptr_restrict。" \
            "Run as root or ensure sysctl is available / 请以 root 运行或确保 sysctl 可用。"
    fi

    # Kernel module loading restriction (modules_disabled)
    _mod_disabled=$(_lg_sysctl_get "kernel.modules_disabled")
    if [ -n "$_mod_disabled" ]; then
        if [ "$_mod_disabled" -eq 1 ] 2>/dev/null; then
            lg_finding \
                "PASS" \
                "Kernel Security / 内核安全" \
                "KERNEL_MODULES_DISABLED" \
                "Kernel module loading disabled / 已禁用内核模块加载" \
                "Compliant / 合规" \
                "kernel.modules_disabled=1" \
                "No new kernel modules can be loaded / 无法加载新的内核模块。" \
                "No action required / 无需操作。"
        else
            lg_finding \
                "LOW" \
                "Kernel Security / 内核安全" \
                "KERNEL_MODULES_DISABLED" \
                "Kernel module loading allowed / 允许加载内核模块" \
                "Informational / 信息" \
                "kernel.modules_disabled=${_mod_disabled}" \
                "New kernel modules can still be loaded / 仍可加载新的内核模块。" \
                "Consider setting kernel.modules_disabled=1 after all modules are loaded / 在所有模块加载完毕后考虑设置 kernel.modules_disabled=1。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Kernel Security / 内核安全" \
            "KERNEL_MODULES_DISABLED" \
            "Cannot determine module loading policy / 无法确定模块加载策略" \
            "Unknown / 未知" \
            "sysctl unavailable / sysctl 不可用" \
            "Unable to read kernel.modules_disabled / 无法读取 kernel.modules_disabled。" \
            "Run as root or ensure sysctl is available / 请以 root 运行或确保 sysctl 可用。"
    fi

    # IPv4 forwarding
    _ip_forward=$(_lg_sysctl_get "net.ipv4.ip_forward")
    if [ -n "$_ip_forward" ]; then
        if [ "$_ip_forward" -eq 0 ] 2>/dev/null; then
            lg_finding \
                "PASS" \
                "Kernel Security / 内核安全" \
                "KERNEL_IP_FORWARD" \
                "IPv4 forwarding disabled / 已禁用 IPv4 转发" \
                "Compliant / 合规" \
                "net.ipv4.ip_forward=0" \
                "System is not acting as an IPv4 router by default / 系统默认不作为 IPv4 路由器。" \
                "No action required / 无需操作。"
        else
            lg_finding \
                "MEDIUM" \
                "Kernel Security / 内核安全" \
                "KERNEL_IP_FORWARD" \
                "IPv4 forwarding enabled / 已启用 IPv4 转发" \
                "Risk found / 发现风险" \
                "net.ipv4.ip_forward=${_ip_forward}" \
                "IPv4 forwarding can expose internal networks if misconfigured / IPv4 转发若配置不当可能暴露内部网络。" \
                "Disable unless this system is a router: set net.ipv4.ip_forward=0 / 除非本系统是路由器，否则禁用：设置 net.ipv4.ip_forward=0。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Kernel Security / 内核安全" \
            "KERNEL_IP_FORWARD" \
            "Cannot determine IPv4 forwarding status / 无法确定 IPv4 转发状态" \
            "Unknown / 未知" \
            "sysctl unavailable / sysctl 不可用" \
            "Unable to read net.ipv4.ip_forward / 无法读取 net.ipv4.ip_forward。" \
            "Run as root or ensure sysctl is available / 请以 root 运行或确保 sysctl 可用。"
    fi

    # Reverse path filtering
    _rp_filter=$(_lg_sysctl_get "net.ipv4.conf.all.rp_filter")
    if [ -n "$_rp_filter" ]; then
        if [ "$_rp_filter" -ge 1 ] 2>/dev/null; then
            lg_finding \
                "PASS" \
                "Kernel Security / 内核安全" \
                "KERNEL_RP_FILTER" \
                "Reverse path filtering enabled / 已启用反向路径过滤" \
                "Compliant / 合规" \
                "net.ipv4.conf.all.rp_filter=${_rp_filter}" \
                "Helps prevent IP spoofing / 有助于防止 IP 欺骗。" \
                "No action required / 无需操作。"
        else
            lg_finding \
                "MEDIUM" \
                "Kernel Security / 内核安全" \
                "KERNEL_RP_FILTER" \
                "Reverse path filtering disabled / 已禁用反向路径过滤" \
                "Risk found / 发现风险" \
                "net.ipv4.conf.all.rp_filter=${_rp_filter}" \
                "Disabled rp_filter increases IP spoofing risk / 禁用 rp_filter 会增加 IP 欺骗风险。" \
                "Set net.ipv4.conf.all.rp_filter=1 / 设置 net.ipv4.conf.all.rp_filter=1。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Kernel Security / 内核安全" \
            "KERNEL_RP_FILTER" \
            "Cannot determine reverse path filtering / 无法确定反向路径过滤" \
            "Unknown / 未知" \
            "sysctl unavailable / sysctl 不可用" \
            "Unable to read net.ipv4.conf.all.rp_filter / 无法读取 net.ipv4.conf.all.rp_filter。" \
            "Run as root or ensure sysctl is available / 请以 root 运行或确保 sysctl 可用。"
    fi
}
