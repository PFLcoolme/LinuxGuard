#!/bin/sh
# modules/ports.sh - Listening port audit module

lg_run_ports() {
    if lg_command_exists ss; then
        _listeners=$(ss -lntu 2>/dev/null | tail -n +2)
        _count=$(printf '%s' "$_listeners" | grep -c . 2>/dev/null || printf '0')

        if [ -n "$_listeners" ]; then
            _public=$(printf '%s' "$_listeners" | grep -E '0\.0\.0\.0:|\[::\]:' | head -n 5 | tr '\n' '; ' | sed 's/; $//')
            if [ -n "$_public" ]; then
                lg_finding \
                    "LOW" \
                    "Open Ports / 开放端口" \
                    "PORT_PUBLIC_LISTENERS" \
                    "Services listening on all interfaces / 服务监听所有接口" \
                    "Informational / 信息" \
                    "${_public}" \
                    "Publicly bound services may be exposed if the firewall is misconfigured / 若防火墙配置不当，公开绑定的服务可能被暴露。" \
                    "Verify each service is required and restricted by the host firewall / 确认每个服务都是必需的，并受主机防火墙限制。"
            fi

            _high_risk=''
            for _port in $LG_HIGH_RISK_TCP_PORTS; do
                _match=$(printf '%s' "$_listeners" | grep -E ":${_port}[[:space:]]" | head -n 1)
                if [ -n "$_match" ]; then
                    if [ -n "$_high_risk" ]; then
                        _high_risk="${_high_risk}; ${_match}"
                    else
                        _high_risk="${_match}"
                    fi
                fi
            done

            if [ -n "$_high_risk" ]; then
                lg_finding \
                    "MEDIUM" \
                    "Open Ports / 开放端口" \
                    "PORT_HIGH_RISK" \
                    "High-risk service ports are listening / 高风险服务端口正在监听" \
                    "Risk found / 发现风险" \
                    "${_high_risk}" \
                    "Well-known administrative or database ports are exposed / 知名管理或数据库端口已暴露。" \
                    "Restrict these services to localhost or trusted networks / 将这些服务限制为 localhost 或可信网络。"
            else
                lg_finding \
                    "PASS" \
                    "Open Ports / 开放端口" \
                    "PORT_HIGH_RISK" \
                    "No high-risk ports detected in common list / 常见高风险端口未检测到" \
                    "Compliant / 合规" \
                    "Checked ports: ${LG_HIGH_RISK_TCP_PORTS} / 已检查端口：${LG_HIGH_RISK_TCP_PORTS}" \
                    "No common high-risk ports found listening / 未检测到常见高风险端口。" \
                    "No action required / 无需操作。"
            fi

            lg_finding \
                "PASS" \
                "Open Ports / 开放端口" \
                "PORT_INVENTORY" \
                "Listening socket inventory collected / 已收集监听套接字清单" \
                "Compliant / 合规" \
                "${_count} TCP/UDP listener(s) / ${_count} 个 TCP/UDP 监听器" \
                "Use ss -lntup to review each listening process / 使用 ss -lntup 检查每个监听进程。" \
                "Confirm each exposed service is required / 确认每个暴露的服务都是必需的。"
        else
            lg_finding \
                "PASS" \
                "Open Ports / 开放端口" \
                "PORT_INVENTORY" \
                "No listening sockets detected / 未检测到监听套接字" \
                "Compliant / 合规" \
                "ss -lntu returned no listeners / ss -lntu 未返回监听器" \
                "No TCP/UDP listening sockets found / 未找到 TCP/UDP 监听套接字。" \
                "No action required / 无需操作。"
        fi
    elif lg_command_exists netstat; then
        _listeners=$(netstat -lntu 2>/dev/null | tail -n +3)
        _count=$(printf '%s' "$_listeners" | grep -c . 2>/dev/null || printf '0')
        lg_finding \
            "PASS" \
            "Open Ports / 开放端口" \
            "PORT_INVENTORY" \
            "Listening socket inventory collected / 已收集监听套接字清单" \
            "Compliant / 合规" \
            "${_count} listener(s) via netstat / 通过 netstat 检测到 ${_count} 个监听器" \
            "Use netstat -lntup to review each listening process / 使用 netstat -lntup 检查每个监听进程。" \
            "Confirm each exposed service is required / 确认每个暴露的服务都是必需的。"
    else
        lg_finding \
            "UNKNOWN" \
            "Open Ports / 开放端口" \
            "PORT_TOOL_MISSING" \
            "Neither ss nor netstat is available / ss 和 netstat 均不可用" \
            "Unknown / 未知" \
            "Tools missing / 工具缺失" \
            "Cannot enumerate listening sockets / 无法枚举监听套接字。" \
            "Install iproute2 or net-tools / 安装 iproute2 或 net-tools。"
    fi
}
