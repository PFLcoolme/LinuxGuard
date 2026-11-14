#!/bin/sh
# modules/firewall.sh - Firewall status audit module

lg_run_firewall() {
    _any_active=0
    _details=''

    # UFW
    if lg_command_exists ufw; then
        _ufw_status=$(ufw status 2>/dev/null | head -n 1 | lg_tolower)
        case "$_ufw_status" in
            *active*)
                _any_active=1
                _details="${_details}UFW:active/活跃; "
                ;;
            *inactive*)
                _details="${_details}UFW:inactive/未启用; "
                ;;
            *)
                _details="${_details}UFW:unknown/未知; "
                ;;
        esac
    fi

    # firewalld
    if lg_command_exists firewall-cmd; then
        if firewall-cmd --state >/dev/null 2>&1; then
            _any_active=1
            _details="${_details}firewalld:active/活跃; "
        else
            _details="${_details}firewalld:inactive/未启用; "
        fi
    fi

    # nftables
    if lg_command_exists nft; then
        _nft_count=$(nft list ruleset 2>/dev/null | grep -vE '^[[:space:]]*$' | wc -l)
        if [ "$_nft_count" -gt 0 ]; then
            _any_active=1
            _details="${_details}nftables:rules present/存在规则; "
        else
            _details="${_details}nftables:no rules/无规则; "
        fi
    fi

    # iptables (legacy)
    if lg_command_exists iptables; then
        _ipt_count=$(iptables -L 2>/dev/null | grep -vE '^Chain|^target|^$' | wc -l)
        if [ "$_ipt_count" -gt 0 ]; then
            _any_active=1
            _details="${_details}iptables:rules present/存在规则; "
        else
            _details="${_details}iptables:no rules/无规则; "
        fi
    fi

    # Determine overall status
    if [ -z "$_details" ]; then
        lg_finding \
            "UNKNOWN" \
            "Firewall / 防火墙" \
            "FIREWALL_STATUS" \
            "No firewall tool detected / 未检测到防火墙工具" \
            "Unknown / 未知" \
            "ufw, firewalld, nftables, iptables not found / 未找到 ufw、firewalld、nftables、iptables" \
            "Cannot determine firewall status / 无法确定防火墙状态。" \
            "Install a host firewall / 安装主机防火墙（ufw、firewalld、nftables 或 iptables）。"
        return
    fi

    # Trim trailing semicolon/space
    _details=$(printf '%s' "$_details" | sed 's/; *$//')

    if [ "$_any_active" -eq 1 ]; then
        lg_finding \
            "PASS" \
            "Firewall / 防火墙" \
            "FIREWALL_STATUS" \
            "Host firewall appears active / 主机防火墙已启用" \
            "Compliant / 合规" \
            "${_details}" \
            "At least one firewall tool has active rules / 至少一个防火墙工具有活动规则。" \
            "Verify rules restrict inbound traffic to required services / 验证规则是否将入站流量限制为仅必要服务。"
    else
        lg_finding \
            "HIGH" \
            "Firewall / 防火墙" \
            "FIREWALL_STATUS" \
            "No active host firewall detected / 未检测到活动的主机防火墙" \
            "Risk found / 发现风险" \
            "${_details}" \
            "Without a firewall, all listening services may be exposed / 没有防火墙时，所有监听服务都可能暴露。" \
            "Enable ufw/firewalld/nftables/iptables and configure default-deny inbound policy / 启用防火墙并配置默认拒绝入站策略。"
    fi
}
