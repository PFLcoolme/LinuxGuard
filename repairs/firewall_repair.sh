#!/bin/sh
# repairs/firewall_repair.sh - Firewall enablement repairs

lg_repair_firewall_status() {
    if lg_command_exists ufw; then
        printf '  Enabling UFW with default deny incoming / 启用 UFW，默认拒绝入站\n'
        if ufw default deny incoming >/dev/null 2>&1 && ufw --force enable >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    elif lg_command_exists firewall-cmd; then
        printf '  Starting and enabling firewalld / 启动并启用 firewalld\n'
        if systemctl start firewalld >/dev/null 2>&1 && systemctl enable firewalld >/dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    elif lg_command_exists nft; then
        printf '  Cannot generate nftables rules automatically / 无法自动生成 nftables 规则。\n'
        printf '  Create /etc/nftables.conf with a default-deny input policy / 请创建 /etc/nftables.conf，配置默认拒绝入站策略。\n'
        return 1
    elif lg_command_exists iptables; then
        printf '  Cannot persist iptables rules automatically / 无法自动持久化 iptables 规则。\n'
        printf '  Configure iptables rules and save them with your distribution persistence tool / 请配置 iptables 规则并使用发行版持久化工具保存。\n'
        return 1
    else
        printf '  No supported firewall tool found / 未找到支持的防火墙工具。\n'
        return 1
    fi
}
