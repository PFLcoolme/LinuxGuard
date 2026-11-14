#!/bin/sh
# repairs/sudo_repair.sh - sudo privilege repairs

lg_repair_sudo_nopasswd() {
    printf '  Will not automatically edit sudoers rules / 不会自动编辑 sudoers 规则。\n'
    printf '  Remove or modify NOPASSWD lines in /etc/sudoers and /etc/sudoers.d/* after review / 请检查后移除或修改 /etc/sudoers 和 /etc/sudoers.d/* 中的 NOPASSWD 行。\n'
    return 1
}

lg_repair_sudo_all_all() {
    printf '  Will not automatically restrict ALL=(ALL) sudo entries / 不会自动限制 ALL=(ALL) sudo 条目。\n'
    printf '  Restrict each sudo rule to specific users, hosts, and commands / 将每条 sudo 规则限制为特定用户、主机和命令。\n'
    return 1
}

lg_repair_sudo_risky() {
    printf '  Will not automatically edit risky sudoers patterns / 不会自动编辑高风险 sudoers 模式。\n'
    printf '  Review /etc/sudoers and /etc/sudoers.d/* for wildcards and !authenticate directives / 请检查 /etc/sudoers 和 /etc/sudoers.d/* 中的通配符和 !authenticate 指令。\n'
    return 1
}

lg_repair_sudoers_permissions() {
    printf '  Setting /etc/sudoers permissions to 440 / 设置 /etc/sudoers 权限为 440\n'
    if chmod 440 /etc/sudoers 2>/dev/null; then
        return 0
    else
        return 1
    fi
}
