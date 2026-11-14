#!/bin/sh
# repairs/permissions_repair.sh - File permission repairs

lg_repair_perm_passwd() {
    printf '  Setting /etc/passwd permissions to 644 / 设置 /etc/passwd 权限为 644\n'
    chmod 644 /etc/passwd 2>/dev/null
}

lg_repair_perm_group() {
    printf '  Setting /etc/group permissions to 644 / 设置 /etc/group 权限为 644\n'
    chmod 644 /etc/group 2>/dev/null
}

lg_repair_perm_shadow() {
    printf '  Setting /etc/shadow permissions to 600 / 设置 /etc/shadow 权限为 600\n'
    chmod 600 /etc/shadow 2>/dev/null
}

lg_repair_perm_ssh_host_keys() {
    printf '  Setting SSH host private keys to 600 / 设置 SSH 主机私钥权限为 600\n'
    _changed=0
    for _key in /etc/ssh/ssh_host_*_key; do
        if [ -f "$_key" ]; then
            _mode=$(lg_file_mode "$_key")
            if [ -n "$_mode" ] && [ "$_mode" -gt 600 ]; then
                chmod 600 "$_key" 2>/dev/null && _changed=$((_changed + 1))
            fi
        fi
    done
    if [ "$_changed" -eq 0 ]; then
        printf '  No host keys needed permission changes / 无需更改主机密钥权限\n'
    fi
}
