#!/bin/sh
# repairs/ssh_repair.sh - SSH configuration repairs

# Set or replace an option in the main sshd_config file
_lg_ssh_set_option() {
    _key=$1
    _value=$2
    _file=$LG_SSHD_CONFIG

    if [ ! -f "$_file" ]; then
        printf 'SSHD config not found / 未找到 SSHD 配置: %s\n' "$_file"
        return 1
    fi

    if grep -qE "^[[:space:]]*${_key}[[:space:]]+" "$_file"; then
        # Replace existing explicit setting in main config
        sed "s/^[[:space:]]*${_key}[[:space:]]+.*/${_key} ${_value}/" "$_file" > "${_file}.lgtmp" && mv "${_file}.lgtmp" "$_file"
    else
        # Append to main config
        printf '\n# Added by LinuxGuard\n%s %s\n' "$_key" "$_value" >> "$_file"
    fi

    # Validate
    if lg_command_exists sshd; then
        if ! sshd -t 2>/dev/null; then
            return 1
        fi
    fi
    return 0
}

lg_repair_ssh_root_login() {
    printf '  Setting PermitRootLogin no / 设置 PermitRootLogin 为 no\n'
    _lg_ssh_set_option "PermitRootLogin" "no"
}

lg_repair_ssh_password_auth() {
    printf '  Setting PasswordAuthentication no / 设置 PasswordAuthentication 为 no\n'
    _lg_ssh_set_option "PasswordAuthentication" "no"
}

lg_repair_ssh_empty_password() {
    printf '  Setting PermitEmptyPasswords no / 设置 PermitEmptyPasswords 为 no\n'
    _lg_ssh_set_option "PermitEmptyPasswords" "no"
}

lg_repair_ssh_listen_address() {
    printf '  Cannot safely determine management interface automatically / 无法自动安全确定管理接口。\n'
    printf '  Manually set ListenAddress in %s to a specific interface IP / 请手动在 %s 中设置 ListenAddress 为特定接口 IP。\n' "$LG_SSHD_CONFIG" "$LG_SSHD_CONFIG"
    return 1
}
