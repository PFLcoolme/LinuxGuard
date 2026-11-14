#!/bin/sh
# modules/ssh.sh - SSH security audit module

# Apply OpenSSH built-in defaults when an option is not explicitly configured.
_lg_ssh_default() {
    case "$1" in
        PermitRootLogin) printf 'prohibit-password' ;;
        PasswordAuthentication) printf 'yes' ;;
        PermitEmptyPasswords) printf 'no' ;;
        ListenAddress) printf '0.0.0.0' ;;
        Port) printf '22' ;;
        AuthorizedKeysFile) printf '.ssh/authorized_keys' ;;
        *) printf '' ;;
    esac
}

# Extract an sshd_config option value, respecting Include directives.
# Tries `sshd -T` first, then falls back to manual parsing.
_lg_ssh_get_value() {
    _key=$1

    # Prefer sshd -T for effective configuration (requires root in many setups)
    if lg_command_exists sshd && lg_is_root; then
        _val=$(sshd -T 2>/dev/null | grep -i "^${_key} " | head -n 1 | awk '{print $2}')
        if [ -n "$_val" ]; then
            printf '%s' "$_val"
            return 0
        fi
    fi

    # Fallback: manual parse of main config and includes
    _val=$(_lg_ssh_parse_file "$LG_SSHD_CONFIG" "$_key")
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi

    # If still unset, apply OpenSSH defaults
    _lg_ssh_default "$_key"
}

# Recursively parse an sshd_config file and included files for a key.
_lg_ssh_parse_file() {
    _file=$1
    _key=$2

    if [ ! -r "$_file" ]; then
        return 1
    fi

    # First collect included files
    _includes=$(grep -iE '^[[:space:]]*Include[[:space:]]+' "$_file" 2>/dev/null | sed 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]*//' | tr -d '"')

    # Then search this file for the key (skip Match blocks for V1.0)
    _val=$(grep -iE "^[[:space:]]*${_key}[[:space:]]+" "$_file" 2>/dev/null | grep -vi '^[[:space:]]*#' | tail -n 1 | awk '{print $2}')
    if [ -n "$_val" ]; then
        printf '%s' "$_val"
        return 0
    fi

    # Search includes
    for _inc in $_includes; do
        for _expanded in $_inc; do
            if [ -f "$_expanded" ]; then
                _val=$(_lg_ssh_parse_file "$_expanded" "$_key")
                if [ -n "$_val" ]; then
                    printf '%s' "$_val"
                    return 0
                fi
            elif [ -d "$_expanded" ]; then
                for _f in "$_expanded"/*.conf; do
                    if [ -f "$_f" ]; then
                        _val=$(_lg_ssh_parse_file "$_f" "$_key")
                        if [ -n "$_val" ]; then
                            printf '%s' "$_val"
                            return 0
                        fi
                    fi
                done
            fi
        done
    done

    return 1
}

lg_run_ssh() {
    if [ ! -d /etc/ssh ] && [ ! -r "$LG_SSHD_CONFIG" ]; then
        lg_finding \
            "SKIP" \
            "SSH Configuration / SSH 配置" \
            "SSH_NOT_INSTALLED" \
            "OpenSSH server not detected / 未检测到 OpenSSH 服务端" \
            "Skipped / 跳过" \
            "/etc/ssh not found / 未找到 /etc/ssh" \
            "OpenSSH server does not appear to be installed / OpenSSH 服务端似乎未安装。" \
            "No action required / 无需操作。"
        return
    fi

    # PermitRootLogin
    _root_login=$(_lg_ssh_get_value "PermitRootLogin")
    case "$_root_login" in
        yes|prohibit-password|without-password|forced-commands-only)
            if [ "$_root_login" = "yes" ]; then
                lg_finding \
                    "HIGH" \
                    "SSH Configuration / SSH 配置" \
                    "SSH_ROOT_LOGIN" \
                    "SSH root login allowed / 允许 SSH root 登录" \
                    "Risk found / 发现风险" \
                    "PermitRootLogin ${_root_login}" \
                    "Allowing root to log in directly over SSH increases attack surface / 允许 root 直接通过 SSH 登录会扩大攻击面。" \
                    "Set PermitRootLogin no in sshd_config and use a non-root account with sudo / 在 sshd_config 中设置 PermitRootLogin no，并使用普通用户配合 sudo。"
            else
                lg_finding \
                    "MEDIUM" \
                    "SSH Configuration / SSH 配置" \
                    "SSH_ROOT_LOGIN" \
                    "SSH root login restricted / SSH root 登录受限" \
                    "Partial / 部分" \
                    "PermitRootLogin ${_root_login}" \
                    "Root login is restricted but still permitted with key or command / root 登录已受限，但仍允许通过密钥或命令登录。" \
                    "Consider setting PermitRootLogin no / 建议设置 PermitRootLogin no。"
            fi
            ;;
        no|No)
            lg_finding \
                "PASS" \
                "SSH Configuration / SSH 配置" \
                "SSH_ROOT_LOGIN" \
                "SSH root login disabled / 已禁用 SSH root 登录" \
                "Compliant / 合规" \
                "PermitRootLogin no" \
                "Root cannot log in directly over SSH / root 无法直接通过 SSH 登录。" \
                "No action required / 无需操作。"
            ;;
        *)
            lg_finding \
                "UNKNOWN" \
                "SSH Configuration / SSH 配置" \
                "SSH_ROOT_LOGIN" \
                "SSH root login status unclear / SSH root 登录状态不明" \
                "Unknown / 未知" \
                "Value: ${_root_login:-<not set>} / 值：${_root_login:-<未设置>}" \
                "Could not determine PermitRootLogin setting / 无法确定 PermitRootLogin 设置。" \
                "Verify sshd_config manually and set PermitRootLogin no / 请手动检查 sshd_config 并设置 PermitRootLogin no。"
            ;;
    esac

    # PasswordAuthentication
    _pass_auth=$(_lg_ssh_get_value "PasswordAuthentication")
    case "$_pass_auth" in
        yes|Yes)
            lg_finding \
                "MEDIUM" \
                "SSH Configuration / SSH 配置" \
                "SSH_PASSWORD_AUTH" \
                "SSH password authentication enabled / 已启用 SSH 密码认证" \
                "Risk found / 发现风险" \
                "PasswordAuthentication yes" \
                "Password authentication is vulnerable to brute-force attacks / 密码认证容易遭受暴力破解攻击。" \
                "Set PasswordAuthentication no and use key-based authentication / 设置 PasswordAuthentication no，并使用基于密钥的认证。"
            ;;
        no|No)
            lg_finding \
                "PASS" \
                "SSH Configuration / SSH 配置" \
                "SSH_PASSWORD_AUTH" \
                "SSH password authentication disabled / 已禁用 SSH 密码认证" \
                "Compliant / 合规" \
                "PasswordAuthentication no" \
                "Only key-based authentication is allowed / 仅允许基于密钥的认证。" \
                "No action required / 无需操作。"
            ;;
        *)
            lg_finding \
                "UNKNOWN" \
                "SSH Configuration / SSH 配置" \
                "SSH_PASSWORD_AUTH" \
                "SSH password authentication status unclear / SSH 密码认证状态不明" \
                "Unknown / 未知" \
                "Value: ${_pass_auth:-<not set>} / 值：${_pass_auth:-<未设置>}" \
                "Could not determine PasswordAuthentication setting / 无法确定 PasswordAuthentication 设置。" \
                "Verify sshd_config manually / 请手动检查 sshd_config。"
            ;;
    esac

    # PermitEmptyPasswords
    _empty_pass=$(_lg_ssh_get_value "PermitEmptyPasswords")
    case "$_empty_pass" in
        yes|Yes)
            lg_finding \
                "CRITICAL" \
                "SSH Configuration / SSH 配置" \
                "SSH_EMPTY_PASSWORD" \
                "SSH empty passwords allowed / 允许 SSH 空密码" \
                "Risk found / 发现风险" \
                "PermitEmptyPasswords yes" \
                "Accounts with empty passwords can be used without authentication / 空密码账户无需认证即可使用。" \
                "Set PermitEmptyPasswords no immediately / 立即设置 PermitEmptyPasswords no。"
            ;;
        no|No)
            lg_finding \
                "PASS" \
                "SSH Configuration / SSH 配置" \
                "SSH_EMPTY_PASSWORD" \
                "SSH empty passwords disabled / 已禁用 SSH 空密码" \
                "Compliant / 合规" \
                "PermitEmptyPasswords no" \
                "Empty passwords are not permitted / 不允许空密码。" \
                "No action required / 无需操作。"
            ;;
        *)
            lg_finding \
                "UNKNOWN" \
                "SSH Configuration / SSH 配置" \
                "SSH_EMPTY_PASSWORD" \
                "SSH empty password status unclear / SSH 空密码状态不明" \
                "Unknown / 未知" \
                "Value: ${_empty_pass:-<not set>} / 值：${_empty_pass:-<未设置>}" \
                "Could not determine PermitEmptyPasswords setting / 无法确定 PermitEmptyPasswords 设置。" \
                "Verify sshd_config manually / 请手动检查 sshd_config。"
            ;;
    esac

    # ListenAddress / Port
    _listen=$(_lg_ssh_get_value "ListenAddress")
    _port=$(_lg_ssh_get_value "Port")
    if [ -n "$_listen" ]; then
        if lg_contains " $_listen " " 0.0.0.0 " || [ "$_listen" = "0.0.0.0" ] || [ "$_listen" = "::" ]; then
            lg_finding \
                "LOW" \
                "SSH Configuration / SSH 配置" \
                "SSH_LISTEN_ADDRESS" \
                "SSH listening on all interfaces / SSH 监听所有接口" \
                "Informational / 信息" \
                "ListenAddress ${_listen}${_port:+ Port $_port}" \
                "SSH is reachable on all network interfaces / SSH 可在所有网络接口上访问。" \
                "Restrict ListenAddress to management interfaces if possible / 如可能，将 ListenAddress 限制为管理接口。"
        else
            lg_finding \
                "PASS" \
                "SSH Configuration / SSH 配置" \
                "SSH_LISTEN_ADDRESS" \
                "SSH bound to specific address / SSH 绑定到特定地址" \
                "Compliant / 合规" \
                "ListenAddress ${_listen}${_port:+ Port $_port}" \
                "SSH is bound to a specific address / SSH 已绑定到特定地址。" \
                "No action required / 无需操作。"
        fi
    fi

    # AuthorizedKeysFile location
    _auth_keys=$(_lg_ssh_get_value "AuthorizedKeysFile")
    if [ -n "$_auth_keys" ]; then
        lg_finding \
            "PASS" \
            "SSH Configuration / SSH 配置" \
            "SSH_AUTHORIZED_KEYS" \
            "SSH authorized keys file configured / SSH 授权密钥文件已配置" \
            "Compliant / 合规" \
            "AuthorizedKeysFile ${_auth_keys}" \
            "Authorized keys location is configured / 授权密钥位置已配置。" \
            "Ensure key files have restrictive permissions (600) / 确保密钥文件权限严格（600）。"
    fi
}
