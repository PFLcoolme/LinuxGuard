#!/bin/sh
# modules/permissions.sh - Sensitive file permissions audit module

lg_run_permissions() {
    # /etc/passwd
    if [ -e /etc/passwd ]; then
        _mode=$(lg_file_mode /etc/passwd)
        case "$_mode" in
            644|444)
                lg_finding \
                    "PASS" \
                    "File Permissions / 文件权限" \
                    "PERM_PASSWD" \
                    "/etc/passwd permissions are conventional / /etc/passwd 权限正常" \
                    "Compliant / 合规" \
                    "mode=${_mode}" \
                    "Permissions match typical distribution defaults / 权限符合典型发行版默认值。" \
                    "No action required / 无需操作。"
                ;;
            "")
                lg_finding \
                    "UNKNOWN" \
                    "File Permissions / 文件权限" \
                    "PERM_PASSWD" \
                    "Could not read /etc/passwd permissions / 无法读取 /etc/passwd 权限" \
                    "Unknown / 未知" \
                    "stat failed / stat 失败" \
                    "Run as root or check file permissions / 请以 root 运行或检查文件权限。" \
                    "Check manually / 请手动检查。"
                ;;
            *)
                lg_finding \
                    "MEDIUM" \
                    "File Permissions / 文件权限" \
                    "PERM_PASSWD" \
                    "/etc/passwd permissions are unusual / /etc/passwd 权限异常" \
                    "Risk found / 发现风险" \
                    "mode=${_mode}" \
                    "Unusual permissions on /etc/passwd may leak account information / /etc/passwd 权限异常可能泄露账户信息。" \
                    "Restore mode 644 or match your distribution default / 恢复为 644 或匹配发行版默认值。"
                ;;
        esac
    fi

    # /etc/shadow
    if [ -e /etc/shadow ]; then
        _mode=$(lg_file_mode /etc/shadow)
        case "$_mode" in
            600|640|000)
                lg_finding \
                    "PASS" \
                    "File Permissions / 文件权限" \
                    "PERM_SHADOW" \
                    "/etc/shadow permissions are restrictive / /etc/shadow 权限受限" \
                    "Compliant / 合规" \
                    "mode=${_mode}" \
                    "Shadow file is not world-readable / shadow 文件不可被全局读取。" \
                    "No action required / 无需操作。"
                ;;
            "")
                lg_finding \
                    "UNKNOWN" \
                    "File Permissions / 文件权限" \
                    "PERM_SHADOW" \
                    "Could not read /etc/shadow permissions / 无法读取 /etc/shadow 权限" \
                    "Unknown / 未知" \
                    "stat failed / stat 失败" \
                    "Run as root for complete results / 请以 root 运行以获得完整结果。" \
                    "Check manually / 请手动检查。"
                ;;
            *)
                lg_finding \
                    "HIGH" \
                    "File Permissions / 文件权限" \
                    "PERM_SHADOW" \
                    "/etc/shadow permissions may be too permissive / /etc/shadow 权限可能过于宽松" \
                    "Risk found / 发现风险" \
                    "mode=${_mode}" \
                    "World-readable shadow file exposes password hashes / 全局可读的 shadow 文件会暴露密码哈希。" \
                    "Set mode 600 or 640 immediately / 立即设置权限为 600 或 640。"
                ;;
        esac
    else
        lg_finding \
            "UNKNOWN" \
            "File Permissions / 文件权限" \
            "PERM_SHADOW" \
            "/etc/shadow not found / 未找到 /etc/shadow" \
            "Unknown / 未知" \
            "File missing / 文件缺失" \
            "Cannot audit shadow file permissions / 无法审计 shadow 文件权限。" \
            "Verify system authentication configuration / 请验证系统认证配置。"
    fi

    # /etc/group
    if [ -e /etc/group ]; then
        _mode=$(lg_file_mode /etc/group)
        case "$_mode" in
            644|444)
                lg_finding \
                    "PASS" \
                    "File Permissions / 文件权限" \
                    "PERM_GROUP" \
                    "/etc/group permissions are conventional / /etc/group 权限正常" \
                    "Compliant / 合规" \
                    "mode=${_mode}" \
                    "Permissions match typical distribution defaults / 权限符合典型发行版默认值。" \
                    "No action required / 无需操作。"
                ;;
            "")
                lg_finding \
                    "UNKNOWN" \
                    "File Permissions / 文件权限" \
                    "PERM_GROUP" \
                    "Could not read /etc/group permissions / 无法读取 /etc/group 权限" \
                    "Unknown / 未知" \
                    "stat failed / stat 失败" \
                    "Run as root or check file permissions / 请以 root 运行或检查文件权限。" \
                    "Check manually / 请手动检查。"
                ;;
            *)
                lg_finding \
                    "MEDIUM" \
                    "File Permissions / 文件权限" \
                    "PERM_GROUP" \
                    "/etc/group permissions are unusual / /etc/group 权限异常" \
                    "Risk found / 发现风险" \
                    "mode=${_mode}" \
                    "Unusual permissions on /etc/group may leak group membership / /etc/group 权限异常可能泄露组成员信息。" \
                    "Restore mode 644 or match your distribution default / 恢复为 644 或匹配发行版默认值。"
                ;;
        esac
    fi

    # SSH private key permissions
    if [ -d /etc/ssh ]; then
        _bad_keys=''
        for _key in /etc/ssh/ssh_host_*_key; do
            if [ -f "$_key" ]; then
                _mode=$(lg_file_mode "$_key")
                if [ -n "$_mode" ] && [ "$_mode" -gt 600 ]; then
                    if [ -n "$_bad_keys" ]; then
                        _bad_keys="${_bad_keys}, ${_key}(${_mode})"
                    else
                        _bad_keys="${_key}(${_mode})"
                    fi
                fi
            fi
        done

        if [ -n "$_bad_keys" ]; then
            lg_finding \
                "HIGH" \
                "File Permissions / 文件权限" \
                "PERM_SSH_HOST_KEYS" \
                "SSH host private keys have overly permissive permissions / SSH 主机私钥权限过于宽松" \
                "Risk found / 发现风险" \
                "${_bad_keys}" \
                "Private host keys readable by non-root users can leak key material / 非 root 用户可读的主机密钥可能泄露密钥材料。" \
                "Set permissions to 600 on each host key file / 将每个主机密钥文件权限设置为 600。"
        else
            lg_finding \
                "PASS" \
                "File Permissions / 文件权限" \
                "PERM_SSH_HOST_KEYS" \
                "SSH host private key permissions are restrictive / SSH 主机私钥权限受限" \
                "Compliant / 合规" \
                "Host keys checked under /etc/ssh / 已检查 /etc/ssh 下的主机密钥" \
                "No overly permissive host private keys found / 未发现权限过于宽松的主机私钥。" \
                "No action required / 无需操作。"
        fi
    fi
}
