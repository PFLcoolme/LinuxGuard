#!/bin/sh
# modules/users.sh - User and account security audit module

# Check whether a shell is considered invalid/non-login
_lg_is_invalid_shell() {
    _shell=$1
    for _invalid in $LG_INVALID_SHELLS; do
        if [ "$_shell" = "$_invalid" ]; then
            return 0
        fi
    done
    return 1
}

# Check whether a shell is listed in /etc/shells
_lg_is_valid_login_shell() {
    _shell=$1
    if [ ! -r /etc/shells ]; then
        return 1
    fi
    grep -qxF "$_shell" /etc/shells
}

lg_run_users() {
    if [ ! -r /etc/passwd ]; then
        lg_finding \
            "UNKNOWN" \
            "User Accounts / 用户账户" \
            "PASSWD_READABLE" \
            "/etc/passwd not readable / 无法读取 /etc/passwd" \
            "Unknown / 未知" \
            "Permission denied / 权限拒绝" \
            "Cannot read user account list / 无法读取用户账户列表。" \
            "Run as root or check file permissions / 请以 root 运行或检查文件权限。"
        return
    fi

    # UID 0 accounts
    _uid0_count=0
    _uid0_extra=''
    while IFS=':' read -r _user _x _uid _gid _gecos _home _shell; do
        if [ "$_uid" -eq 0 ] 2>/dev/null; then
            case " $LG_UID0_WHITELIST " in
                *" $_user "*)
                    : ;;
                *)
                    _uid0_count=$((_uid0_count + 1))
                    if [ -n "$_uid0_extra" ]; then
                        _uid0_extra="${_uid0_extra}, ${_user}"
                    else
                        _uid0_extra="${_user}"
                    fi
                    ;;
            esac
        fi
    done < /etc/passwd

    if [ "$_uid0_count" -gt 0 ]; then
        lg_finding \
            "HIGH" \
            "User Accounts / 用户账户" \
            "UID0_EXTRA_USERS" \
            "Multiple accounts with UID 0 / 存在多个 UID 0 账户" \
            "Risk found / 发现风险" \
            "${_uid0_extra}" \
            "Accounts other than root with UID 0 have full administrative privileges / 除 root 外的 UID 0 账户拥有完全管理权限。" \
            "Remove UID 0 from these accounts or disable them / 从这些账户移除 UID 0 或禁用它们。"
    else
        lg_finding \
            "PASS" \
            "User Accounts / 用户账户" \
            "UID0_EXTRA_USERS" \
            "Only root has UID 0 / 仅 root 拥有 UID 0" \
            "Compliant / 合规" \
            "root" \
            "No additional UID 0 accounts detected / 未检测到额外的 UID 0 账户。" \
            "No action required / 无需操作。"
    fi

    # Empty password accounts
    if [ -r /etc/shadow ]; then
        _empty_users=''
        while IFS=':' read -r _user _hash _rest; do
            if [ -z "$_hash" ] || [ "$_hash" = "" ]; then
                if [ -n "$_empty_users" ]; then
                    _empty_users="${_empty_users}, ${_user}"
                else
                    _empty_users="${_user}"
                fi
            fi
        done < /etc/shadow

        if [ -n "$_empty_users" ]; then
            lg_finding \
                "CRITICAL" \
                "User Accounts / 用户账户" \
                "EMPTY_PASSWORDS" \
                "Accounts with empty password hashes / 存在空密码哈希的账户" \
                "Risk found / 发现风险" \
                "${_empty_users}" \
                "Empty password hash allows password-less local login / 空密码哈希允许无密码本地登录。" \
                "Set strong passwords or lock these accounts / 设置强密码或锁定这些账户。"
        else
            lg_finding \
                "PASS" \
                "User Accounts / 用户账户" \
                "EMPTY_PASSWORDS" \
                "No empty password hashes found / 未发现空密码哈希" \
                "Compliant / 合规" \
                "All shadow entries have a password hash / 所有 shadow 条目均有密码哈希" \
                "No password-less accounts detected / 未检测到无密码账户。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "User Accounts / 用户账户" \
            "EMPTY_PASSWORDS" \
            "Cannot read /etc/shadow / 无法读取 /etc/shadow" \
            "Unknown / 未知" \
            "Permission denied / 权限拒绝" \
            "Empty password check skipped / 空密码检查已跳过。" \
            "Run as root for complete results / 请以 root 运行以获得完整结果。"
    fi

    # Unusual login shells
    _bad_shells=''
    while IFS=':' read -r _user _x _uid _gid _gecos _home _shell; do
        if [ -z "$_shell" ]; then
            continue
        fi
        if ! _lg_is_invalid_shell "$_shell" && ! _lg_is_valid_login_shell "$_shell"; then
            if [ -n "$_bad_shells" ]; then
                _bad_shells="${_bad_shells}, ${_user}:${_shell}"
            else
                _bad_shells="${_user}:${_shell}"
            fi
        fi
    done < /etc/passwd

    if [ -n "$_bad_shells" ]; then
        lg_finding \
            "MEDIUM" \
            "User Accounts / 用户账户" \
            "UNUSUAL_SHELL" \
            "Users with unusual login shells / 存在异常登录 Shell 的用户" \
            "Risk found / 发现风险" \
            "${_bad_shells}" \
            "Shell is neither in /etc/shells nor a standard non-login shell / 该 Shell 既不在 /etc/shells 中，也不是标准非登录 Shell。" \
            "Review and correct these shell assignments / 检查并修正这些 Shell 分配。"
    else
        lg_finding \
            "PASS" \
            "User Accounts / 用户账户" \
            "UNUSUAL_SHELL" \
            "All user shells are standard / 所有用户 Shell 均正常" \
            "Compliant / 合规" \
            "Shells validated against /etc/shells / 已根据 /etc/shells 验证 Shell" \
            "No unusual login shells detected / 未检测到异常登录 Shell。" \
            "No action required / 无需操作。"
    fi

    # Stale passwords
    if lg_command_exists chage && lg_is_root; then
        _stale_users=''
        _now=$(awk 'BEGIN{srand(); print srand()}')
        while IFS=':' read -r _user _hash _lastchg _min _max _warn _inactive _expire _flags; do
            if [ -z "$_lastchg" ] || [ "$_lastchg" = "" ] || [ "$_lastchg" -le 0 ] 2>/dev/null; then
                continue
            fi
            _lastchg_epoch=$((_lastchg * 86400))
            _diff=$(((_now - _lastchg_epoch) / 86400))
            if [ "$_diff" -gt "$LG_PASSWORD_AGE_DAYS" ]; then
                if [ -n "$_stale_users" ]; then
                    _stale_users="${_stale_users}, ${_user}(${_diff}d)"
                else
                    _stale_users="${_user}(${_diff}d)"
                fi
            fi
        done < /etc/shadow

        if [ -n "$_stale_users" ]; then
            lg_finding \
                "LOW" \
                "User Accounts / 用户账户" \
                "STALE_PASSWORDS" \
                "Passwords older than ${LG_PASSWORD_AGE_DAYS} days / 密码超过 ${LG_PASSWORD_AGE_DAYS} 天未更新" \
                "Informational / 信息" \
                "${_stale_users}" \
                "Long-unchanged passwords increase exposure if credentials leak / 长期未更改的密码在凭据泄露时风险更高。" \
                "Enforce password rotation and review stale accounts / 强制密码轮换并检查过期账户。"
        else
            lg_finding \
                "PASS" \
                "User Accounts / 用户账户" \
                "STALE_PASSWORDS" \
                "Passwords are within age threshold / 密码在年龄阈值内" \
                "Compliant / 合规" \
                "Threshold: ${LG_PASSWORD_AGE_DAYS} days / 阈值：${LG_PASSWORD_AGE_DAYS} 天" \
                "No stale passwords detected / 未检测到过期密码。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding \
            "SKIP" \
            "User Accounts / 用户账户" \
            "STALE_PASSWORDS" \
            "Password age check skipped / 密码年龄检查已跳过" \
            "Skipped / 跳过" \
            "chage unavailable or not root / chage 不可用或未以 root 运行" \
            "Cannot calculate password age without chage/root / 没有 chage/root 无法计算密码年龄。" \
            "Run as root or install chage for this check / 请以 root 运行或安装 chage 以进行此项检查。"
    fi
}
