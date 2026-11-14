#!/bin/sh
# modules/auth.sh - Authentication & password-policy module
# Read-only: /etc/login.defs, /etc/pam.d, /etc/security and /etc/shadow metadata.

_lg_auth_clean() {
    printf '%s' "$1" | tr '\n|' ';/' | sed 's/[[:space:]][[:space:]]*/ /g' | cut -c1-260
}

# _lg_auth_conf RULE NAME FILE PATTERN EXPECTED_MODE SEV IMPACT FIX
_lg_auth_conf() {
    _title='Authentication / 认证策略'
    _file=$3
    if [ ! -r "$_file" ]; then
        lg_finding "UNKNOWN" "$_title" "$1" "$2" "Unknown / 未知" \
            "${_file} unreadable / ${_file} 不可读" \
            "Cannot verify this policy / 无法验证此策略。" \
            "Ensure the config file is present / 请确认该配置文件存在。"
        return
    fi
    _line=$(grep -E "$4" "$_file" 2>/dev/null | grep -Ev '^[[:space:]]*#' | head -n 1)
    if [ -z "$_line" ]; then
        lg_finding "$6" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "No active setting in ${_file} / ${_file} 中无生效配置" \
            "$7" "$8"
        return
    fi
    _val=$(printf '%s' "$_line" | awk '{print $2}' | tr -d '[:space:]')
    _ok=0
    case "$5" in
        ge90)  [ "$_val" -ge 90 ]  2>/dev/null && _ok=1 ;;
        ge8)   [ "$_val" -ge 8 ]   2>/dev/null && _ok=1 ;;
        ge1)   [ "$_val" -ge 1 ]   2>/dev/null && _ok=1 ;;
        le0)   [ "$_val" -le 0 ]   2>/dev/null && _ok=1 ;;
        ge5)   [ "$_val" -ge 5 ]   2>/dev/null && _ok=1 ;;
    esac
    if [ "$_ok" -eq 1 ]; then
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "$(_lg_auth_clean "$_line")" "$7" "No action required / 无需操作。"
    else
        lg_finding "$6" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "$(_lg_auth_clean "$_line")" "$7" "$8"
    fi
}

# _lg_auth_pam RULE NAME KEYWORD SEV IMPACT FIX (PRESENT = compliant)
_lg_auth_pam() {
    _title='Authentication / 认证策略'
    if [ ! -d /etc/pam.d ]; then
        lg_finding "SKIP" "$_title" "$1" "$2" "Skipped / 跳过" \
            "/etc/pam.d missing / 缺少 /etc/pam.d" \
            "PAM configuration is unavailable / 无法获取 PAM 配置。" \
            "Check PAM installation / 请检查 PAM 安装。"
        return
    fi
    _hit=$(grep -rEl "$3" /etc/pam.d 2>/dev/null | head -n 3)
    if [ -n "$_hit" ]; then
        lg_finding "PASS" "$_title" "$1" "$2" "Compliant / 合规" \
            "$(_lg_auth_clean "$_hit")" "$5" "No action required / 无需操作。"
    else
        lg_finding "$4" "$_title" "$1" "$2" "Risk found / 发现风险" \
            "No PAM rule match: $(_lg_auth_clean "$3") / 未找到匹配的 PAM 规则" \
            "$5" "$6"
    fi
}

lg_run_auth() {
    : "${LG_AUTH_PASS_MAX_DAYS:=90}"
    : "${LG_AUTH_PASS_MIN_LEN:=8}"
    _title='Authentication / 认证策略'

    _lg_auth_conf "AUTH_PASS_MAX_DAYS" "Password maximum age / 密码最长有效期" \
        /etc/login.defs '^[[:space:]]*PASS_MAX_DAYS' ge90 MEDIUM \
        "Long-lived passwords increase exposure after credential leakage / 密码长期不更换会增加凭据泄露后的风险。" \
        "Set PASS_MAX_DAYS to 90 or less / 将 PASS_MAX_DAYS 设为 90 或更小。"

    _lg_auth_conf "AUTH_PASS_MIN_DAYS" "Password minimum age / 密码最短使用期" \
        /etc/login.defs '^[[:space:]]*PASS_MIN_DAYS' ge1 LOW \
        "A minimum age prevents immediate password cycling / 最短使用期可防止用户立刻改回旧密码。" \
        "Set PASS_MIN_DAYS to 1 or more / 将 PASS_MIN_DAYS 设为 1 或更大。"

    _lg_auth_conf "AUTH_PASS_WARN_AGE" "Password expiry warning / 密码过期提醒" \
        /etc/login.defs '^[[:space:]]*PASS_WARN_AGE' ge1 LOW \
        "Advance warning avoids sudden lockouts / 提前提醒可避免用户突然被锁定。" \
        "Set PASS_WARN_AGE to 7 or more / 将 PASS_WARN_AGE 设为 7 或更大。"

    # 4. Password hashing algorithm in login.defs.
    if [ -r /etc/login.defs ]; then
        _enc=$(grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs 2>/dev/null | awk '{print $2}')
        case "$(printf '%s' "$_enc" | lg_toupper)" in
            SHA512|YESCRYPT|BCRYPT)
                lg_finding "PASS" "$_title" "AUTH_HASH_ALGO" \
                    "Strong password hash / 使用强密码哈希" "Compliant / 合规" \
                    "ENCRYPT_METHOD=${_enc:-unset}" \
                    "A modern one-way hash slows offline cracking / 现代单向哈希可减缓离线破解。" \
                    "No action required / 无需操作。" ;;
            MD5|DES|'')
                lg_finding "HIGH" "$_title" "AUTH_HASH_ALGO" \
                    "Weak or unset password hash / 密码哈希较弱或未设置" "Risk found / 发现风险" \
                    "ENCRYPT_METHOD=${_enc:-unset}" \
                    "Legacy hashes are fast to brute force offline / 旧式哈希极易被离线暴力破解。" \
                    "Set ENCRYPT_METHOD to SHA512 or YESCRYPT / 将 ENCRYPT_METHOD 设为 SHA512 或 YESCRYPT。" ;;
            *)
                lg_finding "UNKNOWN" "$_title" "AUTH_HASH_ALGO" \
                    "Password hash algorithm / 密码哈希算法" "Unknown / 未知" \
                    "ENCRYPT_METHOD=${_enc}" \
                    "Unrecognised hash method / 无法识别该哈希方式。" \
                    "Verify the setting manually / 请手动核对该配置。" ;;
        esac
    else
        lg_finding "UNKNOWN" "$_title" "AUTH_HASH_ALGO" \
            "Password hash algorithm / 密码哈希算法" "Unknown / 未知" \
            "/etc/login.defs unreadable / 该文件不可读" \
            "Cannot verify the hash method / 无法验证哈希方式。" \
            "Ensure /etc/login.defs is present / 请确认 /etc/login.defs 存在。"
    fi

    # 5. PAM password quality / complexity enforcement.
    _lg_auth_pam "AUTH_PAM_PWQUALITY" "PAM password quality policy / PAM 密码复杂度策略" \
        'pam_pwquality|pam_cracklib' MEDIUM \
        "A password quality module blocks weak passwords / 密码质量模块可阻止弱口令。" \
        "Add pam_pwquality.so to /etc/pam.d/common-password / 在 PAM 密码栈中加入 pam_pwquality.so。"

    # 6. PAM account lockout after failed attempts.
    _lg_auth_pam "AUTH_PAM_LOCKOUT" "PAM failed-login lockout / PAM 登录失败锁定" \
        'pam_faillock|pam_tally' MEDIUM \
        "Lockout slows online password guessing / 失败锁定可减缓在线口令猜测。" \
        "Configure pam_faillock.so with deny and unlock_time / 配置 pam_faillock.so 的 deny 与 unlock_time。"

    # 7. PAM password history (reuse prevention).
    _lg_auth_pam "AUTH_PAM_HISTORY" "PAM password history / PAM 密码历史" \
        'remember=|pam_pwhistory' LOW \
        "Password history prevents immediate reuse / 密码历史可防止用户立刻重用旧口令。" \
        "Add use_authtok remember=5 to pam_pwquality / 为 pam_pwquality 增加 remember=5。"

    # 8. umask hardening in /etc/profile.
    if [ -r /etc/profile ]; then
        _um=$(grep -E '^[[:space:]]*umask[[:space:]]' /etc/profile 2>/dev/null | head -n 1)
        case "$_um" in
            *027*|*077*)
                lg_finding "PASS" "$_title" "AUTH_UMASK" \
                    "Restrictive default umask / 严格的默认 umask" "Compliant / 合规" \
                    "$(_lg_auth_clean "$_um")" \
                    "A strict umask prevents world-readable new files / 严格 umask 可避免新建文件全局可读。" \
                    "No action required / 无需操作。" ;;
            *)
                lg_finding "LOW" "$_title" "AUTH_UMASK" \
                    "Restrictive default umask / 严格的默认 umask" "Risk found / 发现风险" \
                    "${_um:-no umask in /etc/profile}" \
                    "A permissive umask may expose newly created files / 宽松 umask 可能暴露新建文件。" \
                    "Set umask 027 in /etc/profile / 在 /etc/profile 中设置 umask 027。" ;;
        esac
    else
        lg_finding "UNKNOWN" "$_title" "AUTH_UMASK" \
            "Restrictive default umask / 严格的默认 umask" "Unknown / 未知" \
            "/etc/profile unreadable / 该文件不可读" \
            "Cannot verify default umask / 无法验证默认 umask。" \
            "Ensure /etc/profile is readable / 请确认 /etc/profile 可读。"
    fi

    # 9. Accounts with empty passwords (shadow field 2 empty). Metadata only.
    if [ -r /etc/shadow ]; then
        _empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | head -n 5 | tr '\n' ' ')
        if [ -n "$(printf '%s' "$_empty" | tr -d '[:space:]')" ]; then
            lg_finding "CRITICAL" "$_title" "AUTH_SHADOW_EMPTY" \
                "Accounts with empty passwords / 存在空口令账户" "Risk found / 发现风险" \
                "$(_lg_auth_clean "$_empty")" \
                "These accounts allow password-less authentication / 这些账户可无需口令直接认证。" \
                "Lock or assign a password to each account / 逐一锁定或设置口令（passwd -l）。"
        else
            lg_finding "PASS" "$_title" "AUTH_SHADOW_EMPTY" \
                "Accounts with empty passwords / 存在空口令账户" "Compliant / 合规" \
                "No empty password field found / 未发现空口令字段" \
                "No account has an empty password field / 没有账户使用空口令。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding "SKIP" "$_title" "AUTH_SHADOW_EMPTY" \
            "Accounts with empty passwords / 存在空口令账户" "Skipped / 跳过" \
            "/etc/shadow unreadable / 该文件不可读（通常需要 root）" \
            "Non-root cannot inspect password hashes / 非 root 无法检查口令哈希。" \
            "Re-run as root / 请以 root 重新运行。"
    fi

    # 10. Password aging policy for existing accounts (chage -l).
    if lg_command_exists chage && lg_is_root; then
        _noexp=0 _sample=''
        for _u in $(awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd 2>/dev/null | head -n 20); do
            _max=$(chage -l "$_u" 2>/dev/null | grep -i 'Maximum number of days' | awk -F: '{print $2}' | tr -d '[:space:]')
            case "$_max" in
                ''|*[!0-9]*) continue ;;
            esac
            if [ "$_max" -gt 99999 ] || [ "$_max" -eq 0 ] 2>/dev/null; then
                _noexp=$((_noexp + 1))
                [ "$_noexp" -le 3 ] && _sample="${_sample}${_sample:+; }${_u}(max=${_max})"
            fi
        done
        if [ "$_noexp" -gt 0 ]; then
            lg_finding "MEDIUM" "$_title" "AUTH_AGING_EXISTING" \
                "Existing accounts without password expiry / 现有账户未设置口令过期" \
                "Risk found / 发现风险" "${_noexp} found: ${_sample}" \
                "login.defs only affects newly created accounts / login.defs 仅影响新建账户，存量账户可能永不过期。" \
                "Apply chage -M 90 to the listed accounts / 对相关账户执行 chage -M 90。"
        else
            lg_finding "PASS" "$_title" "AUTH_AGING_EXISTING" \
                "Existing accounts without password expiry / 现有账户未设置口令过期" \
                "Compliant / 合规" "Sampled human accounts have an expiry / 抽样的普通账户均设置了过期时间" \
                "No never-expiring human account sampled / 抽样未发现永不过期的普通账户。" \
                "No action required / 无需操作。"
        fi
    else
        lg_finding "SKIP" "$_title" "AUTH_AGING_EXISTING" \
            "Existing accounts without password expiry / 现有账户未设置口令过期" \
            "Skipped / 跳过" "Requires chage and root / 需要 chage 与 root 权限" \
            "Cannot inspect per-account aging / 无法检查逐账户的过期策略。" \
            "Re-run as root with passwd/shadow tools / 请以 root 重新运行。"
    fi
}
