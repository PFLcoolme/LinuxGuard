#!/bin/sh
# modules/vulnscan.sh - Host vulnerability posture (indicator) module
#
# Read-only by design. It never refreshes package indexes, installs updates,
# downloads advisories or modifies repositories. It only inspects local state.

# Count pending security updates from a text stream (best-effort).
_lg_vs_count_lines() {
    printf '%s\n' "$1" | grep -c . 2>/dev/null || printf '0'
}

lg_run_vulnscan() {
    : "${LG_VULNSCAN_UPGRADE_THRESHOLD:=10}"
    : "${LG_VULNSCAN_REBOOT_MARKERS:=/var/run/reboot-required /run/reboot-required}"

    # 1. Pending security updates, read-only and per package manager.
    case "$LG_PACKAGE_MANAGER" in
        apt)
            if lg_command_exists apt-get; then
                _list=$(apt-get -s upgrade 2>/dev/null | grep '^Inst ' | head -n 50)
                _n=$(_lg_vs_count_lines "$_list")
                _sample=$(printf '%s\n' "$_list" | head -n 5 | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
                _method='apt-get -s upgrade (simulation only / 仅模拟)'
                _available=1
            else
                _available=0
            fi
            ;;
        dnf|yum)
            if lg_command_exists "$LG_PACKAGE_MANAGER"; then
                _list=$("$LG_PACKAGE_MANAGER" -q check-update 2>/dev/null | grep -Ei '^[[:alnum:]_.+-]+[[:space:]]' | head -n 50)
                _n=$(_lg_vs_count_lines "$_list")
                _sample=$(printf '%s\n' "$_list" | head -n 5 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
                _method="${LG_PACKAGE_MANAGER} -q check-update (no refresh / 不刷新索引)"
                _available=1
            else
                _available=0
            fi
            ;;
        pacman)
            if lg_command_exists pacman; then
                _list=$(pacman -Qu 2>/dev/null | head -n 50)
                _n=$(_lg_vs_count_lines "$_list")
                _sample=$(printf '%s\n' "$_list" | head -n 5 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
                _method='pacman -Qu (local sync db / 本地同步数据库)'
                _available=1
            else
                _available=0
            fi
            ;;
        apk)
            if lg_command_exists apk; then
                _list=$(apk version -l '<' 2>/dev/null | head -n 50)
                _n=$(_lg_vs_count_lines "$_list")
                _sample=$(printf '%s\n' "$_list" | head -n 5 | awk '{print $1}' | tr '\n' ' ' | sed 's/ $//')
                _method='apk version -l < (local index / 本地索引)'
                _available=1
            else
                _available=0
            fi
            ;;
        zypper)
            if lg_command_exists zypper; then
                _list=$(zypper --non-interactive list-updates 2>/dev/null | grep -E '^[[:alpha:]]' | head -n 50)
                _n=$(_lg_vs_count_lines "$_list")
                _sample=$(printf '%s\n' "$_list" | head -n 5 | awk '{print $3}' | tr '\n' ' ' | sed 's/ $//')
                _method='zypper list-updates (no refresh / 不刷新)'
                _available=1
            else
                _available=0
            fi
            ;;
        *)
            _available=0
            ;;
    esac

    if [ "${_available:-0}" -eq 1 ]; then
        if [ "${_n:-0}" -gt 0 ]; then
            _sev='MEDIUM'
            [ "${_n}" -ge "$LG_VULNSCAN_UPGRADE_THRESHOLD" ] && _sev='HIGH'
            lg_finding \
                "$_sev" \
                "Vulnerability Scan / 漏洞扫描" \
                "VULN_PENDING_UPDATES" \
                "Pending package updates detected / 检测到待处理的软件包更新" \
                "Risk found / 发现风险" \
                "${_n} pending; sample: ${_sample:-n/a}; via ${_method}" \
                "Unapplied updates may contain fixes for known CVEs / 未应用的更新可能包含已知 CVE 的修复。" \
                "Apply updates through your trusted maintenance window / 通过可信维护窗口应用更新。"
        else
            lg_finding \
                "PASS" \
                "Vulnerability Scan / 漏洞扫描" \
                "VULN_PENDING_UPDATES" \
                "No pending package updates detected / 未检测到待处理的软件包更新" \
                "Compliant / 合规" \
                "0 pending via ${_method}; local index may be stale / 0 项待更新（${_method}）；本地索引可能较旧" \
                "Package set appears current against the local index / 相对本地索引，软件包集合看起来是最新的。" \
                "Refresh the index regularly to stay accurate / 请定期刷新索引以保持结果准确。"
        fi
    else
        lg_finding \
            "UNKNOWN" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_PENDING_UPDATES" \
            "Cannot query pending updates / 无法查询待处理更新" \
            "Unknown / 未知" \
            "Package manager=${LG_PACKAGE_MANAGER}; query unavailable / 包管理器=${LG_PACKAGE_MANAGER}；查询不可用" \
            "No reliable read-only update query is available / 没有可用的只读更新查询方式。" \
            "Check vendor security advisories and update manually / 请查看厂商安全公告并手动更新。"
    fi

    # 2. Reboot-required marker (a patched kernel is not active until reboot).
    _marker=''
    for _m in $LG_VULNSCAN_REBOOT_MARKERS; do
        if [ -e "$_m" ]; then _marker="$_m"; break; fi
    done
    if [ -n "$_marker" ]; then
        lg_finding \
            "MEDIUM" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_REBOOT_REQUIRED" \
            "A system reboot is pending / 系统需要重启" \
            "Risk found / 发现风险" \
            "marker present: ${_marker}" \
            "Kernel/userspace fixes are not fully effective until reboot / 内核/用户态修复在重启前不会完全生效。" \
            "Schedule a reboot during a maintenance window / 在维护窗口安排重启。"
    else
        lg_finding \
            "PASS" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_REBOOT_REQUIRED" \
            "No reboot-required marker detected / 未检测到需重启标记" \
            "Compliant / 合规" \
            "Checked: ${LG_VULNSCAN_REBOOT_MARKERS}" \
            "No pending reboot marker was found / 未发现待重启标记。" \
            "No action required / 无需操作。"
    fi

    # 3. Running kernel vs on-disk kernel (informational, no assumptions).
    _running=$(uname -r 2>/dev/null)
    if [ -n "$_running" ]; then
        lg_finding \
            "LOW" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_KERNEL_VERSION" \
            "Running kernel version recorded / 已记录运行中的内核版本" \
            "Informational / 信息" \
            "uname -r = ${_running}" \
            "Kernel CVEs are version-specific; compare with vendor advisories / 内核 CVE 与版本相关，请对照厂商公告。" \
            "Track your distribution's kernel security advisories / 跟踪发行版的内核安全公告。"
    else
        lg_finding \
            "UNKNOWN" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_KERNEL_VERSION" \
            "Cannot determine running kernel version / 无法确定运行中的内核版本" \
            "Unknown / 未知" \
            "uname -r failed / uname -r 失败" \
            "Kernel version is required for CVE matching / CVE 匹配需要内核版本。" \
            "Check manually with uname -r / 请手动运行 uname -r 检查。"
    fi

    # 4. Local CVE scanner availability (presence only, never executed).
    _cve_tools='' _cve_n=0
    for _spec in 'lynis:Lynis' 'openscap:OpenSCAP' 'oscap:OpenSCAP' \
                 'vuls:Vuls' 'trivy:Trivy' 'debsecan:debsecan' \
                 'arch-audit:arch-audit'; do
        _bin=${_spec%%:*} _label=${_spec#*:}
        if lg_command_exists "$_bin"; then
            _cve_n=$((_cve_n + 1))
            if [ -n "$_cve_tools" ]; then
                _cve_tools="${_cve_tools}; ${_bin} (${_label})"
            else
                _cve_tools="${_bin} (${_label})"
            fi
        fi
    done
    if [ "$_cve_n" -gt 0 ]; then
        lg_finding \
            "PASS" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_CVE_TOOLING" \
            "Local CVE/vulnerability scanner tooling detected / 检测到本地 CVE/漏洞扫描工具" \
            "Compliant / 合规" \
            "${_cve_n} found: ${_cve_tools}" \
            "A dedicated scanner is available for deeper assessment / 具备专用扫描器，可进行更深入评估。" \
            "Run a full scan and review its findings / 运行完整扫描并复核其结果。"
    else
        lg_finding \
            "LOW" \
            "Vulnerability Scan / 漏洞扫描" \
            "VULN_CVE_TOOLING" \
            "No dedicated CVE scanner detected / 未检测到专用 CVE 扫描器" \
            "Informational / 信息" \
            "lynis/openscap/vuls/trivy/debsecan/arch-audit not in PATH / 上述工具均不在 PATH 中" \
            "This module only samples posture; it is not a full CVE scan / 本模块仅抽样检查态势，并非完整 CVE 扫描。" \
            "Consider installing a trusted scanner for in-depth audits / 如需深度审计，可考虑安装可信扫描器。"
    fi
}
